package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Configuration for the client
type ClientConfig struct {
	LocalPort    int           // Port to listen for UDP packets (default: 51820)
	RemoteAddr   string        // SSH server address (e.g., "server.example.com:22")
	SSHUser      string        // SSH username
	SSHPassword  string        // SSH password
	MaxConns     int           // Maximum concurrent connections (default: 100)
	IdleTimeout  time.Duration // Connection idle timeout (default: 3 minutes)
}

// Packet represents a UDP packet with client info
type Packet struct {
	ClientAddr *net.UDPAddr
	Data       []byte
	Length     int
}

// VXClient represents the main client structure (optimized)
type VXClient struct {
	config       *ClientConfig
	udpListener  *net.UDPConn
	sshConn      ssh.Conn
	sshChan      ssh.Channel
	sshConfig    *ssh.ClientConfig
	ctx          context.Context
	cancel       context.CancelFunc
	packetPool   sync.Pool
	bufferPool   sync.Pool
	clientMap    map[string]*net.UDPAddr
	clientMutex  sync.RWMutex
	sendQueue    chan *Packet
	recvQueue    chan *Packet
	connected    bool
	connMutex    sync.RWMutex
}

// NewVXClient creates a new VX client instance (optimized)
func NewVXClient(config *ClientConfig) (*VXClient, error) {
	// Create SSH client configuration
	sshConfig := &ssh.ClientConfig{
		User: config.SSHUser,
		Auth: []ssh.AuthMethod{
			ssh.Password(config.SSHPassword),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second, // Reduced timeout
	}

	ctx, cancel := context.WithCancel(context.Background())

	client := &VXClient{
		config:     config,
		sshConfig:  sshConfig,
		ctx:        ctx,
		cancel:     cancel,
		clientMap:  make(map[string]*net.UDPAddr),
		sendQueue:  make(chan *Packet, 1000), // Buffered channel for batching
		recvQueue:  make(chan *Packet, 1000),
		connected:  false,
	}

	// Initialize buffer pools for better memory management
	client.bufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 65535) // Max UDP packet size
		},
	}

	client.packetPool = sync.Pool{
		New: func() interface{} {
			return &Packet{
				Data: make([]byte, 65535),
			}
		},
	}

	return client, nil
}

// Start begins listening for UDP packets and handling connections (optimized)
func (c *VXClient) Start() error {
	// Start UDP listener with optimized socket options
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", c.config.LocalPort))
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %v", err)
	}

	c.udpListener, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP port %d: %v", c.config.LocalPort, err)
	}

	// Set socket buffer sizes for better performance
	if err := c.udpListener.SetReadBuffer(1024 * 1024); err != nil {
		log.Printf("Warning: Could not set UDP read buffer: %v", err)
	}
	if err := c.udpListener.SetWriteBuffer(1024 * 1024); err != nil {
		log.Printf("Warning: Could not set UDP write buffer: %v", err)
	}

	log.Printf("VX-Client listening on UDP port %d", c.config.LocalPort)
	log.Printf("SSH target: %s (user: %s)", c.config.RemoteAddr, c.config.SSHUser)

	// Establish single SSH connection
	if err := c.connectSSH(); err != nil {
		return fmt.Errorf("failed to establish SSH connection: %v", err)
	}

	// Start processing routines
	go c.sshSender()     // Handles sending to SSH
	go c.sshReceiver()   // Handles receiving from SSH
	go c.udpSender()     // Handles sending UDP responses
	go c.reconnectLoop() // Handles SSH reconnection

	// Main UDP packet handling loop
	return c.handleUDPPackets()
}

// handleUDPPackets processes incoming UDP packets (optimized)
func (c *VXClient) handleUDPPackets() error {
	for {
		select {
		case <-c.ctx.Done():
			return nil
		default:
		}

		// Get buffer from pool
		buffer := c.bufferPool.Get().([]byte)

		// Read UDP packet
		n, clientAddr, err := c.udpListener.ReadFromUDP(buffer)
		if err != nil {
			c.bufferPool.Put(buffer)
			if c.ctx.Err() != nil {
				return nil
			}
			log.Printf("Error reading UDP packet: %v", err)
			continue
		}

		// Get packet from pool and prepare for sending
		packet := c.packetPool.Get().(*Packet)
		packet.ClientAddr = clientAddr
		packet.Length = n
		copy(packet.Data[:n], buffer[:n])

		// Return buffer to pool immediately
		c.bufferPool.Put(buffer)

		// Store client mapping for responses
		clientKey := clientAddr.String()
		c.clientMutex.Lock()
		c.clientMap[clientKey] = clientAddr
		c.clientMutex.Unlock()

		// Send to processing queue (non-blocking)
		select {
		case c.sendQueue <- packet:
		default:
			// Queue full, drop packet and return to pool
			c.packetPool.Put(packet)
			log.Printf("Send queue full, dropping packet from %s", clientKey)
		}
	}
}

// connectSSH establishes the SSH connection and channel
func (c *VXClient) connectSSH() error {
	log.Printf("Establishing SSH connection to %s", c.config.RemoteAddr)

	// Establish SSH connection
	conn, err := ssh.Dial("tcp", c.config.RemoteAddr, c.sshConfig)
	if err != nil {
		return fmt.Errorf("failed to dial SSH: %v", err)
	}

	// Open channel for data transfer
	channel, reqs, err := conn.OpenChannel("vx-tunnel", nil)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to open SSH channel: %v", err)
	}

	go ssh.DiscardRequests(reqs)

	c.connMutex.Lock()
	c.sshConn = conn
	c.sshChan = channel
	c.connected = true
	c.connMutex.Unlock()

	log.Printf("SSH connection established successfully")
	return nil
}

// sshSender handles sending packets to SSH (optimized with batching)
func (c *VXClient) sshSender() {
	batch := make([]*Packet, 0, 10) // Batch up to 10 packets
	ticker := time.NewTicker(5 * time.Millisecond) // Send batch every 5ms
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return

		case packet := <-c.sendQueue:
			batch = append(batch, packet)
			
			// Send batch if full
			if len(batch) >= cap(batch) {
				c.sendBatch(batch)
				batch = batch[:0] // Reset slice
			}

		case <-ticker.C:
			// Send batch on timer
			if len(batch) > 0 {
				c.sendBatch(batch)
				batch = batch[:0] // Reset slice
			}
		}
	}
}

// sendBatch sends a batch of packets through SSH (optimized)
func (c *VXClient) sendBatch(batch []*Packet) {
	if !c.isConnected() {
		// Return packets to pool if not connected
		for _, packet := range batch {
			c.packetPool.Put(packet)
		}
		return
	}

	// Calculate total size needed
	totalSize := 0
	for _, packet := range batch {
		totalSize += packet.Length + 6 // 2 bytes addr length + 4 bytes data length
	}

	// Get buffer from pool
	buffer := c.bufferPool.Get().([]byte)
	defer c.bufferPool.Put(buffer)

	// Pack multiple packets into single buffer
	offset := 0
	for _, packet := range batch {
		// Write client address length and address
		addrBytes := []byte(packet.ClientAddr.String())
		buffer[offset] = byte(len(addrBytes) >> 8)
		buffer[offset+1] = byte(len(addrBytes))
		offset += 2
		copy(buffer[offset:], addrBytes)
		offset += len(addrBytes)

		// Write data length and data
		buffer[offset] = byte(packet.Length >> 24)
		buffer[offset+1] = byte(packet.Length >> 16)
		buffer[offset+2] = byte(packet.Length >> 8)
		buffer[offset+3] = byte(packet.Length)
		offset += 4
		copy(buffer[offset:], packet.Data[:packet.Length])
		offset += packet.Length

		// Return packet to pool
		c.packetPool.Put(packet)
	}

	// Send entire batch at once
	c.connMutex.RLock()
	if c.sshChan != nil {
		c.sshChan.Write(buffer[:offset])
	}
	c.connMutex.RUnlock()
}

// sshReceiver handles receiving packets from SSH (optimized)
func (c *VXClient) sshReceiver() {
	buffer := make([]byte, 65535)

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		if !c.isConnected() {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		c.connMutex.RLock()
		sshChan := c.sshChan
		c.connMutex.RUnlock()

		if sshChan == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		// Read from SSH channel
		n, err := sshChan.Read(buffer)
		if err != nil {
			if err == io.EOF {
				log.Printf("SSH channel closed, attempting reconnect")
				c.markDisconnected()
				continue
			}
			log.Printf("Error reading from SSH: %v", err)
			continue
		}

		// Parse and queue received packets
		c.parseReceivedData(buffer[:n])
	}
}

// parseReceivedData parses batched data from SSH and queues packets
func (c *VXClient) parseReceivedData(data []byte) {
	offset := 0
	
	for offset < len(data) {
		if offset+2 > len(data) {
			break
		}

		// Read address length
		addrLen := int(data[offset])<<8 | int(data[offset+1])
		offset += 2

		if offset+addrLen > len(data) {
			break
		}

		// Read address
		addrStr := string(data[offset : offset+addrLen])
		offset += addrLen

		if offset+4 > len(data) {
			break
		}

		// Read data length
		dataLen := int(data[offset])<<24 | int(data[offset+1])<<16 | int(data[offset+2])<<8 | int(data[offset+3])
		offset += 4

		if offset+dataLen > len(data) {
			break
		}

		// Find client address
		c.clientMutex.RLock()
		clientAddr, exists := c.clientMap[addrStr]
		c.clientMutex.RUnlock()

		if !exists {
			offset += dataLen
			continue
		}

		// Create packet for UDP response
		packet := c.packetPool.Get().(*Packet)
		packet.ClientAddr = clientAddr
		packet.Length = dataLen
		copy(packet.Data[:dataLen], data[offset:offset+dataLen])
		offset += dataLen

		// Queue for UDP sending
		select {
		case c.recvQueue <- packet:
		default:
			c.packetPool.Put(packet) // Queue full, drop packet
		}
	}
}

// udpSender handles sending UDP responses to clients
func (c *VXClient) udpSender() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case packet := <-c.recvQueue:
			// Send UDP packet to client
			if _, err := c.udpListener.WriteToUDP(packet.Data[:packet.Length], packet.ClientAddr); err != nil {
				log.Printf("Error sending UDP to %s: %v", packet.ClientAddr, err)
			}
			// Return packet to pool
			c.packetPool.Put(packet)
		}
	}
}

// reconnectLoop handles SSH reconnection
func (c *VXClient) reconnectLoop() {
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		if !c.isConnected() {
			log.Printf("SSH disconnected, attempting reconnect...")
			
			// Close old connection
			c.closeSSH()
			
			// Wait before retry
			time.Sleep(2 * time.Second)
			
			// Attempt reconnect
			if err := c.connectSSH(); err != nil {
				log.Printf("Reconnect failed: %v", err)
				continue
			}
			
			log.Printf("SSH reconnected successfully")
		}
		
		time.Sleep(5 * time.Second)
	}
}

// Helper methods for connection state management
func (c *VXClient) isConnected() bool {
	c.connMutex.RLock()
	defer c.connMutex.RUnlock()
	return c.connected
}

func (c *VXClient) markDisconnected() {
	c.connMutex.Lock()
	c.connected = false
	c.connMutex.Unlock()
}

func (c *VXClient) closeSSH() {
	c.connMutex.Lock()
	defer c.connMutex.Unlock()
	
	if c.sshChan != nil {
		c.sshChan.Close()
		c.sshChan = nil
	}
	if c.sshConn != nil {
		c.sshConn.Close()
		c.sshConn = nil
	}
	c.connected = false
}

// Stop gracefully shuts down the client (optimized)
func (c *VXClient) Stop() {
	log.Println("Shutting down VX-Client...")
	c.cancel()

	// Close UDP listener
	if c.udpListener != nil {
		c.udpListener.Close()
	}

	// Close SSH connection
	c.closeSSH()

	// Close channels
	close(c.sendQueue)
	close(c.recvQueue)

	log.Println("VX-Client stopped")
}

func main() {
	// Command line flags
	var (
		localPort   = flag.Int("local-port", 51820, "Local UDP port to listen on")
		remoteAddr  = flag.String("remote", "", "SSH server address (host:port)")
		sshUser     = flag.String("ssh-user", "", "SSH username")
		sshPassword = flag.String("ssh-password", "", "SSH password")
		maxConns    = flag.Int("max-conns", 100, "Maximum concurrent connections")
		idleTimeout = flag.Duration("idle-timeout", 3*time.Minute, "Connection idle timeout")
	)
	flag.Parse()

	// Validate required parameters
	if *remoteAddr == "" {
		fmt.Fprintf(os.Stderr, "Error: -remote is required\n")
		fmt.Fprintf(os.Stderr, "Usage: %s -remote <ssh-server:port> -ssh-user <username> -ssh-password <password>\n", os.Args[0])
		os.Exit(1)
	}
	if *sshUser == "" {
		fmt.Fprintf(os.Stderr, "Error: -ssh-user is required\n")
		os.Exit(1)
	}
	if *sshPassword == "" {
		fmt.Fprintf(os.Stderr, "Error: -ssh-password is required\n")
		os.Exit(1)
	}

	// Create client configuration
	config := &ClientConfig{
		LocalPort:   *localPort,
		RemoteAddr:  *remoteAddr,
		SSHUser:     *sshUser,
		SSHPassword: *sshPassword,
		MaxConns:    *maxConns,
		IdleTimeout: *idleTimeout,
	}

	// Create and start client
	client, err := NewVXClient(config)
	if err != nil {
		log.Fatalf("Failed to create VX client: %v", err)
	}

	// Handle graceful shutdown
	go func() {
		// Simple signal handling - in production, use os/signal
		var input string
		fmt.Scanln(&input)
		client.Stop()
		os.Exit(0)
	}()

	// Start client
	if err := client.Start(); err != nil {
		log.Fatalf("Client error: %v", err)
	}
} 