package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Configuration for the client
type ClientConfig struct {
	LocalPort    int    // Port to listen for UDP packets (default: 51820)
	RemoteAddr   string // SSH server address (e.g., "server.example.com:22")
	SSHUser      string // SSH username
	SSHPassword  string // SSH password
	MaxConns     int    // Maximum concurrent connections (default: 100)
	IdleTimeout  time.Duration // Connection idle timeout (default: 3 minutes)
	WorkerCount  int    // Number of worker goroutines for packet processing
	BufferSize   int    // Buffer size for packet processing
}

// Packet represents a UDP packet with metadata
type Packet struct {
	Data     []byte
	Addr     *net.UDPAddr
	Length   int
}

// Buffer pool for reusing memory
var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 65535)
	},
}

// Packet pool for reusing packet structures
var packetPool = sync.Pool{
	New: func() interface{} {
		return &Packet{
			Data: make([]byte, 65535),
		}
	},
}

// ClientConnection represents a UDP client connection
type ClientConnection struct {
	udpAddr    *net.UDPAddr
	sshConn    ssh.Conn
	sshChan    ssh.Channel
	lastActive time.Time
	mutex      sync.RWMutex
}

// VXClient represents the main client structure
type VXClient struct {
	config      *ClientConfig
	udpListener *net.UDPConn
	connections map[string]*ClientConnection
	connMutex   sync.RWMutex
	sshConfig   *ssh.ClientConfig
	ctx         context.Context
	cancel      context.CancelFunc
	packetChan  chan *Packet
	workers     []chan *Packet
}

// NewVXClient creates a new VX client instance
func NewVXClient(config *ClientConfig) (*VXClient, error) {
	// Set default worker count if not specified
	if config.WorkerCount == 0 {
		config.WorkerCount = runtime.NumCPU() * 2
	}
	if config.BufferSize == 0 {
		config.BufferSize = 8192 // Larger buffer for better throughput
	}

	// Create optimized SSH client configuration
	sshConfig := &ssh.ClientConfig{
		User: config.SSHUser,
		Auth: []ssh.AuthMethod{
			ssh.Password(config.SSHPassword),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second, // Reduced timeout for faster reconnection
		Config: ssh.Config{
			// Optimize ciphers and algorithms for speed
			Ciphers: []string{
				"aes128-ctr", "aes192-ctr", "aes256-ctr",
				"aes128-gcm@openssh.com", "chacha20-poly1305@openssh.com",
			},
			MACs: []string{
				"hmac-sha2-256-etm@openssh.com", "hmac-sha2-256",
				"hmac-sha1", "hmac-sha1-96",
			},
			KeyExchanges: []string{
				"curve25519-sha256", "curve25519-sha256@libssh.org",
				"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
				"diffie-hellman-group14-sha256", "diffie-hellman-group14-sha1",
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Create packet channel with large buffer
	packetChan := make(chan *Packet, config.BufferSize)
	
	// Initialize worker channels
	workers := make([]chan *Packet, config.WorkerCount)
	for i := range workers {
		workers[i] = make(chan *Packet, 256) // Buffer per worker
	}

	return &VXClient{
		config:      config,
		connections: make(map[string]*ClientConnection, config.MaxConns),
		sshConfig:   sshConfig,
		ctx:         ctx,
		cancel:      cancel,
		packetChan:  packetChan,
		workers:     workers,
	}, nil
}

// Start begins listening for UDP packets and handling connections
func (c *VXClient) Start() error {
	// Start UDP listener
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", c.config.LocalPort))
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %v", err)
	}

	c.udpListener, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP port %d: %v", c.config.LocalPort, err)
	}

	// Optimize UDP socket settings
	if err := c.optimizeUDPSocket(); err != nil {
		log.Printf("Warning: Could not optimize UDP socket: %v", err)
	}

	log.Printf("VX-Client listening on UDP port %d", c.config.LocalPort)
	log.Printf("SSH target: %s (user: %s)", c.config.RemoteAddr, c.config.SSHUser)
	log.Printf("Using %d worker goroutines", c.config.WorkerCount)

	// Start worker goroutines for packet processing
	for i := 0; i < c.config.WorkerCount; i++ {
		go c.packetWorker(i)
	}

	// Start connection cleanup routine
	go c.cleanupRoutine()

	// Start packet distributor
	go c.packetDistributor()

	// Main UDP packet handling loop
	return c.handleUDPPackets()
}

// optimizeUDPSocket applies performance optimizations to the UDP socket
func (c *VXClient) optimizeUDPSocket() error {
	// Set larger receive buffer
	if err := c.udpListener.SetReadBuffer(2 * 1024 * 1024); err != nil { // 2MB
		return err
	}
	// Set larger send buffer
	if err := c.udpListener.SetWriteBuffer(2 * 1024 * 1024); err != nil { // 2MB
		return err
	}
	return nil
}

// packetDistributor distributes packets to worker goroutines
func (c *VXClient) packetDistributor() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case packet := <-c.packetChan:
			// Simple round-robin distribution based on client address hash
			workerIndex := int(packet.Addr.Port) % len(c.workers)
			select {
			case c.workers[workerIndex] <- packet:
			default:
				// Worker busy, handle in any available worker
				for i := 0; i < len(c.workers); i++ {
					select {
					case c.workers[i] <- packet:
						goto sent
					default:
					}
				}
				// All workers busy, handle synchronously
				go c.handlePacket(packet.Addr, packet.Data[:packet.Length])
				c.returnPacket(packet)
			sent:
			}
		}
	}
}

// packetWorker processes packets from a dedicated channel
func (c *VXClient) packetWorker(workerID int) {
	for {
		select {
		case <-c.ctx.Done():
			return
		case packet := <-c.workers[workerID]:
			c.handlePacket(packet.Addr, packet.Data[:packet.Length])
			c.returnPacket(packet)
		}
	}
}

// returnPacket returns a packet to the pool
func (c *VXClient) returnPacket(packet *Packet) {
	packet.Addr = nil
	packet.Length = 0
	packetPool.Put(packet)
}

// handleUDPPackets processes incoming UDP packets
func (c *VXClient) handleUDPPackets() error {
	for {
		select {
		case <-c.ctx.Done():
			return nil
		default:
		}

		// Get packet from pool
		packet := packetPool.Get().(*Packet)
		
		// Read UDP packet directly into pooled buffer
		n, clientAddr, err := c.udpListener.ReadFromUDP(packet.Data)
		if err != nil {
			c.returnPacket(packet)
			if c.ctx.Err() != nil {
				return nil
			}
			log.Printf("Error reading UDP packet: %v", err)
			continue
		}

		// Set packet metadata
		packet.Addr = clientAddr
		packet.Length = n

		// Send to packet distributor
		select {
		case c.packetChan <- packet:
		default:
			// Channel full, handle directly
			c.handlePacket(clientAddr, packet.Data[:n])
			c.returnPacket(packet)
		}
	}
}

// handlePacket processes a single UDP packet
func (c *VXClient) handlePacket(clientAddr *net.UDPAddr, data []byte) {
	clientKey := clientAddr.String()

	// Get or create connection for this client
	conn, err := c.getOrCreateConnection(clientKey, clientAddr)
	if err != nil {
		log.Printf("Failed to get connection for %s: %v", clientKey, err)
		return
	}

	// Update last active time
	conn.mutex.Lock()
	conn.lastActive = time.Now()
	conn.mutex.Unlock()

	// Send packet through SSH tunnel
	if err := c.sendPacket(conn, data); err != nil {
		log.Printf("Failed to send packet for %s: %v", clientKey, err)
		c.removeConnection(clientKey)
	}
}

// getOrCreateConnection gets existing connection or creates a new one
func (c *VXClient) getOrCreateConnection(clientKey string, clientAddr *net.UDPAddr) (*ClientConnection, error) {
	c.connMutex.RLock()
	if conn, exists := c.connections[clientKey]; exists {
		c.connMutex.RUnlock()
		return conn, nil
	}
	c.connMutex.RUnlock()

	// Create new connection
	return c.createConnection(clientKey, clientAddr)
}

// createConnection establishes a new SSH connection for a client
func (c *VXClient) createConnection(clientKey string, clientAddr *net.UDPAddr) (*ClientConnection, error) {
	c.connMutex.Lock()
	defer c.connMutex.Unlock()

	// Double-check if connection was created while waiting for lock
	if conn, exists := c.connections[clientKey]; exists {
		return conn, nil
	}

	log.Printf("Creating new SSH connection for client %s", clientKey)

	// Establish SSH connection
	sshConn, err := ssh.Dial("tcp", c.config.RemoteAddr, c.sshConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to establish SSH connection: %v", err)
	}

	// Open channel for UDP tunneling
	sshChan, reqs, err := sshConn.OpenChannel("vx-tunnel", nil)
	if err != nil {
		sshConn.Close()
		return nil, fmt.Errorf("failed to open SSH channel: %v", err)
	}

	// Discard incoming requests
	go ssh.DiscardRequests(reqs)

	// Create connection object
	conn := &ClientConnection{
		udpAddr:    clientAddr,
		sshConn:    sshConn,
		sshChan:    sshChan,
		lastActive: time.Now(),
	}

	// Store connection
	c.connections[clientKey] = conn

	// Start receiving routine for this connection
	go c.receiveFromSSH(clientKey, conn)

	return conn, nil
}

// sendPacket sends a UDP packet through SSH channel
func (c *VXClient) sendPacket(conn *ClientConnection, data []byte) error {
	// Get buffer from pool
	buffer := bufferPool.Get().([]byte)
	defer bufferPool.Put(buffer)

	// Prepare packet with length prefix (reuse buffer)
	if len(data)+4 > len(buffer) {
		// Fallback to allocation if packet too large
		packet := make([]byte, 4+len(data))
		binary.BigEndian.PutUint32(packet[:4], uint32(len(data)))
		copy(packet[4:], data)
		_, err := conn.sshChan.Write(packet)
		return err
	}

	binary.BigEndian.PutUint32(buffer[:4], uint32(len(data)))
	copy(buffer[4:4+len(data)], data)

	// Send through SSH channel
	_, err := conn.sshChan.Write(buffer[:4+len(data)])
	return err
}

// receiveFromSSH handles incoming data from SSH channel
func (c *VXClient) receiveFromSSH(clientKey string, conn *ClientConnection) {
	defer c.removeConnection(clientKey)

	// Get buffer from pool
	buffer := bufferPool.Get().([]byte)
	defer bufferPool.Put(buffer)
	
	var lengthBuf [4]byte

	for {
		// Read packet length
		if _, err := io.ReadFull(conn.sshChan, lengthBuf[:]); err != nil {
			if err != io.EOF {
				log.Printf("Error reading packet length for %s: %v", clientKey, err)
			}
			return
		}

		packetLen := binary.BigEndian.Uint32(lengthBuf[:])
		if packetLen > 65535 {
			log.Printf("Invalid packet length %d for %s", packetLen, clientKey)
			return
		}

		// Ensure buffer is large enough
		var readBuffer []byte
		if packetLen <= uint32(len(buffer)) {
			readBuffer = buffer[:packetLen]
		} else {
			// Allocate larger buffer if needed (rare case)
			readBuffer = make([]byte, packetLen)
		}

		// Read packet data
		if _, err := io.ReadFull(conn.sshChan, readBuffer); err != nil {
			log.Printf("Error reading packet data for %s: %v", clientKey, err)
			return
		}

		// Send back to UDP client
		if _, err := c.udpListener.WriteToUDP(readBuffer, conn.udpAddr); err != nil {
			log.Printf("Error sending UDP packet to %s: %v", clientKey, err)
			return
		}

		// Update last active time (optimized - less frequent updates)
		conn.mutex.Lock()
		conn.lastActive = time.Now()
		conn.mutex.Unlock()
	}
}

// removeConnection removes and closes a connection
func (c *VXClient) removeConnection(clientKey string) {
	c.connMutex.Lock()
	defer c.connMutex.Unlock()

	if conn, exists := c.connections[clientKey]; exists {
		log.Printf("Removing connection for client %s", clientKey)
		conn.sshChan.Close()
		conn.sshConn.Close()
		delete(c.connections, clientKey)
	}
}

// cleanupRoutine periodically removes idle connections
func (c *VXClient) cleanupRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.cleanupIdleConnections()
		}
	}
}

// cleanupIdleConnections removes connections that have been idle
func (c *VXClient) cleanupIdleConnections() {
	now := time.Now()
	var toRemove []string

	c.connMutex.RLock()
	for clientKey, conn := range c.connections {
		conn.mutex.RLock()
		if now.Sub(conn.lastActive) > c.config.IdleTimeout {
			toRemove = append(toRemove, clientKey)
		}
		conn.mutex.RUnlock()
	}
	c.connMutex.RUnlock()

	// Remove idle connections
	for _, clientKey := range toRemove {
		c.removeConnection(clientKey)
	}

	if len(toRemove) > 0 {
		log.Printf("Cleaned up %d idle connections", len(toRemove))
	}
}

// Stop gracefully shuts down the client
func (c *VXClient) Stop() {
	log.Println("Shutting down VX-Client...")
	c.cancel()

	// Close UDP listener
	if c.udpListener != nil {
		c.udpListener.Close()
	}

	// Close all connections
	c.connMutex.Lock()
	for clientKey := range c.connections {
		c.removeConnection(clientKey)
	}
	c.connMutex.Unlock()

	log.Println("VX-Client stopped")
}

func main() {
	// Command line flags
	var (
		localPort   = flag.Int("local-port", 51820, "Local UDP port to listen on")
		remoteAddr  = flag.String("remote", "", "SSH server address (host:port)")
		sshUser     = flag.String("ssh-user", "", "SSH username")
		sshPassword = flag.String("ssh-password", "", "SSH password")
		maxConns    = flag.Int("max-conns", 200, "Maximum concurrent connections")
		idleTimeout = flag.Duration("idle-timeout", 3*time.Minute, "Connection idle timeout")
		workerCount = flag.Int("workers", 0, "Number of worker goroutines (0 = auto)")
		bufferSize  = flag.Int("buffer-size", 16384, "Internal buffer size for packet processing")
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
		WorkerCount: *workerCount,
		BufferSize:  *bufferSize,
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