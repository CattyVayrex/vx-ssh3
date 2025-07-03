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
}

// ClientConnection represents a UDP client connection
type ClientConnection struct {
	udpAddr    *net.UDPAddr
	sshConn    ssh.Conn
	sshChan    ssh.Channel
	lastActive time.Time
	mutex      sync.RWMutex
	bufferPool sync.Pool // Added for optimization
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
	bufferPool  sync.Pool // Added for optimization
}

// NewVXClient creates a new VX client instance
func NewVXClient(config *ClientConfig) (*VXClient, error) {
	// Create SSH client configuration
	sshConfig := &ssh.ClientConfig{
		User: config.SSHUser,
		Auth: []ssh.AuthMethod{
			ssh.Password(config.SSHPassword),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // For simplicity, ignore host key verification
		Timeout:         10 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())

	client := &VXClient{
		config:      config,
		connections: make(map[string]*ClientConnection),
		sshConfig:   sshConfig,
		ctx:         ctx,
		cancel:      cancel,
	}

	// Initialize buffer pool for optimization (safe addition)
	client.bufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 65535)
		},
	}

	return client, nil
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

	// Set socket buffer sizes for better performance (safe optimization)
	if err := c.udpListener.SetReadBuffer(1024 * 1024); err != nil {
		log.Printf("Warning: Could not set UDP read buffer: %v", err)
	}
	if err := c.udpListener.SetWriteBuffer(1024 * 1024); err != nil {
		log.Printf("Warning: Could not set UDP write buffer: %v", err)
	}

	log.Printf("VX-Client listening on UDP port %d", c.config.LocalPort)
	log.Printf("SSH target: %s (user: %s)", c.config.RemoteAddr, c.config.SSHUser)

	// Start connection cleanup routine
	go c.cleanupRoutine()

	// Main UDP packet handling loop
	return c.handleUDPPackets()
}

// handleUDPPackets processes incoming UDP packets
func (c *VXClient) handleUDPPackets() error {
	for {
		select {
		case <-c.ctx.Done():
			return nil
		default:
		}

		// Get buffer from pool (optimization)
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

		// Handle packet in goroutine for concurrent processing
		go func() {
			defer c.bufferPool.Put(buffer) // Return buffer when done
			c.handlePacket(clientAddr, buffer[:n])
		}()
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

	// Create connection object with buffer pool (optimization)
	conn := &ClientConnection{
		udpAddr:    clientAddr,
		sshConn:    sshConn,
		sshChan:    sshChan,
		lastActive: time.Now(),
	}

	// Initialize buffer pool for this connection
	conn.bufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 65535)
		},
	}

	// Store connection
	c.connections[clientKey] = conn

	// Start receiving routine for this connection
	go c.receiveFromSSH(clientKey, conn)

	return conn, nil
}

// sendPacket sends a packet through SSH tunnel
func (c *VXClient) sendPacket(conn *ClientConnection, data []byte) error {
	// Create packet with client address and data
	clientAddrBytes := []byte(conn.udpAddr.String())
	
	// Calculate total size: 2 bytes addr length + addr + 4 bytes data length + data
	totalSize := 2 + len(clientAddrBytes) + 4 + len(data)
	
	// Get buffer from connection's pool (optimization)
	buffer := conn.bufferPool.Get().([]byte)
	defer conn.bufferPool.Put(buffer)
	
	// Pack the packet: [addr_len(2)][addr][data_len(4)][data]
	binary.BigEndian.PutUint16(buffer[0:2], uint16(len(clientAddrBytes)))
	copy(buffer[2:], clientAddrBytes)
	binary.BigEndian.PutUint32(buffer[2+len(clientAddrBytes):], uint32(len(data)))
	copy(buffer[2+len(clientAddrBytes)+4:], data)
	
	// Send through SSH channel
	_, err := conn.sshChan.Write(buffer[:totalSize])
	return err
}

// receiveFromSSH handles receiving packets from SSH for a specific connection
func (c *VXClient) receiveFromSSH(clientKey string, conn *ClientConnection) {
	defer c.removeConnection(clientKey)
	
	buffer := conn.bufferPool.Get().([]byte)
	defer conn.bufferPool.Put(buffer)

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		// Read packet from SSH channel
		n, err := conn.sshChan.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading from SSH for %s: %v", clientKey, err)
			}
			return
		}

		// Send packet back to UDP client
		_, err = c.udpListener.WriteToUDP(buffer[:n], conn.udpAddr)
		if err != nil {
			log.Printf("Error writing UDP packet to %s: %v", clientKey, err)
			return
		}

		// Update last active time
		conn.mutex.Lock()
		conn.lastActive = time.Now()
		conn.mutex.Unlock()
	}
}

// removeConnection safely removes a connection
func (c *VXClient) removeConnection(clientKey string) {
	c.connMutex.Lock()
	defer c.connMutex.Unlock()

	if conn, exists := c.connections[clientKey]; exists {
		log.Printf("Closing connection for client %s", clientKey)
		conn.sshChan.Close()
		conn.sshConn.Close()
		delete(c.connections, clientKey)
	}
}

// cleanupRoutine periodically cleans up idle connections
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

// cleanupIdleConnections removes connections that have been idle too long
func (c *VXClient) cleanupIdleConnections() {
	c.connMutex.RLock()
	var idleConnections []string
	now := time.Now()

	for clientKey, conn := range c.connections {
		conn.mutex.RLock()
		if now.Sub(conn.lastActive) > c.config.IdleTimeout {
			idleConnections = append(idleConnections, clientKey)
		}
		conn.mutex.RUnlock()
	}
	c.connMutex.RUnlock()

	// Remove idle connections
	for _, clientKey := range idleConnections {
		c.removeConnection(clientKey)
	}

	if len(idleConnections) > 0 {
		log.Printf("Cleaned up %d idle connections", len(idleConnections))
	}
}

// Stop gracefully stops the client
func (c *VXClient) Stop() {
	log.Printf("Stopping VX-Client...")
	
	// Cancel context to stop all goroutines
	c.cancel()
	
	// Close all connections
	c.connMutex.RLock()
	for clientKey := range c.connections {
		c.removeConnection(clientKey)
	}
	c.connMutex.RUnlock()
	
	// Close UDP listener
	if c.udpListener != nil {
		c.udpListener.Close()
	}
	
	log.Printf("VX-Client stopped")
}

// main function starts the VX-SSH client

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