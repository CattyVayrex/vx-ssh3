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

	return &VXClient{
		config:      config,
		connections: make(map[string]*ClientConnection),
		sshConfig:   sshConfig,
		ctx:         ctx,
		cancel:      cancel,
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

	log.Printf("VX-Client listening on UDP port %d", c.config.LocalPort)
	log.Printf("SSH target: %s (user: %s)", c.config.RemoteAddr, c.config.SSHUser)

	// Start connection cleanup routine
	go c.cleanupRoutine()

	// Main UDP packet handling loop
	return c.handleUDPPackets()
}

// handleUDPPackets processes incoming UDP packets
func (c *VXClient) handleUDPPackets() error {
	buffer := make([]byte, 65535) // Maximum UDP packet size

	for {
		select {
		case <-c.ctx.Done():
			return nil
		default:
		}

		// Read UDP packet
		n, clientAddr, err := c.udpListener.ReadFromUDP(buffer)
		if err != nil {
			if c.ctx.Err() != nil {
				return nil
			}
			log.Printf("Error reading UDP packet: %v", err)
			continue
		}

		// Handle packet in goroutine for concurrent processing
		go c.handlePacket(clientAddr, buffer[:n])
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
	// Prepare packet with length prefix
	packet := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(packet[:4], uint32(len(data)))
	copy(packet[4:], data)

	// Send through SSH channel
	_, err := conn.sshChan.Write(packet)
	return err
}

// receiveFromSSH handles incoming data from SSH channel
func (c *VXClient) receiveFromSSH(clientKey string, conn *ClientConnection) {
	defer c.removeConnection(clientKey)

	buffer := make([]byte, 65535)
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

		// Read packet data
		if _, err := io.ReadFull(conn.sshChan, buffer[:packetLen]); err != nil {
			log.Printf("Error reading packet data for %s: %v", clientKey, err)
			return
		}

		// Send back to UDP client
		if _, err := c.udpListener.WriteToUDP(buffer[:packetLen], conn.udpAddr); err != nil {
			log.Printf("Error sending UDP packet to %s: %v", clientKey, err)
			return
		}

		// Update last active time
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