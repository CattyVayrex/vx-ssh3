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
	"sync/atomic"
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
	WorkerCount  int    // Number of worker goroutines (default: CPU cores * 2)
	PoolSize     int    // SSH connection pool size (default: 10)
}

// Buffer pool for reducing GC pressure
var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 65535)
	},
}

// Packet represents a UDP packet with metadata
type Packet struct {
	data     []byte
	size     int
	clientAddr *net.UDPAddr
}

// PacketPool for reusing packet structures
var packetPool = sync.Pool{
	New: func() interface{} {
		return &Packet{
			data: make([]byte, 65535),
		}
	},
}

// ClientConnection represents a UDP client connection (optimized)
type ClientConnection struct {
	udpAddr    *net.UDPAddr
	sshChan    ssh.Channel
	lastActive int64 // Use atomic for better performance
	connID     uint64
}

// SSHConnectionPool manages a pool of SSH connections
type SSHConnectionPool struct {
	connections chan ssh.Conn
	config      *ssh.ClientConfig
	remoteAddr  string
	mutex       sync.RWMutex
	closed      bool
}

// NewSSHConnectionPool creates a new SSH connection pool
func NewSSHConnectionPool(remoteAddr string, sshConfig *ssh.ClientConfig, poolSize int) *SSHConnectionPool {
	pool := &SSHConnectionPool{
		connections: make(chan ssh.Conn, poolSize),
		config:      sshConfig,
		remoteAddr:  remoteAddr,
	}

	// Pre-populate the pool
	for i := 0; i < poolSize; i++ {
		if conn, err := ssh.Dial("tcp", remoteAddr, sshConfig); err == nil {
			pool.connections <- conn
		}
	}

	return pool
}

// Get retrieves a connection from the pool
func (p *SSHConnectionPool) Get() (ssh.Conn, error) {
	p.mutex.RLock()
	if p.closed {
		p.mutex.RUnlock()
		return nil, fmt.Errorf("pool is closed")
	}
	p.mutex.RUnlock()

	select {
	case conn := <-p.connections:
		return conn, nil
	default:
		// Create new connection if pool is empty
		return ssh.Dial("tcp", p.remoteAddr, p.config)
	}
}

// Put returns a connection to the pool
func (p *SSHConnectionPool) Put(conn ssh.Conn) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	if p.closed {
		conn.Close()
		return
	}

	select {
	case p.connections <- conn:
	default:
		// Pool is full, close the connection
		conn.Close()
	}
}

// Close closes all connections in the pool
func (p *SSHConnectionPool) Close() {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if p.closed {
		return
	}
	p.closed = true

	close(p.connections)
	for conn := range p.connections {
		conn.Close()
	}
}

// VXClient represents the main client structure (optimized)
type VXClient struct {
	config       *ClientConfig
	udpListener  *net.UDPConn
	connections  sync.Map // Use sync.Map for better concurrent access
	sshPool      *SSHConnectionPool
	ctx          context.Context
	cancel       context.CancelFunc
	packetChan   chan *Packet
	workers      sync.WaitGroup
	connCounter  uint64
}

// NewVXClient creates a new VX client instance
func NewVXClient(config *ClientConfig) (*VXClient, error) {
	// Set defaults for performance parameters
	if config.WorkerCount == 0 {
		config.WorkerCount = runtime.NumCPU() * 2
	}
	if config.PoolSize == 0 {
		config.PoolSize = 10
	}

	// Create SSH client configuration
	sshConfig := &ssh.ClientConfig{
		User: config.SSHUser,
		Auth: []ssh.AuthMethod{
			ssh.Password(config.SSHPassword),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second, // Reduced timeout for faster connections
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Create SSH connection pool
	sshPool := NewSSHConnectionPool(config.RemoteAddr, sshConfig, config.PoolSize)

	return &VXClient{
		config:     config,
		sshPool:    sshPool,
		ctx:        ctx,
		cancel:     cancel,
		packetChan: make(chan *Packet, config.WorkerCount*100), // Buffered channel for better throughput
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

	// Set socket buffer sizes for better performance
	c.udpListener.SetReadBuffer(4 * 1024 * 1024)  // 4MB read buffer
	c.udpListener.SetWriteBuffer(4 * 1024 * 1024) // 4MB write buffer

	log.Printf("VX-Client listening on UDP port %d", c.config.LocalPort)
	log.Printf("SSH target: %s (user: %s)", c.config.RemoteAddr, c.config.SSHUser)
	log.Printf("Workers: %d, Pool size: %d", c.config.WorkerCount, c.config.PoolSize)

	// Start worker pool
	c.startWorkers()

	// Start connection cleanup routine
	go c.cleanupRoutine()

	// Main UDP packet reading loop (optimized)
	return c.handleUDPPackets()
}

// startWorkers starts the worker pool for processing packets
func (c *VXClient) startWorkers() {
	for i := 0; i < c.config.WorkerCount; i++ {
		c.workers.Add(1)
		go c.worker()
	}
}

// worker processes packets from the packet channel
func (c *VXClient) worker() {
	defer c.workers.Done()

	for {
		select {
		case <-c.ctx.Done():
			return
		case packet := <-c.packetChan:
			c.processPacket(packet)
			// Return packet to pool
			packetPool.Put(packet)
		}
	}
}

// handleUDPPackets processes incoming UDP packets (optimized)
func (c *VXClient) handleUDPPackets() error {
	for {
		select {
		case <-c.ctx.Done():
			return nil
		default:
		}

		// Get packet from pool
		packet := packetPool.Get().(*Packet)

		// Read UDP packet
		n, clientAddr, err := c.udpListener.ReadFromUDP(packet.data)
		if err != nil {
			packetPool.Put(packet)
			if c.ctx.Err() != nil {
				return nil
			}
			log.Printf("Error reading UDP packet: %v", err)
			continue
		}

		packet.size = n
		packet.clientAddr = clientAddr

		// Send to worker pool (non-blocking)
		select {
		case c.packetChan <- packet:
		default:
			// Channel is full, process in current goroutine to avoid dropping
			c.processPacket(packet)
			packetPool.Put(packet)
		}
	}
}

// processPacket processes a single UDP packet (optimized)
func (c *VXClient) processPacket(packet *Packet) {
	clientKey := packet.clientAddr.String()

	// Get or create connection for this client
	conn, err := c.getOrCreateConnection(clientKey, packet.clientAddr)
	if err != nil {
		log.Printf("Failed to get connection for %s: %v", clientKey, err)
		return
	}

	// Update last active time using atomic operation
	atomic.StoreInt64(&conn.lastActive, time.Now().UnixNano())

	// Send packet through SSH tunnel
	if err := c.sendPacketOptimized(conn, packet.data[:packet.size]); err != nil {
		log.Printf("Failed to send packet for %s: %v", clientKey, err)
		c.removeConnection(clientKey)
	}
}

// getOrCreateConnection gets existing connection or creates a new one (optimized)
func (c *VXClient) getOrCreateConnection(clientKey string, clientAddr *net.UDPAddr) (*ClientConnection, error) {
	// Try to get existing connection
	if value, ok := c.connections.Load(clientKey); ok {
		return value.(*ClientConnection), nil
	}

	// Create new connection
	return c.createConnectionOptimized(clientKey, clientAddr)
}

// createConnectionOptimized establishes a new SSH connection for a client (optimized)
func (c *VXClient) createConnectionOptimized(clientKey string, clientAddr *net.UDPAddr) (*ClientConnection, error) {
	log.Printf("Creating new SSH connection for client %s", clientKey)

	// Get SSH connection from pool
	sshConn, err := c.sshPool.Get()
	if err != nil {
		return nil, fmt.Errorf("failed to get SSH connection: %v", err)
	}

	// Open channel for UDP tunneling
	sshChan, reqs, err := sshConn.OpenChannel("vx-tunnel", nil)
	if err != nil {
		c.sshPool.Put(sshConn)
		return nil, fmt.Errorf("failed to open SSH channel: %v", err)
	}

	// Discard incoming requests
	go ssh.DiscardRequests(reqs)

	// Create connection object
	connID := atomic.AddUint64(&c.connCounter, 1)
	conn := &ClientConnection{
		udpAddr:    clientAddr,
		sshChan:    sshChan,
		lastActive: time.Now().UnixNano(),
		connID:     connID,
	}

	// Store connection (check for race condition)
	if actual, loaded := c.connections.LoadOrStore(clientKey, conn); loaded {
		// Another goroutine created the connection, close ours and use theirs
		sshChan.Close()
		c.sshPool.Put(sshConn)
		return actual.(*ClientConnection), nil
	}

	// Start receiving routine for this connection
	go c.receiveFromSSHOptimized(clientKey, conn, sshConn)

	return conn, nil
}

// sendPacketOptimized sends a UDP packet through SSH channel (optimized)
func (c *VXClient) sendPacketOptimized(conn *ClientConnection, data []byte) error {
	// Pre-allocate packet with exact size needed
	packet := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(packet[:4], uint32(len(data)))
	copy(packet[4:], data)

	// Send through SSH channel
	_, err := conn.sshChan.Write(packet)
	return err
}

// receiveFromSSHOptimized handles incoming data from SSH channel (optimized)
func (c *VXClient) receiveFromSSHOptimized(clientKey string, conn *ClientConnection, sshConn ssh.Conn) {
	defer func() {
		c.removeConnection(clientKey)
		c.sshPool.Put(sshConn)
	}()

	// Use buffer from pool
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

		// Update last active time using atomic operation
		atomic.StoreInt64(&conn.lastActive, time.Now().UnixNano())
	}
}

// removeConnection removes and closes a connection (optimized)
func (c *VXClient) removeConnection(clientKey string) {
	if value, ok := c.connections.LoadAndDelete(clientKey); ok {
		conn := value.(*ClientConnection)
		log.Printf("Removing connection for client %s", clientKey)
		conn.sshChan.Close()
	}
}

// cleanupRoutine periodically removes idle connections (optimized)
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

// cleanupIdleConnections removes connections that have been idle (optimized)
func (c *VXClient) cleanupIdleConnections() {
	now := time.Now().UnixNano()
	timeoutNano := c.config.IdleTimeout.Nanoseconds()
	var toRemove []string

	c.connections.Range(func(key, value interface{}) bool {
		clientKey := key.(string)
		conn := value.(*ClientConnection)
		
		lastActive := atomic.LoadInt64(&conn.lastActive)
		if now-lastActive > timeoutNano {
			toRemove = append(toRemove, clientKey)
		}
		return true
	})

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

	// Wait for workers to finish
	c.workers.Wait()

	// Close SSH pool
	c.sshPool.Close()

	// Close all connections
	c.connections.Range(func(key, value interface{}) bool {
		clientKey := key.(string)
		c.removeConnection(clientKey)
		return true
	})

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
		workerCount = flag.Int("workers", 0, "Number of worker goroutines (0 = auto)")
		poolSize    = flag.Int("pool-size", 10, "SSH connection pool size")
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
		PoolSize:    *poolSize,
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