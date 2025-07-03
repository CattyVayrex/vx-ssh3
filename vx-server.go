package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
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

// ServerConfig holds server configuration
type ServerConfig struct {
	SSHPort       int    // SSH server port (default: 22)
	TargetAddr    string // Target UDP address (default: 127.0.0.1:51820)
	SSHUser       string // Expected SSH username
	SSHPassword   string // Expected SSH password
	MaxConns      int    // Maximum concurrent connections
	IdleTimeout   time.Duration
	WorkerCount   int    // Number of worker goroutines (default: CPU cores * 2)
	UDPPoolSize   int    // UDP connection pool size (default: 20)
}

// Buffer pool for reducing GC pressure
var serverBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 65535)
	},
}

// Packet structure for server processing
type ServerPacket struct {
	data       []byte
	size       int
	sshChan    ssh.Channel
	packetType int // 0 = from SSH, 1 = from UDP
}

// Server packet pool
var serverPacketPool = sync.Pool{
	New: func() interface{} {
		return &ServerPacket{
			data: make([]byte, 65535),
		}
	},
}

// UDPConnectionPool manages a pool of UDP connections
type UDPConnectionPool struct {
	connections chan *net.UDPConn
	targetAddr  *net.UDPAddr
	mutex       sync.RWMutex
	closed      bool
}

// NewUDPConnectionPool creates a new UDP connection pool
func NewUDPConnectionPool(targetAddr *net.UDPAddr, poolSize int) *UDPConnectionPool {
	pool := &UDPConnectionPool{
		connections: make(chan *net.UDPConn, poolSize),
		targetAddr:  targetAddr,
	}

	// Pre-populate the pool
	for i := 0; i < poolSize; i++ {
		if conn, err := net.DialUDP("udp", nil, targetAddr); err == nil {
			pool.connections <- conn
		}
	}

	return pool
}

// Get retrieves a UDP connection from the pool
func (p *UDPConnectionPool) Get() (*net.UDPConn, error) {
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
		return net.DialUDP("udp", nil, p.targetAddr)
	}
}

// Put returns a UDP connection to the pool
func (p *UDPConnectionPool) Put(conn *net.UDPConn) {
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
func (p *UDPConnectionPool) Close() {
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

// ServerConnection represents a client connection (optimized)
type ServerConnection struct {
	sshChan    ssh.Channel
	udpConn    *net.UDPConn
	targetAddr *net.UDPAddr
	lastActive int64 // Use atomic for better performance
	connID     uint64
	udpPool    *UDPConnectionPool
}

// VXServer represents the main server (optimized)
type VXServer struct {
	config       *ServerConfig
	connections  sync.Map // Use sync.Map for better concurrent access
	udpPool      *UDPConnectionPool
	ctx          context.Context
	cancel       context.CancelFunc
	packetChan   chan *ServerPacket
	workers      sync.WaitGroup
	connCounter  uint64
}

// NewVXServer creates a new server instance
func NewVXServer(config *ServerConfig) (*VXServer, error) {
	// Set defaults for performance parameters
	if config.WorkerCount == 0 {
		config.WorkerCount = runtime.NumCPU() * 2
	}
	if config.UDPPoolSize == 0 {
		config.UDPPoolSize = 20
	}

	ctx, cancel := context.WithCancel(context.Background())
	
	return &VXServer{
		config:     config,
		ctx:        ctx,
		cancel:     cancel,
		packetChan: make(chan *ServerPacket, config.WorkerCount*100), // Buffered channel
	}, nil
}

// startWorkers starts the worker pool for processing packets
func (s *VXServer) startWorkers() {
	for i := 0; i < s.config.WorkerCount; i++ {
		s.workers.Add(1)
		go s.worker()
	}
}

// worker processes packets from the packet channel
func (s *VXServer) worker() {
	defer s.workers.Done()

	for {
		select {
		case <-s.ctx.Done():
			return
		case packet := <-s.packetChan:
			s.processPacket(packet)
			// Return packet to pool
			serverPacketPool.Put(packet)
		}
	}
}

// processPacket processes a packet from the queue
func (s *VXServer) processPacket(packet *ServerPacket) {
	if packet.packetType == 0 {
		// Packet from SSH, forward to UDP
		s.forwardToUDP(packet)
	} else {
		// Packet from UDP, forward to SSH
		s.forwardToSSH(packet)
	}
}

// forwardToUDP forwards data from SSH to UDP target
func (s *VXServer) forwardToUDP(packet *ServerPacket) {
	// Get UDP connection from pool
	udpConn, err := s.udpPool.Get()
	if err != nil {
		log.Printf("Failed to get UDP connection: %v", err)
		return
	}
	defer s.udpPool.Put(udpConn)

	// Forward to UDP target
	if _, err := udpConn.Write(packet.data[:packet.size]); err != nil {
		log.Printf("Error forwarding to UDP target: %v", err)
	}
}

// forwardToSSH forwards data from UDP to SSH channel
func (s *VXServer) forwardToSSH(packet *ServerPacket) {
	// Prepare packet with length prefix
	response := make([]byte, 4+packet.size)
	binary.BigEndian.PutUint32(response[:4], uint32(packet.size))
	copy(response[4:], packet.data[:packet.size])

	// Send via SSH channel
	if _, err := packet.sshChan.Write(response); err != nil {
		log.Printf("Error sending SSH response: %v", err)
	}
}

// Start begins the SSH server
func (s *VXServer) Start() error {
	// Parse target address
	targetAddr, err := net.ResolveUDPAddr("udp", s.config.TargetAddr)
	if err != nil {
		return fmt.Errorf("invalid target address: %v", err)
	}

	// Create UDP connection pool
	s.udpPool = NewUDPConnectionPool(targetAddr, s.config.UDPPoolSize)

	// SSH server configuration
	sshConfig := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == s.config.SSHUser && string(pass) == s.config.SSHPassword {
				return nil, nil
			}
			return nil, fmt.Errorf("authentication failed")
		},
	}

	// Generate host key
	hostKey, err := generateHostKey()
	if err != nil {
		return fmt.Errorf("failed to generate host key: %v", err)
	}
	sshConfig.AddHostKey(hostKey)

	// Start SSH listener
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.config.SSHPort))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %v", s.config.SSHPort, err)
	}
	defer listener.Close()

	log.Printf("VX-Server listening on SSH port %d", s.config.SSHPort)
	log.Printf("Target UDP address: %s", s.config.TargetAddr)
	log.Printf("Workers: %d, UDP pool size: %d", s.config.WorkerCount, s.config.UDPPoolSize)

	// Start worker pool
	s.startWorkers()

	// Start cleanup routine
	go s.cleanupRoutine()

	// Accept connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			if s.ctx.Err() != nil {
				return nil
			}
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go s.handleSSHConnection(conn, sshConfig, targetAddr)
	}
}

// handleSSHConnection processes a new SSH connection (optimized)
func (s *VXServer) handleSSHConnection(conn net.Conn, sshConfig *ssh.ServerConfig, targetAddr *net.UDPAddr) {
	defer conn.Close()

	// Set connection timeouts
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// SSH handshake
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, sshConfig)
	if err != nil {
		log.Printf("SSH handshake failed: %v", err)
		return
	}
	defer sshConn.Close()

	log.Printf("New SSH connection from %s (user: %s)", sshConn.RemoteAddr(), sshConn.User())

	// Discard global requests
	go ssh.DiscardRequests(reqs)

	// Handle channels
	for newChannel := range chans {
		if newChannel.ChannelType() != "vx-tunnel" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("Failed to accept channel: %v", err)
			continue
		}

		go ssh.DiscardRequests(requests)
		go s.handleChannelOptimized(channel, targetAddr, sshConn.RemoteAddr().String())
	}
}

// handleChannelOptimized processes data from an SSH channel (optimized)
func (s *VXServer) handleChannelOptimized(sshChan ssh.Channel, targetAddr *net.UDPAddr, clientID string) {
	defer sshChan.Close()

	// Create UDP connection to target
	udpConn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		log.Printf("Failed to connect to target %s: %v", targetAddr, err)
		return
	}
	defer udpConn.Close()

	// Set UDP buffer sizes
	udpConn.SetReadBuffer(1024 * 1024)  // 1MB
	udpConn.SetWriteBuffer(1024 * 1024) // 1MB

	log.Printf("Created UDP connection to %s for client %s", targetAddr, clientID)

	// Create connection object
	connID := atomic.AddUint64(&s.connCounter, 1)
	conn := &ServerConnection{
		sshChan:    sshChan,
		udpConn:    udpConn,
		targetAddr: targetAddr,
		lastActive: time.Now().UnixNano(),
		connID:     connID,
		udpPool:    s.udpPool,
	}

	// Store connection
	s.connections.Store(clientID, conn)

	// Start UDP receiver
	go s.receiveFromUDPOptimized(conn, clientID)

	// Handle SSH data
	s.receiveFromSSHOptimized(conn, clientID)
}

// receiveFromSSHOptimized reads data from SSH channel and forwards to UDP (optimized)
func (s *VXServer) receiveFromSSHOptimized(conn *ServerConnection, clientID string) {
	defer s.removeConnection(clientID)

	// Use buffer from pool
	buffer := serverBufferPool.Get().([]byte)
	defer serverBufferPool.Put(buffer)

	var lengthBuf [4]byte

	for {
		// Read packet length
		if _, err := io.ReadFull(conn.sshChan, lengthBuf[:]); err != nil {
			if err != io.EOF {
				log.Printf("Error reading packet length from %s: %v", clientID, err)
			}
			return
		}

		packetLen := binary.BigEndian.Uint32(lengthBuf[:])
		if packetLen > 65535 {
			log.Printf("Invalid packet length %d from %s", packetLen, clientID)
			return
		}

		// Read packet data
		if _, err := io.ReadFull(conn.sshChan, buffer[:packetLen]); err != nil {
			log.Printf("Error reading packet data from %s: %v", clientID, err)
			return
		}

		// Get packet from pool and send to worker
		packet := serverPacketPool.Get().(*ServerPacket)
		packet.size = int(packetLen)
		copy(packet.data[:packet.size], buffer[:packetLen])
		packet.sshChan = conn.sshChan
		packet.packetType = 0 // From SSH

		// Send to worker pool (non-blocking)
		select {
		case s.packetChan <- packet:
		default:
			// Channel is full, process directly
			s.processPacket(packet)
			serverPacketPool.Put(packet)
		}

		// Update activity using atomic operation
		atomic.StoreInt64(&conn.lastActive, time.Now().UnixNano())
	}
}

// receiveFromUDPOptimized reads responses from UDP target and sends back via SSH (optimized)
func (s *VXServer) receiveFromUDPOptimized(conn *ServerConnection, clientID string) {
	// Use buffer from pool
	buffer := serverBufferPool.Get().([]byte)
	defer serverBufferPool.Put(buffer)

	for {
		// Set read timeout
		conn.udpConn.SetReadDeadline(time.Now().Add(s.config.IdleTimeout))

		// Read from UDP target
		n, err := conn.udpConn.Read(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Timeout, check if connection is still active
				continue
			}
			log.Printf("Error reading UDP response for %s: %v", clientID, err)
			return
		}

		// Get packet from pool and send to worker
		packet := serverPacketPool.Get().(*ServerPacket)
		packet.size = n
		copy(packet.data[:n], buffer[:n])
		packet.sshChan = conn.sshChan
		packet.packetType = 1 // From UDP

		// Send to worker pool (non-blocking)
		select {
		case s.packetChan <- packet:
		default:
			// Channel is full, process directly
			s.processPacket(packet)
			serverPacketPool.Put(packet)
		}

		// Update activity using atomic operation
		atomic.StoreInt64(&conn.lastActive, time.Now().UnixNano())
	}
}

// removeConnection removes and closes a connection (optimized)
func (s *VXServer) removeConnection(clientID string) {
	if value, ok := s.connections.LoadAndDelete(clientID); ok {
		conn := value.(*ServerConnection)
		log.Printf("Removing connection for client %s", clientID)
		conn.sshChan.Close()
		conn.udpConn.Close()
	}
}

// cleanupRoutine periodically removes idle connections (optimized)
func (s *VXServer) cleanupRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.cleanupIdleConnections()
		}
	}
}

// cleanupIdleConnections removes idle connections (optimized)
func (s *VXServer) cleanupIdleConnections() {
	now := time.Now().UnixNano()
	timeoutNano := s.config.IdleTimeout.Nanoseconds()
	var toRemove []string

	s.connections.Range(func(key, value interface{}) bool {
		clientID := key.(string)
		conn := value.(*ServerConnection)
		
		lastActive := atomic.LoadInt64(&conn.lastActive)
		if now-lastActive > timeoutNano {
			toRemove = append(toRemove, clientID)
		}
		return true
	})

	for _, clientID := range toRemove {
		s.removeConnection(clientID)
	}

	if len(toRemove) > 0 {
		log.Printf("Cleaned up %d idle connections", len(toRemove))
	}
}

// generateHostKey creates a temporary RSA host key
func generateHostKey() (ssh.Signer, error) {
	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %v", err)
	}

	// Convert to PEM format
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	privateKeyBytes := pem.EncodeToMemory(privateKeyPEM)

	// Parse into SSH signer
	signer, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	return signer, nil
}

func main() {
	var (
		sshPort     = flag.Int("ssh-port", 22, "SSH server port")
		targetAddr  = flag.String("target", "127.0.0.1:51820", "Target UDP address")
		sshUser     = flag.String("ssh-user", "", "Expected SSH username")
		sshPassword = flag.String("ssh-password", "", "Expected SSH password")
		maxConns    = flag.Int("max-conns", 100, "Maximum concurrent connections")
		idleTimeout = flag.Duration("idle-timeout", 3*time.Minute, "Connection idle timeout")
		workerCount = flag.Int("workers", 0, "Number of worker goroutines (0 = auto)")
		udpPoolSize = flag.Int("udp-pool-size", 20, "UDP connection pool size")
	)
	flag.Parse()

	if *sshUser == "" || *sshPassword == "" {
		fmt.Fprintf(os.Stderr, "Error: -ssh-user and -ssh-password are required\n")
		fmt.Fprintf(os.Stderr, "Usage: %s -ssh-user <username> -ssh-password <password>\n", os.Args[0])
		os.Exit(1)
	}

	config := &ServerConfig{
		SSHPort:     *sshPort,
		TargetAddr:  *targetAddr,
		SSHUser:     *sshUser,
		SSHPassword: *sshPassword,
		MaxConns:    *maxConns,
		IdleTimeout: *idleTimeout,
		WorkerCount: *workerCount,
		UDPPoolSize: *udpPoolSize,
	}

	server, err := NewVXServer(config)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	if err := server.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
} 