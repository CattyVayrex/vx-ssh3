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
	WorkerCount   int    // Number of worker goroutines
	BufferSize    int    // Buffer size for packet processing
}

// Buffer pool for reusing memory on server side
var serverBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 65535)
	},
}

// ServerConnection represents a client connection
type ServerConnection struct {
	sshChan    ssh.Channel
	udpConn    *net.UDPConn
	targetAddr *net.UDPAddr
	lastActive time.Time
	mutex      sync.RWMutex
}

// VXServer represents the main server
type VXServer struct {
	config      *ServerConfig
	connections map[string]*ServerConnection
	connMutex   sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewVXServer creates a new server instance
func NewVXServer(config *ServerConfig) (*VXServer, error) {
	// Set default worker count if not specified
	if config.WorkerCount == 0 {
		config.WorkerCount = runtime.NumCPU() * 2
	}
	if config.BufferSize == 0 {
		config.BufferSize = 8192
	}

	ctx, cancel := context.WithCancel(context.Background())
	
	return &VXServer{
		config:      config,
		connections: make(map[string]*ServerConnection, config.MaxConns),
		ctx:         ctx,
		cancel:      cancel,
	}, nil
}

// Start begins the SSH server
func (s *VXServer) Start() error {
	// Parse target address
	targetAddr, err := net.ResolveUDPAddr("udp", s.config.TargetAddr)
	if err != nil {
		return fmt.Errorf("invalid target address: %v", err)
	}

	// Optimized SSH server configuration
	sshConfig := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == s.config.SSHUser && string(pass) == s.config.SSHPassword {
				return nil, nil
			}
			return nil, fmt.Errorf("authentication failed")
		},
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

	// Generate host key (in production, use proper key management)
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
	log.Printf("Using optimized configuration with %d worker capacity", s.config.WorkerCount)

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

// handleSSHConnection processes a new SSH connection
func (s *VXServer) handleSSHConnection(conn net.Conn, sshConfig *ssh.ServerConfig, targetAddr *net.UDPAddr) {
	defer conn.Close()

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
		go s.handleChannel(channel, targetAddr, sshConn.RemoteAddr().String())
	}
}

// handleChannel processes data from an SSH channel
func (s *VXServer) handleChannel(sshChan ssh.Channel, targetAddr *net.UDPAddr, clientID string) {
	defer sshChan.Close()

	// Create UDP connection to target
	udpConn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		log.Printf("Failed to connect to target %s: %v", targetAddr, err)
		return
	}
	defer udpConn.Close()

	// Optimize UDP connection
	if err := s.optimizeUDPConnection(udpConn); err != nil {
		log.Printf("Warning: Could not optimize UDP connection: %v", err)
	}

	log.Printf("Created UDP connection to %s for client %s", targetAddr, clientID)

	// Create connection object
	conn := &ServerConnection{
		sshChan:    sshChan,
		udpConn:    udpConn,
		targetAddr: targetAddr,
		lastActive: time.Now(),
	}

	// Store connection
	s.connMutex.Lock()
	s.connections[clientID] = conn
	s.connMutex.Unlock()

	// Start UDP receiver
	go s.receiveFromUDP(conn, clientID)

	// Handle SSH data
	s.receiveFromSSH(conn, clientID)
}

// receiveFromSSH reads data from SSH channel and forwards to UDP
func (s *VXServer) receiveFromSSH(conn *ServerConnection, clientID string) {
	defer s.removeConnection(clientID)

	// Get buffer from pool
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
			log.Printf("Error reading packet data from %s: %v", clientID, err)
			return
		}

		// Forward to UDP target
		if _, err := conn.udpConn.Write(readBuffer); err != nil {
			log.Printf("Error forwarding to UDP target from %s: %v", clientID, err)
			return
		}

		// Update activity (optimized - less frequent locking)
		conn.mutex.Lock()
		conn.lastActive = time.Now()
		conn.mutex.Unlock()
	}
}

// receiveFromUDP reads responses from UDP target and sends back via SSH
func (s *VXServer) receiveFromUDP(conn *ServerConnection, clientID string) {
	// Get buffers from pool
	readBuffer := serverBufferPool.Get().([]byte)
	defer serverBufferPool.Put(readBuffer)
	
	sendBuffer := serverBufferPool.Get().([]byte)
	defer serverBufferPool.Put(sendBuffer)

	for {
		// Read from UDP target
		n, err := conn.udpConn.Read(readBuffer)
		if err != nil {
			log.Printf("Error reading UDP response for %s: %v", clientID, err)
			return
		}

		// Prepare packet with length prefix (reuse buffer)
		if n+4 <= len(sendBuffer) {
			binary.BigEndian.PutUint32(sendBuffer[:4], uint32(n))
			copy(sendBuffer[4:4+n], readBuffer[:n])
			
			// Send via SSH channel
			if _, err := conn.sshChan.Write(sendBuffer[:4+n]); err != nil {
				log.Printf("Error sending SSH response to %s: %v", clientID, err)
				return
			}
		} else {
			// Fallback allocation for large packets
			packet := make([]byte, 4+n)
			binary.BigEndian.PutUint32(packet[:4], uint32(n))
			copy(packet[4:], readBuffer[:n])
			
			if _, err := conn.sshChan.Write(packet); err != nil {
				log.Printf("Error sending SSH response to %s: %v", clientID, err)
				return
			}
		}

		// Update activity (optimized - less frequent locking)
		conn.mutex.Lock()
		conn.lastActive = time.Now()
		conn.mutex.Unlock()
	}
}

// removeConnection removes and closes a connection
func (s *VXServer) removeConnection(clientID string) {
	s.connMutex.Lock()
	defer s.connMutex.Unlock()

	if conn, exists := s.connections[clientID]; exists {
		log.Printf("Removing connection for client %s", clientID)
		conn.sshChan.Close()
		conn.udpConn.Close()
		delete(s.connections, clientID)
	}
}

// cleanupRoutine periodically removes idle connections
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

// cleanupIdleConnections removes idle connections
func (s *VXServer) cleanupIdleConnections() {
	now := time.Now()
	var toRemove []string

	s.connMutex.RLock()
	for clientID, conn := range s.connections {
		conn.mutex.RLock()
		if now.Sub(conn.lastActive) > s.config.IdleTimeout {
			toRemove = append(toRemove, clientID)
		}
		conn.mutex.RUnlock()
	}
	s.connMutex.RUnlock()

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

// optimizeUDPConnection applies performance optimizations to UDP connections
func (s *VXServer) optimizeUDPConnection(conn *net.UDPConn) error {
	// Set larger receive buffer
	if err := conn.SetReadBuffer(1024 * 1024); err != nil { // 1MB
		return err
	}
	// Set larger send buffer
	if err := conn.SetWriteBuffer(1024 * 1024); err != nil { // 1MB
		return err
	}
	return nil
}

func main() {
	var (
		sshPort     = flag.Int("ssh-port", 22, "SSH server port")
		targetAddr  = flag.String("target", "127.0.0.1:51820", "Target UDP address")
		sshUser     = flag.String("ssh-user", "", "Expected SSH username")
		sshPassword = flag.String("ssh-password", "", "Expected SSH password")
		maxConns    = flag.Int("max-conns", 200, "Maximum concurrent connections")
		idleTimeout = flag.Duration("idle-timeout", 3*time.Minute, "Connection idle timeout")
		workerCount = flag.Int("workers", 0, "Number of worker goroutines (0 = auto)")
		bufferSize  = flag.Int("buffer-size", 16384, "Internal buffer size for packet processing")
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
		BufferSize:  *bufferSize,
	}

	server, err := NewVXServer(config)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	if err := server.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
} 