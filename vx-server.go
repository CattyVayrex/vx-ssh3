package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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

// ServerConfig holds server configuration
type ServerConfig struct {
	SSHPort       int    // SSH server port (default: 22)
	TargetAddr    string // Target UDP address (default: 127.0.0.1:51820)
	SSHUser       string // Expected SSH username
	SSHPassword   string // Expected SSH password
	MaxConns      int    // Maximum concurrent connections
	IdleTimeout   time.Duration
}

// Packet represents a UDP packet with client info (server side)
type Packet struct {
	ClientAddr string
	Data       []byte
	Length     int
}

// ServerConnection represents a client connection (optimized)
type ServerConnection struct {
	sshChan      ssh.Channel
	udpConn      *net.UDPConn
	targetAddr   *net.UDPAddr
	sendQueue    chan *Packet
	recvQueue    chan *Packet
	clientID     string
	ctx          context.Context
	cancel       context.CancelFunc
}

// VXServer represents the main server (optimized)
type VXServer struct {
	config       *ServerConfig
	connections  map[string]*ServerConnection
	connMutex    sync.RWMutex
	ctx          context.Context
	cancel       context.CancelFunc
	packetPool   sync.Pool
	bufferPool   sync.Pool
}

// NewVXServer creates a new server instance (optimized)
func NewVXServer(config *ServerConfig) (*VXServer, error) {
	ctx, cancel := context.WithCancel(context.Background())
	
	server := &VXServer{
		config:      config,
		connections: make(map[string]*ServerConnection),
		ctx:         ctx,
		cancel:      cancel,
	}

	// Initialize buffer pools
	server.bufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 65535)
		},
	}

	server.packetPool = sync.Pool{
		New: func() interface{} {
			return &Packet{
				Data: make([]byte, 65535),
			}
		},
	}

	return server, nil
}

// Start begins the SSH server
func (s *VXServer) Start() error {
	// Parse target address
	targetAddr, err := net.ResolveUDPAddr("udp", s.config.TargetAddr)
	if err != nil {
		return fmt.Errorf("invalid target address: %v", err)
	}

	// SSH server configuration
	sshConfig := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == s.config.SSHUser && string(pass) == s.config.SSHPassword {
				return nil, nil
			}
			return nil, fmt.Errorf("authentication failed")
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

	// Start connection monitor
	go s.connectionMonitor()

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

// handleChannel processes data from an SSH channel (optimized)
func (s *VXServer) handleChannel(sshChan ssh.Channel, targetAddr *net.UDPAddr, clientID string) {
	defer sshChan.Close()

	// Create UDP connection to target with optimized settings
	udpConn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		log.Printf("Failed to connect to target %s: %v", targetAddr, err)
		return
	}
	defer udpConn.Close()

	// Set UDP buffer sizes for performance
	if err := udpConn.SetReadBuffer(1024 * 1024); err != nil {
		log.Printf("Warning: Could not set UDP read buffer: %v", err)
	}
	if err := udpConn.SetWriteBuffer(1024 * 1024); err != nil {
		log.Printf("Warning: Could not set UDP write buffer: %v", err)
	}

	log.Printf("Created optimized UDP connection to %s for client %s", targetAddr, clientID)

	// Create connection context
	ctx, cancel := context.WithCancel(s.ctx)

	// Create connection object
	conn := &ServerConnection{
		sshChan:    sshChan,
		udpConn:    udpConn,
		targetAddr: targetAddr,
		sendQueue:  make(chan *Packet, 500),
		recvQueue:  make(chan *Packet, 500),
		clientID:   clientID,
		ctx:        ctx,
		cancel:     cancel,
	}

	// Store connection
	s.connMutex.Lock()
	s.connections[clientID] = conn
	s.connMutex.Unlock()

	// Start processing goroutines
	go s.sshSender(conn)     // SSH -> UDP
	go s.sshReceiver(conn)   // UDP -> SSH  
	go s.udpReceiver(conn)   // UDP responses

	// Wait for context cancellation
	<-ctx.Done()
	s.removeConnection(clientID)
}

// sshSender handles sending packets from SSH to UDP (optimized)
func (s *VXServer) sshSender(conn *ServerConnection) {
	defer conn.cancel()

	buffer := make([]byte, 65535)

	for {
		select {
		case <-conn.ctx.Done():
			return
		default:
		}

		// Read from SSH channel
		n, err := conn.sshChan.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading from SSH for %s: %v", conn.clientID, err)
			}
			return
		}

		// Parse batched data and forward to UDP
		s.parseAndForwardToUDP(conn, buffer[:n])
	}
}

// parseAndForwardToUDP parses batched data and forwards to UDP
func (s *VXServer) parseAndForwardToUDP(conn *ServerConnection, data []byte) {
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

		// Skip address (not needed for server side)
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

		// Forward directly to UDP target
		if _, err := conn.udpConn.Write(data[offset:offset+dataLen]); err != nil {
			log.Printf("Error forwarding to UDP: %v", err)
		}
		
		offset += dataLen
	}
}

// udpReceiver reads responses from UDP target (optimized)
func (s *VXServer) udpReceiver(conn *ServerConnection) {
	for {
		select {
		case <-conn.ctx.Done():
			return
		default:
		}

		// Get buffer from pool
		buffer := s.bufferPool.Get().([]byte)

		// Read from UDP target
		n, err := conn.udpConn.Read(buffer)
		if err != nil {
			s.bufferPool.Put(buffer)
			log.Printf("Error reading UDP response for %s: %v", conn.clientID, err)
			return
		}

		// Get packet from pool
		packet := s.packetPool.Get().(*Packet)
		packet.ClientAddr = conn.clientID
		packet.Length = n
		copy(packet.Data[:n], buffer[:n])

		// Return buffer to pool
		s.bufferPool.Put(buffer)

		// Queue for SSH sending
		select {
		case conn.recvQueue <- packet:
		default:
			s.packetPool.Put(packet) // Queue full, drop packet
		}
	}
}

// sshReceiver handles sending UDP responses back via SSH (optimized)
func (s *VXServer) sshReceiver(conn *ServerConnection) {
	batch := make([]*Packet, 0, 10)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-conn.ctx.Done():
			return

		case packet := <-conn.recvQueue:
			batch = append(batch, packet)
			
			// Send batch if full
			if len(batch) >= cap(batch) {
				s.sendBatchToSSH(conn, batch)
				batch = batch[:0]
			}

		case <-ticker.C:
			// Send batch on timer
			if len(batch) > 0 {
				s.sendBatchToSSH(conn, batch)
				batch = batch[:0]
			}
		}
	}
}

// sendBatchToSSH sends batched packets via SSH
func (s *VXServer) sendBatchToSSH(conn *ServerConnection, batch []*Packet) {
	// Get buffer from pool
	buffer := s.bufferPool.Get().([]byte)
	defer s.bufferPool.Put(buffer)

	offset := 0
	for _, packet := range batch {
		// Write client address length and address
		addrBytes := []byte(packet.ClientAddr)
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
		s.packetPool.Put(packet)
	}

	// Send entire batch
	if _, err := conn.sshChan.Write(buffer[:offset]); err != nil {
		log.Printf("Error sending batch to SSH: %v", err)
		conn.cancel() // Close connection on error
	}
}

// removeConnection removes and closes a connection (optimized)
func (s *VXServer) removeConnection(clientID string) {
	s.connMutex.Lock()
	defer s.connMutex.Unlock()

	if conn, exists := s.connections[clientID]; exists {
		log.Printf("Removing connection for client %s", clientID)
		conn.cancel() // Cancel context first
		conn.sshChan.Close()
		conn.udpConn.Close()
		close(conn.sendQueue)
		close(conn.recvQueue)
		delete(s.connections, clientID)
	}
}

// connectionMonitor monitors connection health and removes dead connections
func (s *VXServer) connectionMonitor() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.checkConnections()
		}
	}
}

// checkConnections removes dead connections (optimized)
func (s *VXServer) checkConnections() {
	var toRemove []string

	s.connMutex.RLock()
	for clientID, conn := range s.connections {
		select {
		case <-conn.ctx.Done():
			toRemove = append(toRemove, clientID)
		default:
		}
	}
	s.connMutex.RUnlock()

	for _, clientID := range toRemove {
		s.removeConnection(clientID)
	}

	if len(toRemove) > 0 {
		log.Printf("Cleaned up %d dead connections", len(toRemove))
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
	}

	server, err := NewVXServer(config)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	if err := server.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
} 