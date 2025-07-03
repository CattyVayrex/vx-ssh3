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
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// ServerConfig holds server configuration
type ServerConfig struct {
	SSHPort     int           // SSH server port (default: 22)
	TargetAddr  string        // Target UDP address (default: 127.0.0.1:51820)
	SSHUser     string        // Expected SSH username
	SSHPassword string        // Expected SSH password
	MaxConns    int           // Maximum concurrent connections
	IdleTimeout time.Duration // Connection idle timeout
}

// VXServer represents the main server
type VXServer struct {
	config *ServerConfig
	ctx    context.Context
	cancel context.CancelFunc
	bufferPool sync.Pool // Added for optimization
}

// NewVXServer creates a new server instance
func NewVXServer(config *ServerConfig) (*VXServer, error) {
	ctx, cancel := context.WithCancel(context.Background())

	server := &VXServer{
		config: config,
		ctx:    ctx,
		cancel: cancel,
	}

	// Initialize buffer pool for optimization (safe addition)
	server.bufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 65535)
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

	// Set socket buffer sizes for better performance (safe optimization)
	if err := udpConn.SetReadBuffer(1024 * 1024); err != nil {
		log.Printf("Warning: Could not set UDP read buffer: %v", err)
	}
	if err := udpConn.SetWriteBuffer(1024 * 1024); err != nil {
		log.Printf("Warning: Could not set UDP write buffer: %v", err)
	}

	log.Printf("Created UDP connection to %s for client %s", targetAddr, clientID)

	// Start forwarding goroutines
	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()

	// SSH to UDP
	go s.forwardSSHToUDP(ctx, sshChan, udpConn, clientID)
	// UDP to SSH
	go s.forwardUDPToSSH(ctx, udpConn, sshChan, clientID)

	// Wait for context cancellation
	<-ctx.Done()
}

// forwardSSHToUDP forwards packets from SSH to UDP
func (s *VXServer) forwardSSHToUDP(ctx context.Context, sshChan ssh.Channel, udpConn *net.UDPConn, clientID string) {
	buffer := s.bufferPool.Get().([]byte)
	defer s.bufferPool.Put(buffer)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Read from SSH channel
		n, err := sshChan.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading from SSH for %s: %v", clientID, err)
			}
			return
		}

		// Parse packet: [addr_len(2)][addr][data_len(4)][data]
		if n < 6 {
			continue
		}

		offset := 0
		
		// Read address length
		addrLen := binary.BigEndian.Uint16(buffer[offset:offset+2])
		offset += 2

		if offset+int(addrLen) > n {
			continue
		}

		// Skip address (we don't need it on server side)
		offset += int(addrLen)

		if offset+4 > n {
			continue
		}

		// Read data length
		dataLen := binary.BigEndian.Uint32(buffer[offset:offset+4])
		offset += 4

		if offset+int(dataLen) > n {
			continue
		}

		// Forward to UDP target
		_, err = udpConn.Write(buffer[offset:offset+int(dataLen)])
		if err != nil {
			log.Printf("Error writing to UDP for %s: %v", clientID, err)
			return
		}
	}
}

// forwardUDPToSSH forwards packets from UDP to SSH
func (s *VXServer) forwardUDPToSSH(ctx context.Context, udpConn *net.UDPConn, sshChan ssh.Channel, clientID string) {
	buffer := s.bufferPool.Get().([]byte)
	defer s.bufferPool.Put(buffer)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Read from UDP
		n, err := udpConn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading from UDP for %s: %v", clientID, err)
			}
			return
		}

		// Forward directly to SSH (no need to re-encode)
		_, err = sshChan.Write(buffer[:n])
		if err != nil {
			log.Printf("Error writing to SSH for %s: %v", clientID, err)
			return
		}
	}
}

// Stop gracefully stops the server
func (s *VXServer) Stop() {
	log.Printf("Stopping VX-Server...")
	s.cancel()
	log.Printf("VX-Server stopped")
}

// generateHostKey generates a temporary RSA host key
func generateHostKey() (ssh.Signer, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	privateKeyBytes := pem.EncodeToMemory(privateKeyPEM)
	signer, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		return nil, err
	}

	return signer, nil
}

func main() {
	// Command line flags
	var (
		sshPort     = flag.Int("ssh-port", 22, "SSH server port")
		targetAddr  = flag.String("target", "127.0.0.1:51820", "Target UDP address")
		sshUser     = flag.String("ssh-user", "", "Expected SSH username")
		sshPassword = flag.String("ssh-password", "", "Expected SSH password")
		maxConns    = flag.Int("max-conns", 100, "Maximum concurrent connections")
		idleTimeout = flag.Duration("idle-timeout", 3*time.Minute, "Connection idle timeout")
	)
	flag.Parse()

	// Validate required parameters
	if *sshUser == "" {
		fmt.Fprintf(os.Stderr, "Error: -ssh-user is required\n")
		fmt.Fprintf(os.Stderr, "Usage: %s -ssh-user <username> -ssh-password <password>\n", os.Args[0])
		os.Exit(1)
	}
	if *sshPassword == "" {
		fmt.Fprintf(os.Stderr, "Error: -ssh-password is required\n")
		os.Exit(1)
	}

	// Create server configuration
	config := &ServerConfig{
		SSHPort:     *sshPort,
		TargetAddr:  *targetAddr,
		SSHUser:     *sshUser,
		SSHPassword: *sshPassword,
		MaxConns:    *maxConns,
		IdleTimeout: *idleTimeout,
	}

	// Create and start server
	server, err := NewVXServer(config)
	if err != nil {
		log.Fatalf("Failed to create VX server: %v", err)
	}

	// Handle graceful shutdown
	go func() {
		// Simple signal handling - in production, use os/signal
		var input string
		fmt.Scanln(&input)
		server.Stop()
		os.Exit(0)
	}()

	// Start server
	if err := server.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
} 