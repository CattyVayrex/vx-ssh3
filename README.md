# VX-SSH: UDP over SSH Tunnel

VX-SSH is a lightweight and fast UDP tunneling tool that transmits UDP packets through SSH connections. It's designed specifically for tunneling Wireguard traffic through SSH to bypass deep packet inspection and censorship.

## Overview

VX-SSH creates a secure tunnel between two servers using SSH protocol:

- **Client (Iran Server)**: Receives UDP packets on port 51820 and forwards them through SSH
- **Server (England Server)**: Accepts SSH connections, receives UDP data, and forwards to local port 51820

```
[Wireguard Clients] -> [Iran Server:51820] -> [SSH Tunnel] -> [England Server:51820] -> [Wireguard Server]
```

## Features

- **High Performance**: Optimized for speed with concurrent packet processing
- **Lightweight**: Minimal overhead and resource usage
- **Real-time**: No packet loss with proper connection management
- **Multi-connection**: Handles multiple clients simultaneously
- **Simple Setup**: Easy configuration with command-line arguments
- **Auto-cleanup**: Automatic cleanup of idle connections

## Installation

### Prerequisites

- Go 1.21 or later
- Network access between client and server

### Build Instructions

1. Clone or download the project
2. Navigate to the vx-ssh directory
3. Build the binaries:

```bash
# Build client
go build -o vx-client vx-client.go

# Build server
go build -o vx-server vx-server.go
```

### Cross-compilation for Linux

```bash
# For Linux client
GOOS=linux GOARCH=amd64 go build -o vx-client-linux vx-client.go

# For Linux server
GOOS=linux GOARCH=amd64 go build -o vx-server-linux vx-server.go
```

## Usage

### Server Setup (England Server)

Run the server on your England server that has access to the Wireguard server:

```bash
./vx-server -ssh-user myuser -ssh-password mypassword
```

**Server Options:**
- `-ssh-port`: SSH server port (default: 22)
- `-target`: Target UDP address (default: 127.0.0.1:51820)
- `-ssh-user`: SSH username (required)
- `-ssh-password`: SSH password (required)
- `-max-conns`: Maximum concurrent connections (default: 100)
- `-idle-timeout`: Connection idle timeout (default: 3m)

**Example:**
```bash
./vx-server -ssh-port 2222 -target 10.0.0.1:51820 -ssh-user tunnel -ssh-password secretpass123
```

### Client Setup (Iran Server)

Run the client on your Iran server where Wireguard clients connect:

```bash
./vx-client -remote england-server.com:22 -ssh-user myuser -ssh-password mypassword
```

**Client Options:**
- `-local-port`: Local UDP port to listen on (default: 51820)
- `-remote`: SSH server address (required, format: host:port)
- `-ssh-user`: SSH username (required)
- `-ssh-password`: SSH password (required)
- `-max-conns`: Maximum concurrent connections (default: 100)
- `-idle-timeout`: Connection idle timeout (default: 3m)

**Example:**
```bash
./vx-client -local-port 51820 -remote england-server.com:2222 -ssh-user tunnel -ssh-password secretpass123
```

## Complete Setup Example

### 1. England Server (Wireguard Server)

```bash
# Start the VX-SSH server
./vx-server -ssh-user tunneluser -ssh-password SecurePass123 -target 127.0.0.1:51820
```

### 2. Iran Server (Proxy)

```bash
# Start the VX-SSH client  
./vx-client -remote england-server.example.com:22 -ssh-user tunneluser -ssh-password SecurePass123 -local-port 51820
```

### 3. Wireguard Client Configuration

Point your Wireguard clients to the Iran server:

```ini
[Interface]
PrivateKey = YOUR_PRIVATE_KEY
Address = 10.0.0.2/24

[Peer]
PublicKey = SERVER_PUBLIC_KEY
Endpoint = iran-server.example.com:51820  # Iran server IP
AllowedIPs = 0.0.0.0/0
```

## Security Considerations

### SSH Authentication
- Use strong passwords or preferably SSH key authentication
- Consider changing the default SSH port
- Implement fail2ban or similar protection

### Network Security
- Ensure proper firewall rules are in place
- Monitor connections and logs regularly
- Use VPN or secure networks when possible

### Production Deployment
- Use systemd services for automatic startup
- Implement proper logging and monitoring
- Regular security updates

## Systemd Service Examples

### Server Service (England)

Create `/etc/systemd/system/vx-server.service`:

```ini
[Unit]
Description=VX-SSH Server
After=network.target

[Service]
Type=simple
User=vxuser
WorkingDirectory=/opt/vx-ssh
ExecStart=/opt/vx-ssh/vx-server -ssh-user tunneluser -ssh-password SecurePass123
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### Client Service (Iran)

Create `/etc/systemd/system/vx-client.service`:

```ini
[Unit]
Description=VX-SSH Client
After=network.target

[Service]
Type=simple
User=vxuser
WorkingDirectory=/opt/vx-ssh
ExecStart=/opt/vx-ssh/vx-client -remote england-server.com:22 -ssh-user tunneluser -ssh-password SecurePass123
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start services:
```bash
sudo systemctl enable vx-server.service
sudo systemctl start vx-server.service
sudo systemctl status vx-server.service
```

## Troubleshooting

### Common Issues

1. **Connection Refused**
   - Check if SSH server is running and accessible
   - Verify firewall rules and port accessibility
   - Confirm SSH credentials

2. **Permission Denied**
   - Verify SSH username and password
   - Check SSH server configuration
   - Ensure user has necessary permissions

3. **High Latency**
   - Check network connectivity between servers
   - Monitor CPU and memory usage
   - Consider increasing connection limits

4. **Packet Loss**
   - Verify UDP target is accessible
   - Check for network congestion
   - Monitor connection timeout settings

### Logs and Monitoring

The applications provide detailed logging. Monitor logs for:
- Connection establishment/termination
- Error messages and warnings
- Performance metrics
- Cleanup activities

### Performance Tuning

For high-traffic scenarios:
- Increase `-max-conns` parameter
- Adjust `-idle-timeout` based on usage patterns
- Monitor system resources (CPU, memory, network)
- Consider load balancing multiple instances

## Technical Details

### Protocol
- Uses SSH channels for data transmission
- Each UDP client gets a dedicated SSH channel
- Packets are prefixed with 4-byte length headers
- Automatic connection pooling and cleanup

### Performance Optimizations
- Concurrent packet processing with goroutines
- Connection reuse for multiple packets
- Efficient memory management
- Minimal protocol overhead

### Security Features
- All traffic encrypted through SSH
- Password-based authentication
- Connection timeout management
- Resource usage limits

## License

This project is released under the MIT License. See LICENSE file for details.

## Support

For issues, questions, or contributions, please check the documentation or contact the maintainers. 