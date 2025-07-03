#!/bin/bash

# VX-SSH Build Script

set -e

echo "Building VX-SSH components..."

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "Error: Go is not installed or not in PATH"
    echo "Please install Go 1.21 or later from https://golang.org"
    exit 1
fi

# Check Go version
GO_VERSION=$(go version | cut -d' ' -f3 | cut -d'o' -f2)
echo "Using Go version: $GO_VERSION"

# Create bin directory
mkdir -p bin

# Download dependencies
echo "Downloading dependencies..."
go mod tidy

# Build client
echo "Building VX-SSH Client..."
go build -ldflags="-s -w" -o bin/vx-client vx-client.go
if [ $? -eq 0 ]; then
    echo "✓ Client built successfully: bin/vx-client"
else
    echo "✗ Client build failed"
    exit 1
fi

# Build server
echo "Building VX-SSH Server..."
go build -ldflags="-s -w" -o bin/vx-server vx-server.go
if [ $? -eq 0 ]; then
    echo "✓ Server built successfully: bin/vx-server"
else
    echo "✗ Server build failed"
    exit 1
fi

# Cross-compile for Linux if on different platform
if [ "$(uname)" != "Linux" ]; then
    echo "Cross-compiling for Linux..."
    
    GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/vx-client-linux vx-client.go
    if [ $? -eq 0 ]; then
        echo "✓ Linux client built: bin/vx-client-linux"
    fi
    
    GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/vx-server-linux vx-server.go
    if [ $? -eq 0 ]; then
        echo "✓ Linux server built: bin/vx-server-linux"
    fi
fi

echo ""
echo "Build completed successfully!"
echo ""
echo "Usage:"
echo "  Server: ./bin/vx-server -ssh-user <user> -ssh-password <pass>"
echo "  Client: ./bin/vx-client -remote <host:port> -ssh-user <user> -ssh-password <pass>"
echo ""
echo "For detailed usage, run with -h flag or see README.md" 