.PHONY: all clean client server linux windows

# Default target
all: client server

# Create bin directory
bin:
	mkdir -p bin

# Build client
client: bin
	go build -ldflags="-s -w" -o bin/vx-client vx-client.go

# Build server  
server: bin
	go build -ldflags="-s -w" -o bin/vx-server vx-server.go

# Build for Linux
linux: bin
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/vx-client-linux vx-client.go
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/vx-server-linux vx-server.go

# Build for Windows
windows: bin
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o bin/vx-client.exe vx-client.go
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o bin/vx-server.exe vx-server.go

# Clean build artifacts
clean:
	rm -rf bin/

# Download dependencies
deps:
	go mod tidy

# Run tests (basic compile test)
test: deps
	go build -o /tmp/vx-client-test vx-client.go
	go build -o /tmp/vx-server-test vx-server.go
	rm -f /tmp/vx-client-test /tmp/vx-server-test
	@echo "Build tests passed"

# Install binaries to system
install: all
	sudo cp bin/vx-client /usr/local/bin/
	sudo cp bin/vx-server /usr/local/bin/
	@echo "Installed to /usr/local/bin/" 