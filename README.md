# PortScanner 

PortScanner is a simple and efficient command-line tool for scanning open ports on a target host. Written in Go, it allows you to quickly identify open ports, making it a valuable asset for network administrators, security professionals, and developers.

## Features

- Fast and concurrent port scanning.
- User-friendly command-line interface.
- Customizable port range to scan.
- Efficient handling of open ports.

## Getting Started

### Prerequisites

Before using PortScanner, ensure that you have Go installed on your system.

### Installation

You can build and install PortScanner using the following steps:

```bash
go get github.com/ziety/PortScanner
go install github.com/ziety/PortScanner
```

## Usage
To scan open ports on a target host, use the following command:

```bash
go run portscanner.go
URL: example.com
IP: 192.168.1.1 
ports: 1-1000
```

Replace 'example.com' with the target URL / Replace '192.168.1.1' with the target IP.


Adjust the port range as needed.


## Results
After scanning is complete, PortScanner will provide a list of open ports on the specified URL or IP.
