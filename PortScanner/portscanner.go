package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// scanPort scans a specific port on a given host and sends open port numbers to the results channel.
func scanPort(hostname string, port int, results chan int, wg *sync.WaitGroup) {
	defer wg.Done() // Notify the WaitGroup that this Goroutine has completed.
	address := fmt.Sprintf("%s:%d", hostname, port)
	_, err := net.DialTimeout("tcp", address, 2) // Use DialTimeout to limit connection time.
	if err == nil {
		results <- port // Send open port number to the results channel.
	}
}

func main() {
	results := make(chan int)
	var openPorts []int

	hostname := getUserInput("Hostname to scan (example.com): ")
	portRange := getUserInput("Port range to scan (e.g., 1-1024): ")
	startPort, endPort := parsePortRange(portRange)

	fmt.Printf("+++ Port scanning started for %s from port %d to %d ...\n", hostname, startPort, endPort)

	var wg sync.WaitGroup // WaitGroup to keep track of active Goroutines.

	for port := startPort; port <= endPort; port++ {
		wg.Add(1) // Increment the WaitGroup counter for each Goroutine.
		go scanPort(hostname, port, results, &wg)
	}

	go func() {
		wg.Wait()      // Wait for all Goroutines to complete.
		close(results) // Close the results channel when all scanning is done.
	}()

	for openPort := range results {
		openPorts = append(openPorts, openPort)
	}

	sort.Ints(openPorts)

	fmt.Println("+++ Scanning has been done!")
	fmt.Println("+++ Results -->\n")

	for _, port := range openPorts {
		fmt.Printf("Port number %d is open\n", port)
	}
}

// getUserInput prompts the user for input and returns the trimmed result.
func getUserInput(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	userInput, _ := reader.ReadString('\n')
	return strings.TrimSpace(userInput)
}

// parsePortRange takes a port range string and returns the start and end ports.
func parsePortRange(portRange string) (int, int) {
	parts := strings.Split(portRange, "-")
	if len(parts) == 2 {
		startPort, _ := strconv.Atoi(parts[0])
		endPort, _ := strconv.Atoi(parts[1])
		return startPort, endPort
	}
	return 1, 65535 // Default to scanning all ports if input is invalid.
}
