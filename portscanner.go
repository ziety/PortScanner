package main

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

type ScanResult struct {
	Host   string
	Port   int
	Type   string
	Status string
	Banner string // Banner grabbing result
}

func scanPort(host string, port int, results chan ScanResult, wg *sync.WaitGroup) {
	defer wg.Done()
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)

	portType := "TCP"
	status := "closed"
	banner := ""

	if err == nil {
		portType = "TCP"
		status = "open"
		// Attempt banner grabbing
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read([]byte{})
		if err == nil {
			banner = fmt.Sprintf("Banner: %s", string([]byte{}[:n]))
		}
		conn.Close()
	}

	results <- ScanResult{Host: host, Port: port, Type: portType, Status: status, Banner: banner}
}

func main() {
	results := make(chan ScanResult)
	var openPorts []ScanResult

	target := getUserInput("Enter URL or IP to scan: ")
	portCount := getUserInputInt("Enter the number of ports to scan (e.g., 1000):")

	fmt.Printf("+++ Port scanning started for %s (TCP ports 1-%d)...\n", target, portCount)

	var wg sync.WaitGroup

	for port := 1; port <= portCount; port++ {
		wg.Add(1)
		go scanPort(target, port, results, &wg)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for result := range results {
		if result.Status == "open" {
			openPorts = append(openPorts, result)
		}
	}

	fmt.Println("+++ Scanning has been done!")
	fmt.Println("+++ Open Ports -->")

	sortScanResults(openPorts)

	currentHost := ""
	for _, result := range openPorts {
		if result.Host != currentHost {
			if currentHost != "" {
				fmt.Println()
			}
			fmt.Printf("Open Ports for %s:\n", result.Host)
			currentHost = result.Host
		}
		openPortText := fmt.Sprintf("Port number %d is open (%s)", result.Port, result.Type)
		color.Green(openPortText) // Display open ports in green
		if result.Banner != "" {
			fmt.Println(result.Banner)
		}
	}
}

func getUserInput(prompt string) string {
	fmt.Print(prompt)
	var userInput string
	fmt.Scanln(&userInput)
	return strings.TrimSpace(userInput)
}

func getUserInputInt(prompt string) int {
	fmt.Print(prompt)
	var userInput int
	fmt.Scanln(&userInput)
	return userInput
}

func sortScanResults(results []ScanResult) {
	// Sort openPorts in ascending order.
	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})
}
