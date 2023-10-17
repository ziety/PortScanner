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

const (
	maxDialTimeout   = 2 * time.Second
	maxReadTimeout   = 2 * time.Second
	defaultPortRange = 1000
)

type ScanResult struct {
	Host   string
	Port   int
	Type   string
	Status string
	Banner string
}

var vulnerabilities = map[int]string{
	22:   "SSH",
	80:   "HTTP",
	443:  "HTTPS",
	3306: "MySQL",
	// Add more ports and descriptions as needed
}

func main() {
	target := getUserInput("Enter URL or IP to scan: ")
	portCount := getUserInputInt("Enter the number of ports to scan (e.g., 1000):")

	ips, err := net.LookupHost(target)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Printf("+++ Target: %s (IP Address: %s)\n", target, ips[0])
	fmt.Printf("+++ Port scanning started for %s (TCP ports 1-%d)...\n", target, portCount)

	results := scanPorts(target, portCount)
	printScanResults(results)
}

func scanPorts(target string, portCount int) []ScanResult {
	results := make(chan ScanResult)
	var openPorts []ScanResult
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

	return openPorts
}

func printScanResults(openPorts []ScanResult) {
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
		color.Green(openPortText)
		if result.Banner != "" {
			fmt.Println(result.Banner)
		}

		if service, ok := vulnerabilities[result.Port]; ok {
			fmt.Printf("Known Service: %s\n", service)
		}
	}
}

func scanPort(host string, port int, results chan ScanResult, wg *sync.WaitGroup) {
	defer wg.Done()
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, maxDialTimeout)

	portType := "TCP"
	status := "closed"
	banner := ""

	if err == nil {
		portType = "TCP"
		status = "open"
		conn.SetReadDeadline(time.Now().Add(maxReadTimeout))
		n, err := conn.Read([]byte{})
		if err == nil {
			banner = fmt.Sprintf("Banner: %s", string([]byte{}[:n]))
		}
		conn.Close()
	}

	results <- ScanResult{Host: host, Port: port, Type: portType, Status: status, Banner: banner}
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
	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})
}
