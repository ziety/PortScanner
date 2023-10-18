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
	Host     string
	Port     int
	Type     string
	Status   string
	Banner   string
	Vulns    []string
	Exploit  string
	WebVulns []string
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
	continuous := getUserInput("Enable continuous scanning? (yes/no):")

	ips, err := net.LookupHost(target)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Printf("+++ Target: %s (IP Address: %s)\n", target, ips[0])
	fmt.Printf("+++ Port scanning started for %s (TCP ports 1-%d)...\n", target, portCount)

	for {
		results := scanPorts(target, portCount)
		printScanResults(results)

		if strings.ToLower(continuous) != "yes" {
			break
		}

		time.Sleep(5 * time.Minute) // Sleep for 5 minutes before the next scan
	}
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

		if len(result.Vulns) > 0 {
			fmt.Println("Vulnerabilities:")
			for _, vuln := range result.Vulns {
				fmt.Printf("- %s\n", vuln)
			}
		}

		if result.Exploit != "" {
			fmt.Println("Exploitation:")
			fmt.Printf("- %s\n", result.Exploit)
		}

		if len(result.WebVulns) > 0 {
			fmt.Println("Web Application Vulnerabilities:")
			for _, webVuln := range result.WebVulns {
				fmt.Printf("- %s\n", webVuln)
			}
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
	vulns := []string{}
	exploit := ""
	webVulns := []string{}

	if err == nil {
		portType = "TCP"
		status = "open"
		conn.SetReadDeadline(time.Now().Add(maxReadTimeout))
		n, err := conn.Read([]byte{})
		if err == nil {
			banner = fmt.Sprintf("Banner: %s", string([]byte{}[:n]))
		}
		conn.Close()

		if service, ok := vulnerabilities[port]; ok {
			vulns, exploit = checkForVulnerabilities(service, banner)
		}

		webVulns = checkWebApplicationVulnerabilities(fmt.Sprintf("http://%s:%d", host, port))
	}

	results <- ScanResult{
		Host:     host,
		Port:     port,
		Type:     portType,
		Status:   status,
		Banner:   banner,
		Vulns:    vulns,
		Exploit:  exploit,
		WebVulns: webVulns,
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
	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})
}

func checkForVulnerabilities(service, banner string) ([]string, string) {
	vulns := []string{}
	exploit := ""

	if service == "SSH" {
		if strings.Contains(banner, "OpenSSH") {
			vulns = append(vulns, "OpenSSH Vulnerability")
			exploit = "Exploitation for OpenSSH Vulnerability"
		}
	}

	return vulns, exploit
}

func checkWebApplicationVulnerabilities(url string) []string {
	webVulns := []string{}

	if checkXSSVulnerability(url) {
		webVulns = append(webVulns, "Cross-Site Scripting (XSS) Vulnerability")
	}

	return webVulns
}

func checkXSSVulnerability(url string) bool {
	return false
}

func checkSQLInjectionVulnerability(url string) bool {
	return false
}

func checkOtherWebVulnerability(url string) bool {
	return false
}
