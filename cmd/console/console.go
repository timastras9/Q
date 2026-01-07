package console

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"q/internal/ai"
	"q/internal/exploit"
	"q/internal/recon"
	"q/internal/remediation"
	"q/internal/util"
	"q/internal/webapp"
)

const (
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorReset   = "\033[0m"
	colorBold    = "\033[1m"
)

type Console struct {
	framework     *exploit.Framework
	scanner       *recon.Scanner
	webScanner    *webapp.WebScanner
	ai            *ai.ClaudeClient
	vulnLookup    *exploit.VulnLookupService
	currentModule exploit.Exploit
	workspace     string
	history       []string
	running       bool
	lastScanState *ai.PentestState  // Store last autopwn state for reporting
	lastReport    *ai.PentestReport // Store last autopwn report
}

func NewConsole() *Console {
	// Get NVD API key from environment
	nvdAPIKey := os.Getenv("NVD_API_KEY")

	return &Console{
		framework:  exploit.NewFramework(),
		scanner:    recon.NewScanner(),
		webScanner: webapp.NewWebScanner(),
		vulnLookup: exploit.NewVulnLookupService(nvdAPIKey),
		workspace:  "default",
		running:    true,
	}
}

func (c *Console) Run() {
	c.printBanner()

	// Initialize AI if API key is set
	aiClient, err := ai.NewClaudeClient()
	if err == nil {
		c.ai = aiClient
		fmt.Printf("%s[*]%s AI assistant enabled (Claude)\n", colorBlue, colorReset)
	} else {
		fmt.Printf("%s[!]%s AI assistant disabled: %v\n", colorYellow, colorReset, err)
	}

	// Handle Ctrl+C
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT)
	go func() {
		for range sigChan {
			fmt.Println("\nUse 'exit' or 'quit' to leave")
		}
	}()

	reader := bufio.NewReader(os.Stdin)

	for c.running {
		prompt := c.getPrompt()
		fmt.Print(prompt)

		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		c.history = append(c.history, line)
		c.execute(line)
	}
}

func (c *Console) printBanner() {
	banner := `
    ____            __            __  ___    ____
   / __ \___  ____  / /____  _____/ /_/   |  /  _/
  / /_/ / _ \/ __ \/ __/ _ \/ ___/ __/ /| |  / /
 / ____/  __/ / / / /_/  __(__  ) /_/ ___ |_/ /
/_/    \___/_/ /_/\__/\___/____/\__/_/  |_/___/

        AI-Powered Penetration Testing Framework
                    Version 1.0.0

`
	fmt.Print(colorCyan + banner + colorReset)

	modules := c.framework.List()
	fmt.Printf("       %d exploit/auxiliary modules loaded\n\n", len(modules))
}

func (c *Console) getPrompt() string {
	if c.currentModule != nil {
		info := c.currentModule.Info()
		return fmt.Sprintf("%sq%s %s(%s%s%s)%s > ",
			colorBold+colorRed, colorReset,
			colorReset, colorRed, info.Name, colorReset, colorReset)
	}
	return fmt.Sprintf("%sq%s > ", colorBold+colorRed, colorReset)
}

func (c *Console) execute(line string) {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return
	}

	cmd := strings.ToLower(parts[0])
	args := parts[1:]

	switch cmd {
	case "help", "?":
		c.cmdHelp(args)
	case "exit", "quit":
		c.running = false
	case "use":
		c.cmdUse(args)
	case "back":
		c.currentModule = nil
	case "show":
		c.cmdShow(args)
	case "set":
		c.cmdSet(args)
	case "unset":
		c.cmdUnset(args)
	case "run", "exploit":
		c.cmdRun(args)
	case "check":
		c.cmdCheck(args)
	case "search":
		c.cmdSearch(args)
	case "info":
		c.cmdInfo(args)
	case "options":
		c.cmdOptions(args)
	case "sessions":
		c.cmdSessions(args)
	case "scan":
		c.cmdScan(args)
	case "webscan":
		c.cmdWebScan(args)
	case "sslsniff":
		c.cmdSSLSniff(args)
	case "ai":
		c.cmdAI(args)
	case "analyze":
		c.cmdAnalyze(args)
	case "autopwn", "auto":
		c.cmdAutoPwn(args)
	case "autopwn-agents", "agents":
		c.cmdAutoPwnAgents(args)
	case "train":
		c.cmdTrain(args)
	case "history":
		c.cmdHistory(args)
	case "report":
		c.cmdReport(args)
	case "autofix", "fix":
		c.cmdAutoFix(args)
	case "clear":
		fmt.Print("\033[H\033[2J")
	case "banner":
		c.printBanner()
	default:
		fmt.Printf("%s[-]%s Unknown command: %s. Type 'help' for available commands.\n",
			colorRed, colorReset, cmd)
	}
}

func (c *Console) cmdHelp(args []string) {
	help := `
Core Commands
=============
    help                    Show this help
    exit, quit              Exit the console
    clear                   Clear the screen
    history                 Show command history

Module Commands
===============
    use <module>            Select a module
    back                    Deselect current module
    show modules            List all modules
    show options            Show current module options
    search <pattern>        Search for modules
    info                    Show module information

Exploit Commands
================
    set <option> <value>    Set an option value
    unset <option>          Clear an option value
    options                 Show current options
    check                   Check if target is vulnerable
    run, exploit            Execute the current module

Session Commands
================
    sessions                List active sessions
    sessions -i <id>        Interact with a session
    sessions -k <id>        Kill a session

Scanning Commands
=================
    scan <target>           Run port scan on target
    scan -sV <target>       Scan with service detection
    scan -p <ports> <host>  Scan specific ports
    webscan <url>           Run web vulnerability scan
    sslsniff <target>       Intercept SSL/TLS traffic

AI Commands
===========
    ai <question>           Ask the AI assistant
    analyze                 AI analyzes current scan/module data
    autopwn <target>        Autonomous AI-driven pentest
    auto <target>           Alias for autopwn

Remediation Commands
====================
    autofix <scan.json>     Generate fixes for vulnerabilities
    autofix --safe <file>   Auto-apply safe fixes (headers, configs)
    autofix --review <file> Generate all patches for human review
    fix <scan.json>         Alias for autofix

Examples
========
    use auxiliary/scanner/ssh/ssh_login
    set RHOSTS 192.168.1.1
    set USERNAME root
    set PASS_FILE /usr/share/wordlists/passwords.txt
    run

    scan 192.168.1.0/24
    webscan http://target.com
`
	fmt.Println(help)
}

func (c *Console) cmdUse(args []string) {
	if len(args) == 0 {
		fmt.Printf("%s[-]%s Usage: use <module_path>\n", colorRed, colorReset)
		return
	}

	modulePath := args[0]
	if err := c.framework.Use(modulePath); err != nil {
		fmt.Printf("%s[-]%s %v\n", colorRed, colorReset, err)
		return
	}

	c.currentModule = c.framework.Current()
	info := c.currentModule.Info()
	fmt.Printf("%s[*]%s Using %s\n", colorBlue, colorReset, info.Name)
}

func (c *Console) cmdShow(args []string) {
	if len(args) == 0 {
		fmt.Printf("%s[-]%s Usage: show [modules|options|sessions]\n", colorRed, colorReset)
		return
	}

	switch args[0] {
	case "modules":
		modules := c.framework.List()
		sort.Strings(modules)

		fmt.Printf("\n%sModules%s\n", colorBold, colorReset)
		fmt.Println(strings.Repeat("=", 70))

		currentType := ""
		for _, path := range modules {
			parts := strings.Split(path, "/")
			modType := parts[0]
			if modType != currentType {
				fmt.Printf("\n%s%s%s\n", colorCyan, strings.Title(modType), colorReset)
				currentType = modType
			}
			fmt.Printf("  %s\n", path)
		}
		fmt.Println()

	case "options":
		c.cmdOptions(nil)

	case "sessions":
		c.cmdSessions(nil)

	default:
		fmt.Printf("%s[-]%s Unknown show type: %s\n", colorRed, colorReset, args[0])
	}
}

func (c *Console) cmdSet(args []string) {
	if len(args) < 2 {
		fmt.Printf("%s[-]%s Usage: set <option> <value>\n", colorRed, colorReset)
		return
	}

	if c.currentModule == nil {
		fmt.Printf("%s[-]%s No module selected\n", colorRed, colorReset)
		return
	}

	option := strings.ToUpper(args[0])
	value := strings.Join(args[1:], " ")

	if err := c.currentModule.SetOption(option, value); err != nil {
		fmt.Printf("%s[-]%s %v\n", colorRed, colorReset, err)
		return
	}

	fmt.Printf("%s[*]%s %s => %s\n", colorBlue, colorReset, option, value)
}

func (c *Console) cmdUnset(args []string) {
	if len(args) == 0 {
		fmt.Printf("%s[-]%s Usage: unset <option>\n", colorRed, colorReset)
		return
	}

	if c.currentModule == nil {
		fmt.Printf("%s[-]%s No module selected\n", colorRed, colorReset)
		return
	}

	option := strings.ToUpper(args[0])
	if err := c.currentModule.SetOption(option, ""); err != nil {
		fmt.Printf("%s[-]%s %v\n", colorRed, colorReset, err)
		return
	}

	fmt.Printf("%s[*]%s Unset %s\n", colorBlue, colorReset, option)
}

func (c *Console) cmdOptions(args []string) {
	if c.currentModule == nil {
		fmt.Printf("%s[-]%s No module selected\n", colorRed, colorReset)
		return
	}

	options := c.currentModule.Options()
	info := c.currentModule.Info()

	fmt.Printf("\nModule options (%s):\n\n", info.Name)
	fmt.Printf("   %-15s  %-20s  %-8s  %s\n", "Name", "Current Setting", "Required", "Description")
	fmt.Printf("   %-15s  %-20s  %-8s  %s\n",
		strings.Repeat("-", 15), strings.Repeat("-", 20),
		strings.Repeat("-", 8), strings.Repeat("-", 30))

	for _, opt := range options {
		required := "no"
		if opt.Required {
			required = "yes"
		}
		value := opt.Value
		if len(value) > 20 {
			value = value[:17] + "..."
		}
		fmt.Printf("   %-15s  %-20s  %-8s  %s\n", opt.Name, value, required, opt.Description)
	}
	fmt.Println()
}

func (c *Console) cmdRun(args []string) {
	if c.currentModule == nil {
		fmt.Printf("%s[-]%s No module selected\n", colorRed, colorReset)
		return
	}

	info := c.currentModule.Info()
	fmt.Printf("%s[*]%s Running %s...\n", colorBlue, colorReset, info.Name)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	result, err := c.currentModule.Run(ctx)
	if err != nil {
		fmt.Printf("%s[-]%s Error: %v\n", colorRed, colorReset, err)
		return
	}

	// Display results
	if result.Success {
		fmt.Printf("%s[+]%s Module completed successfully\n", colorGreen, colorReset)
	} else {
		fmt.Printf("%s[-]%s Module completed without success\n", colorYellow, colorReset)
	}

	if result.Output != "" {
		fmt.Printf("\n%s\n", result.Output)
	}

	if len(result.Credentials) > 0 {
		fmt.Printf("\n%s[+]%s Credentials found:\n", colorGreen, colorReset)
		for _, cred := range result.Credentials {
			// Sanitize password for display - show service, username, and masked password
			fmt.Printf("    %s @ %s - %s:%s\n", cred.Source, cred.Type, cred.Username, util.SanitizePassword(cred.Password))
		}
	}

	fmt.Printf("\n%s[*]%s Execution time: %v\n", colorBlue, colorReset,
		result.EndTime.Sub(result.StartTime).Round(time.Millisecond))
}

func (c *Console) cmdCheck(args []string) {
	if c.currentModule == nil {
		fmt.Printf("%s[-]%s No module selected\n", colorRed, colorReset)
		return
	}

	fmt.Printf("%s[*]%s Checking target vulnerability...\n", colorBlue, colorReset)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	vulnerable, err := c.currentModule.Check(ctx)
	if err != nil {
		fmt.Printf("%s[-]%s Check failed: %v\n", colorRed, colorReset, err)
		return
	}

	if vulnerable {
		fmt.Printf("%s[+]%s Target appears to be VULNERABLE\n", colorGreen, colorReset)
	} else {
		fmt.Printf("%s[-]%s Target does not appear to be vulnerable\n", colorYellow, colorReset)
	}
}

func (c *Console) cmdSearch(args []string) {
	if len(args) == 0 {
		fmt.Printf("%s[-]%s Usage: search <pattern>\n", colorRed, colorReset)
		return
	}

	pattern := strings.Join(args, " ")
	matches := c.framework.Search(pattern)

	if len(matches) == 0 {
		fmt.Printf("%s[-]%s No modules found matching '%s'\n", colorYellow, colorReset, pattern)
		return
	}

	fmt.Printf("\n%sMatching Modules%s\n", colorBold, colorReset)
	fmt.Println(strings.Repeat("=", 50))

	for _, path := range matches {
		fmt.Printf("  %s\n", path)
	}
	fmt.Println()
}

func (c *Console) cmdInfo(args []string) {
	if c.currentModule == nil {
		fmt.Printf("%s[-]%s No module selected\n", colorRed, colorReset)
		return
	}

	info := c.currentModule.Info()

	fmt.Printf("\n%sModule Information%s\n", colorBold, colorReset)
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("       Name: %s\n", info.Name)
	fmt.Printf("Description: %s\n", info.Description)
	fmt.Printf("     Author: %s\n", info.Author)
	fmt.Printf("   Platform: %s\n", info.Platform)
	fmt.Printf("       Type: %s\n", info.Type)
	fmt.Printf("   Severity: %s%s%s\n", severityColor(info.Severity), info.Severity, colorReset)

	if len(info.CVE) > 0 {
		fmt.Printf("        CVE: %s\n", strings.Join(info.CVE, ", "))
	}
	if len(info.References) > 0 {
		fmt.Printf(" References:\n")
		for _, ref := range info.References {
			fmt.Printf("             %s\n", ref)
		}
	}
	fmt.Println()
}

func (c *Console) cmdSessions(args []string) {
	sessions := c.framework.Sessions()

	if len(sessions) == 0 {
		fmt.Printf("%s[*]%s No active sessions\n", colorBlue, colorReset)
		return
	}

	fmt.Printf("\n%sActive Sessions%s\n", colorBold, colorReset)
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("  %-5s  %-15s  %-10s  %-20s  %s\n", "ID", "Type", "Target", "Platform", "Created")
	fmt.Printf("  %-5s  %-15s  %-10s  %-20s  %s\n",
		strings.Repeat("-", 5), strings.Repeat("-", 15),
		strings.Repeat("-", 10), strings.Repeat("-", 20), strings.Repeat("-", 20))

	for _, session := range sessions {
		fmt.Printf("  %-5s  %-15s  %-10s  %-20s  %s\n",
			session.ID, session.Type, session.Target,
			session.Platform, session.CreatedAt.Format("2006-01-02 15:04:05"))
	}
	fmt.Println()
}

func (c *Console) cmdScan(args []string) {
	if len(args) == 0 {
		fmt.Printf("%s[-]%s Usage: scan [options] <target>\n", colorRed, colorReset)
		fmt.Println("  -p <ports>   Specify ports (e.g., 22,80,443 or 1-1000)")
		fmt.Println("  -sV          Enable service version detection")
		fmt.Println("  --top <n>    Scan top N ports")
		return
	}

	var target string
	var ports []int
	serviceDetect := false
	topN := 0

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-p":
			if i+1 < len(args) {
				ports = parsePorts(args[i+1])
				i++
			}
		case "-sV":
			serviceDetect = true
		case "--top":
			if i+1 < len(args) {
				topN, _ = strconv.Atoi(args[i+1])
				i++
			}
		default:
			target = args[i]
		}
	}

	if target == "" {
		fmt.Printf("%s[-]%s No target specified\n", colorRed, colorReset)
		return
	}

	if len(ports) == 0 {
		if topN > 0 {
			ports = recon.TopPorts(topN)
		} else {
			ports = recon.DefaultPorts()
		}
	}

	fmt.Printf("%s[*]%s Scanning %s (%d ports)...\n", colorBlue, colorReset, target, len(ports))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	opts := recon.ScanOptions{
		Ports:       ports,
		ServiceScan: serviceDetect,
		BannerGrab:  serviceDetect,
	}

	host, err := c.scanner.ScanHost(ctx, target, opts)
	if err != nil {
		fmt.Printf("%s[-]%s Scan failed: %v\n", colorRed, colorReset, err)
		return
	}

	if host.State != "up" {
		fmt.Printf("%s[-]%s Host appears to be down\n", colorYellow, colorReset)
		return
	}

	fmt.Printf("\n%s[+]%s Host is up\n", colorGreen, colorReset)

	if len(host.Ports) > 0 {
		fmt.Printf("\n%sPORT        STATE   SERVICE         VERSION%s\n", colorBold, colorReset)
		for _, port := range host.Ports {
			version := ""
			if port.Service.Product != "" {
				version = port.Service.Product
				if port.Service.Version != "" {
					version += " " + port.Service.Version
				}
			}
			fmt.Printf("%-11s %-7s %-15s %s\n",
				fmt.Sprintf("%d/%s", port.Number, port.Protocol),
				port.State,
				port.Service.Name,
				version)
		}
	}
	fmt.Println()
}

func (c *Console) cmdWebScan(args []string) {
	if len(args) == 0 {
		fmt.Printf("%s[-]%s Usage: webscan <url>\n", colorRed, colorReset)
		return
	}

	targetURL := args[0]
	if !strings.HasPrefix(targetURL, "http") {
		targetURL = "http://" + targetURL
	}

	fmt.Printf("%s[*]%s Scanning %s...\n", colorBlue, colorReset, targetURL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	result, err := c.webScanner.Scan(ctx, targetURL)
	if err != nil {
		fmt.Printf("%s[-]%s Scan failed: %v\n", colorRed, colorReset, err)
		return
	}

	fmt.Print(result.FormatResult())
}

func (c *Console) cmdSSLSniff(args []string) {
	if len(args) == 0 {
		fmt.Printf("%s[-]%s Usage: sslsniff <target> [options]\n", colorRed, colorReset)
		fmt.Println("  Options:")
		fmt.Println("    -p <port>           Target port (default: 443)")
		fmt.Println("    -d <duration>       Capture duration in seconds (default: 30)")
		fmt.Println("    -o <file>           Output keylog file for Wireshark")
		fmt.Println("    --sni <name>        Server Name Indication (SNI) for TLS")
		fmt.Println("    --detect-sensitive  Scan for PII, credentials, API keys")
		fmt.Println()
		fmt.Println("  Examples:")
		fmt.Println("    sslsniff example.com")
		fmt.Println("    sslsniff 192.168.1.1 -p 8443")
		fmt.Println("    sslsniff example.com --sni www.example.com")
		fmt.Println("    sslsniff example.com --detect-sensitive")
		fmt.Println("    sslsniff example.com -d 60 -o /tmp/sslkeys.log --detect-sensitive")
		return
	}

	target := args[0]
	port := 443
	duration := 30
	outputFile := ""
	sni := ""
	detectSensitive := false

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "-p":
			if i+1 < len(args) {
				port, _ = strconv.Atoi(args[i+1])
				i++
			}
		case "-d":
			if i+1 < len(args) {
				duration, _ = strconv.Atoi(args[i+1])
				i++
			}
		case "-o":
			if i+1 < len(args) {
				outputFile = args[i+1]
				i++
			}
		case "--sni":
			if i+1 < len(args) {
				sni = args[i+1]
				i++
			}
		case "--detect-sensitive", "-s":
			detectSensitive = true
		}
	}

	// If no SNI specified, use target as SNI (for proper TLS handshake)
	if sni == "" {
		sni = target
	}

	fmt.Printf("\n%s%s╔══════════════════════════════════════════════════════════════╗%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s║                  SSL/TLS TRAFFIC SNIFFER                      ║%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s╚══════════════════════════════════════════════════════════════╝%s\n\n", colorBold, colorCyan, colorReset)

	fmt.Printf("%s[*]%s Target: %s:%d\n", colorBlue, colorReset, target, port)
	fmt.Printf("%s[*]%s SNI: %s\n", colorBlue, colorReset, sni)
	fmt.Printf("%s[*]%s Duration: %d seconds\n", colorBlue, colorReset, duration)
	if outputFile != "" {
		fmt.Printf("%s[*]%s Keylog file: %s\n", colorBlue, colorReset, outputFile)
	}
	if detectSensitive {
		fmt.Printf("%s[*]%s Sensitive data detection: %sENABLED%s\n", colorBlue, colorReset, colorGreen, colorReset)
	}
	fmt.Println()

	// Use the SSL interceptor module
	if err := c.framework.Use("auxiliary/sniffer/ssl_interceptor"); err != nil {
		// Try the other registered name
		if err := c.framework.Use("auxiliary/scanner/ssl/ssl_sniffer"); err != nil {
			fmt.Printf("%s[-]%s SSL sniffer module not available: %v\n", colorRed, colorReset, err)
			return
		}
	}

	module := c.framework.Current()
	module.SetOption("RHOSTS", target)
	module.SetOption("RPORT", strconv.Itoa(port))
	module.SetOption("DURATION", strconv.Itoa(duration))
	module.SetOption("SNI", sni)
	if outputFile != "" {
		module.SetOption("KEYLOG_FILE", outputFile)
	}
	if detectSensitive {
		module.SetOption("DETECT_SENSITIVE", "true")
	}

	fmt.Printf("%s[*]%s Starting SSL interception...\n", colorBlue, colorReset)
	fmt.Printf("%s[*]%s Press Ctrl+C to stop early\n\n", colorBlue, colorReset)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration+10)*time.Second)
	defer cancel()

	// Handle interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT)
	go func() {
		<-sigChan
		fmt.Printf("\n%s[!]%s Stopping capture...\n", colorYellow, colorReset)
		cancel()
	}()

	result, err := module.Run(ctx)
	if err != nil {
		fmt.Printf("%s[-]%s SSL interception failed: %v\n", colorRed, colorReset, err)
		return
	}

	// Display results
	fmt.Printf("\n%s%s═══════════════════ RESULTS ═══════════════════%s\n", colorBold, colorCyan, colorReset)

	if result.Success {
		fmt.Printf("%s[+]%s SSL traffic captured successfully\n", colorGreen, colorReset)
	} else {
		fmt.Printf("%s[-]%s Capture completed (no traffic intercepted)\n", colorYellow, colorReset)
	}

	if result.Output != "" {
		// Truncate if too long for display
		output := result.Output
		if len(output) > 5000 {
			output = output[:5000] + "\n\n... [truncated - full output in keylog file] ..."
		}
		fmt.Printf("\n%sDecrypted Traffic:%s\n", colorBold, colorReset)
		fmt.Println(output)
	}

	// Show keylog file location
	if outputFile != "" {
		fmt.Printf("\n%s[*]%s TLS session keys saved to: %s\n", colorBlue, colorReset, outputFile)
		fmt.Printf("%s[*]%s To decrypt in Wireshark:\n", colorBlue, colorReset)
		fmt.Println("     1. Edit > Preferences > Protocols > TLS")
		fmt.Println("     2. Set (Pre)-Master-Secret log filename to:", outputFile)
		fmt.Println("     3. Load your PCAP capture file")
	}

	fmt.Println()
}

func (c *Console) cmdAI(args []string) {
	if c.ai == nil {
		fmt.Printf("%s[-]%s AI assistant not available. Set ANTHROPIC_API_KEY.\n", colorRed, colorReset)
		return
	}

	if len(args) == 0 {
		fmt.Printf("%s[-]%s Usage: ai <question>\n", colorRed, colorReset)
		return
	}

	question := strings.Join(args, " ")
	fmt.Printf("%s[*]%s Asking AI...\n", colorBlue, colorReset)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	messages := []ai.Message{
		{Role: "user", Content: question},
	}

	response, err := c.ai.Chat(ctx, messages)
	if err != nil {
		fmt.Printf("%s[-]%s AI error: %v\n", colorRed, colorReset, err)
		return
	}

	fmt.Printf("\n%s%sAI Response:%s\n", colorBold, colorCyan, colorReset)
	fmt.Println(response)
	fmt.Println()
}

func (c *Console) cmdAnalyze(args []string) {
	if c.ai == nil {
		fmt.Printf("%s[-]%s AI assistant not available. Set ANTHROPIC_API_KEY.\n", colorRed, colorReset)
		return
	}

	if c.currentModule == nil {
		fmt.Printf("%s[-]%s No module selected for analysis\n", colorRed, colorReset)
		return
	}

	info := c.currentModule.Info()
	options := c.currentModule.Options()

	var optData strings.Builder
	for _, opt := range options {
		if opt.Value != "" {
			optData.WriteString(fmt.Sprintf("%s: %s\n", opt.Name, opt.Value))
		}
	}

	data := fmt.Sprintf(`Module: %s
Type: %s
Severity: %s
CVEs: %s

Current Configuration:
%s

Please analyze this configuration and suggest the best approach to use this module effectively.`,
		info.Name, info.Type, info.Severity, strings.Join(info.CVE, ", "), optData.String())

	fmt.Printf("%s[*]%s Analyzing module configuration...\n", colorBlue, colorReset)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	decision, err := c.ai.Analyze(ctx, data)
	if err != nil {
		fmt.Printf("%s[-]%s Analysis failed: %v\n", colorRed, colorReset, err)
		return
	}

	fmt.Printf("\n%s%sAI Analysis:%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("Action: %s\n", decision.Action)
	fmt.Printf("Reasoning: %s\n", decision.Reasoning)
	if len(decision.NextSteps) > 0 {
		fmt.Println("Next Steps:")
		for _, step := range decision.NextSteps {
			fmt.Printf("  - %s\n", step)
		}
	}
	if decision.Remediation != "" {
		fmt.Printf("Remediation: %s\n", decision.Remediation)
	}
	fmt.Println()
}

func (c *Console) cmdHistory(args []string) {
	if len(c.history) == 0 {
		fmt.Printf("%s[*]%s No command history\n", colorBlue, colorReset)
		return
	}

	for i, cmd := range c.history {
		fmt.Printf("  %3d  %s\n", i+1, cmd)
	}
}

func (c *Console) cmdAutoPwn(args []string) {
	if c.ai == nil {
		fmt.Printf("%s[-]%s AI assistant not available. Set ANTHROPIC_API_KEY.\n", colorRed, colorReset)
		return
	}

	if len(args) == 0 {
		fmt.Printf("%s[-]%s Usage: autopwn <target> [--max-actions N]\n", colorRed, colorReset)
		fmt.Println("  Example: autopwn 192.168.1.1")
		fmt.Println("  Example: autopwn 192.168.1.0/24 --max-actions 30")
		return
	}

	target := args[0]
	maxActions := 100

	for i := 1; i < len(args); i++ {
		if args[i] == "--max-actions" && i+1 < len(args) {
			maxActions, _ = strconv.Atoi(args[i+1])
			i++
		}
	}

	fmt.Printf("\n%s%s╔══════════════════════════════════════════════════════════════╗%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s║          AUTONOMOUS PENETRATION TEST - AI MODE               ║%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s╚══════════════════════════════════════════════════════════════╝%s\n\n", colorBold, colorCyan, colorReset)

	fmt.Printf("%s[*]%s Target: %s\n", colorBlue, colorReset, target)
	fmt.Printf("%s[*]%s Max Actions: %d\n", colorBlue, colorReset, maxActions)
	fmt.Printf("%s[*]%s AI is now in control. Press Ctrl+C to abort.\n\n", colorBlue, colorReset)

	runner := ai.NewAutoRunner(c.ai)
	runner.SetMaxActions(maxActions)
	runner.SetCallbacks(ai.RunnerCallbacks{
		OnPhaseChange: func(phase string) {
			phaseNames := map[string]string{
				"reconnaissance":           "RECONNAISSANCE",
				"enumeration":              "ENUMERATION",
				"vulnerability_assessment": "VULNERABILITY ASSESSMENT",
				"exploitation":             "EXPLOITATION",
				"post_exploitation":        "POST-EXPLOITATION",
				"reporting":                "REPORTING",
			}
			name := phaseNames[phase]
			if name == "" {
				name = strings.ToUpper(phase)
			}
			fmt.Printf("\n%s%s[PHASE]%s %s\n", colorBold, colorMagenta, colorReset, name)
			fmt.Println(strings.Repeat("─", 50))
		},
		OnAIDecision: func(decision *ai.AIDecision) {
			fmt.Printf("%s[AI]%s Decision: %s%s%s on %s\n",
				colorCyan, colorReset, colorBold, decision.Action, colorReset, decision.Target)
			fmt.Printf("     Reasoning: %s\n", truncate(decision.Reasoning, 80))
			fmt.Printf("     Risk: %s\n", decision.RiskLevel)
		},
		OnActionStart: func(action string, target string) {
			fmt.Printf("%s[>]%s Executing: %s -> %s\n", colorYellow, colorReset, action, target)
		},
		OnActionEnd: func(action string, success bool, output string) {
			if success {
				fmt.Printf("%s[+]%s %s completed successfully\n", colorGreen, colorReset, action)
			} else {
				fmt.Printf("%s[-]%s %s failed\n", colorRed, colorReset, action)
			}
			if output != "" && len(output) < 500 {
				lines := strings.Split(output, "\n")
				for _, line := range lines {
					if line != "" {
						fmt.Printf("    %s\n", line)
					}
				}
			}
		},
		OnFinding: func(finding ai.Finding) {
			sevColor := colorBlue
			sevIcon := "ℹ"
			switch strings.ToLower(finding.Severity) {
			case "critical":
				sevColor = colorRed + colorBold
				sevIcon = "🔴"
			case "high":
				sevColor = colorRed
				sevIcon = "🟠"
			case "medium":
				sevColor = colorYellow
				sevIcon = "🟡"
			case "low":
				sevColor = colorCyan
				sevIcon = "🔵"
			}
			fmt.Printf("\n%s╔══ VULNERABILITY FOUND ══╗%s\n", sevColor, colorReset)
			fmt.Printf("%s[%s %s]%s %s\n", sevColor, sevIcon, strings.ToUpper(finding.Severity), colorReset, finding.Type)
			fmt.Printf("  %sTarget:%s  %s\n", colorBold, colorReset, finding.Target)
			fmt.Printf("  %sDesc:%s    %s\n", colorBold, colorReset, finding.Description)
			if finding.Evidence != "" {
				// Truncate evidence for terminal display
				evidence := finding.Evidence
				if len(evidence) > 200 {
					evidence = evidence[:200] + "..."
				}
				// Remove newlines for cleaner display
				evidence = strings.ReplaceAll(evidence, "\n", " ")
				fmt.Printf("  %sEvidence:%s %s\n", colorBold, colorReset, evidence)
			}
			fmt.Printf("%s╚═════════════════════════╝%s\n", sevColor, colorReset)
		},
		OnCredential: func(cred ai.CredentialFind) {
			fmt.Printf("%s[CRED]%s Found: %s%s:%s%s on %s (%s)\n",
				colorGreen+colorBold, colorReset,
				colorGreen, cred.Username, cred.Password, colorReset,
				cred.Target, cred.Service)
		},
		OnError: func(err error) {
			fmt.Printf("%s[ERR]%s %v\n", colorRed, colorReset, err)
		},
		OnComplete: func(report *ai.PentestReport) {
			fmt.Printf("\n%s%s╔══════════════════════════════════════════════════════════════╗%s\n", colorBold, colorGreen, colorReset)
			fmt.Printf("%s%s║                    PENTEST COMPLETE                          ║%s\n", colorBold, colorGreen, colorReset)
			fmt.Printf("%s%s╚══════════════════════════════════════════════════════════════╝%s\n\n", colorBold, colorGreen, colorReset)

			fmt.Printf("%sExecutive Summary:%s\n", colorBold, colorReset)
			fmt.Println(report.ExecutiveSummary)
			fmt.Println()

			fmt.Printf("%sRisk Rating: %s%s%s\n\n", colorBold, getRiskColor(report.RiskRating), report.RiskRating, colorReset)

			fmt.Printf("%sFindings Summary:%s\n", colorBold, colorReset)
			for sev, count := range report.FindingsSummary {
				if count > 0 {
					fmt.Printf("  %s: %d\n", sev, count)
				}
			}
			fmt.Println()

			if len(report.CredentialsFound) > 0 {
				fmt.Printf("%sCredentials Discovered:%s\n", colorBold, colorReset)
				for _, cred := range report.CredentialsFound {
					// Sanitize password for display
					fmt.Printf("  %s @ %s (%s) - %s\n", cred.Username, cred.Target, cred.Service, util.SanitizePassword(cred.Password))
				}
				fmt.Println()
			}

			if len(report.Recommendations) > 0 {
				fmt.Printf("%sRecommendations:%s\n", colorBold, colorReset)
				for i, rec := range report.Recommendations {
					fmt.Printf("  %d. %s\n", i+1, rec)
				}
				fmt.Println()
			}

			// Show API usage and cost
			inputTok, outputTok, requests, cost := c.ai.GetUsageStats()
			fmt.Printf("%sAPI Usage:%s\n", colorBold, colorReset)
			fmt.Printf("  Requests: %d\n", requests)
			fmt.Printf("  Input tokens: %d\n", inputTok)
			fmt.Printf("  Output tokens: %d\n", outputTok)
			fmt.Printf("  %sEstimated cost: $%.4f%s\n\n", colorGreen, cost, colorReset)
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// Handle interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT)
	go func() {
		<-sigChan
		fmt.Printf("\n%s[!]%s Aborting autonomous mode...\n", colorYellow, colorReset)
		runner.Stop()
		cancel()
	}()

	state, err := runner.Run(ctx, target, []string{target})
	if err != nil {
		fmt.Printf("%s[-]%s Autopwn error: %v\n", colorRed, colorReset, err)
	}

	// Store state for report generation
	if state != nil {
		c.lastScanState = state
	}
	c.lastReport = runner.GetReport()

	// Auto-save JSON for PDF generation
	if c.lastScanState != nil {
		// Ensure output directory exists
		os.MkdirAll("output/scans", 0755)
		jsonFile := fmt.Sprintf("output/scans/pentest_%s_%s.json", strings.ReplaceAll(target, ".", "_"), time.Now().Format("20060102_150405"))
		c.saveReportJSON(jsonFile)
		fmt.Printf("%s[*]%s Scan results saved to: %s\n", colorBlue, colorReset, jsonFile)
		fmt.Printf("%s[*]%s Generate PDF with: report pdf %s\n", colorBlue, colorReset, jsonFile)
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func getRiskColor(risk string) string {
	switch strings.ToLower(risk) {
	case "critical":
		return colorRed + colorBold
	case "high":
		return colorRed
	case "medium":
		return colorYellow
	case "low":
		return colorBlue
	default:
		return colorReset
	}
}

func severityColor(sev exploit.Severity) string {
	switch sev {
	case exploit.SeverityCritical:
		return colorRed + colorBold
	case exploit.SeverityHigh:
		return colorRed
	case exploit.SeverityMedium:
		return colorYellow
	case exploit.SeverityLow:
		return colorBlue
	default:
		return colorReset
	}
}

func (c *Console) cmdReport(args []string) {
	if len(args) == 0 {
		fmt.Printf("%s[-]%s Usage: report <format> [output_file]\n", colorRed, colorReset)
		fmt.Println("  Formats: json, pdf, html, markdown")
		fmt.Println()
		fmt.Println("  Examples:")
		fmt.Println("    report json                     - Save JSON report")
		fmt.Println("    report pdf                      - Generate PDF report")
		fmt.Println("    report pdf scan_results.json    - Generate PDF from JSON")
		fmt.Println("    report html report.html         - Save HTML report")
		return
	}

	format := strings.ToLower(args[0])

	switch format {
	case "json":
		os.MkdirAll("output/scans", 0755)
		outputFile := "output/scans/pentest_report.json"
		if len(args) > 1 {
			outputFile = args[1]
		}
		if c.lastScanState == nil {
			fmt.Printf("%s[-]%s No scan data available. Run autopwn first.\n", colorRed, colorReset)
			return
		}
		c.saveReportJSON(outputFile)
		fmt.Printf("%s[+]%s JSON report saved to: %s\n", colorGreen, colorReset, outputFile)

	case "pdf":
		os.MkdirAll("output/reports", 0755)
		inputFile := ""
		outputFile := "output/reports/pentest_report.pdf"
		if len(args) > 1 {
			inputFile = args[1]
		}
		if len(args) > 2 {
			outputFile = args[2]
		}

		// If no input file, generate from current state
		if inputFile == "" {
			if c.lastScanState == nil {
				fmt.Printf("%s[-]%s No scan data available. Run autopwn first or specify JSON file.\n", colorRed, colorReset)
				return
			}
			inputFile = "temp_scan_data.json"
			c.saveReportJSON(inputFile)
			defer os.Remove(inputFile)
		}

		c.generatePDF(inputFile, outputFile)

	case "html":
		os.MkdirAll("output/reports", 0755)
		outputFile := "output/reports/pentest_report.html"
		if len(args) > 1 {
			outputFile = args[1]
		}
		if c.lastScanState == nil {
			fmt.Printf("%s[-]%s No scan data available. Run autopwn first.\n", colorRed, colorReset)
			return
		}
		c.saveReportHTML(outputFile)
		fmt.Printf("%s[+]%s HTML report saved to: %s\n", colorGreen, colorReset, outputFile)

	case "markdown", "md":
		os.MkdirAll("output/reports", 0755)
		outputFile := "output/reports/pentest_report.md"
		if len(args) > 1 {
			outputFile = args[1]
		}
		if c.lastScanState == nil {
			fmt.Printf("%s[-]%s No scan data available. Run autopwn first.\n", colorRed, colorReset)
			return
		}
		c.saveReportMarkdown(outputFile)
		fmt.Printf("%s[+]%s Markdown report saved to: %s\n", colorGreen, colorReset, outputFile)

	default:
		fmt.Printf("%s[-]%s Unknown format: %s\n", colorRed, colorReset, format)
	}
}

// ReportData represents the JSON structure for PDF generation
type ReportData struct {
	Target          string       `json:"target"`
	Date            string       `json:"date"`
	Tests           []TestResult `json:"tests"`
	Vulnerabilities []VulnEntry  `json:"vulnerabilities"`
	Credentials     []CredEntry  `json:"credentials"`
	CVEs            []CVEEntry   `json:"cves,omitempty"`
}

// CVEEntry represents CVE data for the report
type CVEEntry struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	CVSSScore   float64  `json:"cvss_score"`
	Severity    string   `json:"severity"`
	Remediation string   `json:"remediation"`
	PatchURLs   []string `json:"patch_urls,omitempty"`
}

type TestResult struct {
	Name    string `json:"name"`
	Action  string `json:"action"`
	Target  string `json:"target"`
	Success bool   `json:"success"`
	Output  string `json:"output"`
}

type VulnEntry struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Target      string `json:"target"`
	Service     string `json:"service,omitempty"`
	Description string `json:"description"`
	Evidence    string `json:"evidence,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

type CredEntry struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"` // SHA256(salt + password) - never store plaintext
	Salt         string `json:"salt"`          // Salt used for hashing
	Display      string `json:"display"`       // Masked display version (e.g., "ad****(8) [hash:a1b2]")
	Type         string `json:"type"`
	Source       string `json:"source"`
	Target       string `json:"target"`
}

func (c *Console) saveReportJSON(filename string) {
	if c.lastScanState == nil {
		return
	}

	state := c.lastScanState
	data := ReportData{
		Target:          state.Target,
		Date:            time.Now().Format("2006-01-02"),
		Tests:           make([]TestResult, 0),
		Vulnerabilities: make([]VulnEntry, 0),
		Credentials:     make([]CredEntry, 0),
	}

	// Convert action history to test results
	for _, action := range state.ActionHistory {
		data.Tests = append(data.Tests, TestResult{
			Name:    action.Type,
			Action:  action.Type,
			Target:  action.Target,
			Success: action.Success,
			Output:  action.Result,
		})
	}

	// Convert vulnerabilities
	for _, vuln := range state.Vulnerabilities {
		data.Vulnerabilities = append(data.Vulnerabilities, VulnEntry{
			Type:        vuln.Type,
			Severity:    vuln.Severity,
			Target:      vuln.Target,
			Service:     vuln.Service,
			Description: vuln.Description,
			Evidence:    vuln.Evidence,
			Remediation: vuln.Remediation,
		})
	}

	// Convert credentials - hash passwords for security
	for _, cred := range state.Credentials {
		salt := util.GenerateSalt(cred.Username, cred.Service, cred.Target)
		hash := util.HashPassword(cred.Password, salt)
		display := util.SanitizePassword(cred.Password)
		data.Credentials = append(data.Credentials, CredEntry{
			Username:     cred.Username,
			PasswordHash: hash,
			Salt:         salt,
			Display:      display,
			Type:         "password",
			Source:       cred.Service,
			Target:       cred.Target,
		})
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Printf("%s[-]%s Failed to marshal JSON: %v\n", colorRed, colorReset, err)
		return
	}

	if err := os.WriteFile(filename, jsonData, 0644); err != nil {
		fmt.Printf("%s[-]%s Failed to save JSON: %v\n", colorRed, colorReset, err)
	}
}

// saveAgentsReportJSON saves multi-agent scan results to JSON for PDF generation
func (c *Console) saveAgentsReportJSON(filename string, state *ai.ScanState) error {
	data := ReportData{
		Target:          state.Target,
		Date:            time.Now().Format("2006-01-02"),
		Tests:           make([]TestResult, 0),
		Vulnerabilities: make([]VulnEntry, 0),
		Credentials:     make([]CredEntry, 0),
		CVEs:            make([]CVEEntry, 0),
	}

	// Convert action history to test results
	for _, action := range state.ActionHistory {
		data.Tests = append(data.Tests, TestResult{
			Name:    action.Type,
			Action:  action.Type,
			Target:  action.Target,
			Success: action.Success,
			Output:  action.Result,
		})
	}

	// Convert vulnerabilities
	for _, vuln := range state.Vulnerabilities {
		data.Vulnerabilities = append(data.Vulnerabilities, VulnEntry{
			Type:        vuln.Type,
			Severity:    vuln.Severity,
			Target:      vuln.Target,
			Service:     vuln.Service,
			Description: vuln.Description,
			Evidence:    vuln.Evidence,
			Remediation: vuln.Remediation,
		})
	}

	// Convert credentials - hash passwords for security
	for _, cred := range state.Credentials {
		credType := "password"
		if cred.Hash != "" {
			credType = "hash"
		}
		salt := util.GenerateSalt(cred.Username, cred.Service, cred.Target)
		hash := util.HashPassword(cred.Password, salt)
		display := util.SanitizePassword(cred.Password)
		data.Credentials = append(data.Credentials, CredEntry{
			Username:     cred.Username,
			PasswordHash: hash,
			Salt:         salt,
			Display:      display,
			Type:         credType,
			Source:       cred.Service,
			Target:       cred.Target,
		})
	}

	// Look up CVE data for vulnerabilities
	if c.vulnLookup != nil && c.lastScanState != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cveInfos := c.lookupVulnerabilityCVEs(ctx, c.lastScanState)
		for _, info := range cveInfos {
			if info != nil && info.CVE != "" {
				entry := CVEEntry{
					ID:          info.CVE,
					Title:       info.Title,
					Description: info.Description,
					Severity:    info.Severity,
				}
				// Get CVSS score if available
				if info.CVSS != nil {
					entry.CVSSScore = info.CVSS.BaseScore
				}
				// Get remediation info if available
				if info.Remediation != nil {
					entry.Remediation = info.Remediation.Summary
					entry.PatchURLs = info.Remediation.PatchURLs
				}
				data.CVEs = append(data.CVEs, entry)
			}
		}
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if err := os.WriteFile(filename, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to save JSON: %w", err)
	}

	return nil
}

func (c *Console) generatePDF(inputFile, outputFile string) {
	// Check if node and the report generator exist
	scriptPath := "report/generate-report.js"
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		// Try alternate location
		scriptPath = "./report/generate-report.js"
		if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
			fmt.Printf("%s[-]%s PDF generator not found. Run: cd report && npm install\n", colorRed, colorReset)
			return
		}
	}

	fmt.Printf("%s[*]%s Generating PDF report...\n", colorBlue, colorReset)

	// Run the node script
	cmd := exec.Command("node", scriptPath, inputFile, outputFile)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()

	if err != nil {
		fmt.Printf("%s[-]%s PDF generation failed: %v\n", colorRed, colorReset, err)
		fmt.Println(string(output))
		fmt.Printf("%s[*]%s Make sure to run: cd report && npm install\n", colorBlue, colorReset)
		return
	}

	fmt.Printf("%s[+]%s PDF report generated: %s\n", colorGreen, colorReset, outputFile)
}

func (c *Console) saveReportHTML(filename string) {
	if c.lastScanState == nil {
		return
	}

	state := c.lastScanState
	html := c.generateHTMLReport(state)

	if err := os.WriteFile(filename, []byte(html), 0644); err != nil {
		fmt.Printf("%s[-]%s Failed to save HTML: %v\n", colorRed, colorReset, err)
	}
}

func (c *Console) saveReportMarkdown(filename string) {
	if c.lastScanState == nil {
		return
	}

	state := c.lastScanState
	md := c.generateMarkdownReport(state)

	if err := os.WriteFile(filename, []byte(md), 0644); err != nil {
		fmt.Printf("%s[-]%s Failed to save Markdown: %v\n", colorRed, colorReset, err)
	}
}

func (c *Console) generateHTMLReport(state *ai.PentestState) string {
	var sb strings.Builder

	sb.WriteString(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Penetration Test Report - ` + state.Target + `</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
        .header { background: linear-gradient(135deg, #1a365d 0%, #2d3748 100%); color: white; padding: 40px; border-radius: 10px; margin-bottom: 30px; }
        .header h1 { margin: 0 0 10px 0; font-size: 2.5em; }
        .header .target { font-size: 1.2em; opacity: 0.9; }
        .card { background: white; border-radius: 10px; padding: 25px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .card h2 { margin-top: 0; color: #1a365d; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .stat { background: #f7fafc; padding: 20px; border-radius: 8px; text-align: center; }
        .stat .value { font-size: 2em; font-weight: bold; }
        .stat .label { color: #718096; font-size: 0.9em; }
        .stat.critical .value { color: #c53030; }
        .stat.high .value { color: #dd6b20; }
        .stat.medium .value { color: #d69e2e; }
        .stat.low .value { color: #38a169; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }
        th { background: #f7fafc; font-weight: 600; }
        .badge { padding: 4px 12px; border-radius: 20px; font-size: 0.85em; font-weight: 500; }
        .badge.critical { background: #fed7d7; color: #c53030; }
        .badge.high { background: #feebc8; color: #c05621; }
        .badge.medium { background: #fefcbf; color: #975a16; }
        .badge.low { background: #c6f6d5; color: #276749; }
        .badge.info { background: #bee3f8; color: #2b6cb0; }
        .badge.success { background: #c6f6d5; color: #276749; }
        .badge.failed { background: #fed7d7; color: #c53030; }
        .test-item { padding: 15px; border-left: 4px solid #38a169; margin-bottom: 10px; background: #f7fafc; border-radius: 0 8px 8px 0; }
        .test-item.failed { border-left-color: #e53e3e; }
        .test-item .name { font-weight: 600; }
        .test-item .target { color: #718096; font-size: 0.9em; }
        .test-item .output { font-family: monospace; font-size: 0.85em; background: #2d3748; color: #e2e8f0; padding: 10px; border-radius: 4px; margin-top: 10px; white-space: pre-wrap; max-height: 200px; overflow-y: auto; }
        .cred-alert { background: #fed7d7; border: 2px solid #c53030; border-radius: 10px; padding: 20px; margin-bottom: 20px; }
        .cred-alert h3 { color: #c53030; margin-top: 0; }
        .footer { text-align: center; color: #718096; padding: 20px; }
    </style>
</head>
<body>
`)

	// Header
	sb.WriteString(fmt.Sprintf(`<div class="header">
    <h1>Penetration Test Report</h1>
    <div class="target">Target: %s</div>
    <div class="target">Date: %s</div>
</div>
`, state.Target, time.Now().Format("January 2, 2006")))

	// Stats summary
	critCount := 0
	highCount := 0
	medCount := 0
	lowCount := 0
	for _, v := range state.Vulnerabilities {
		switch strings.ToLower(v.Severity) {
		case "critical":
			critCount++
		case "high":
			highCount++
		case "medium":
			medCount++
		case "low":
			lowCount++
		}
	}

	sb.WriteString(`<div class="card">
    <h2>Executive Summary</h2>
    <div class="stats">
`)
	sb.WriteString(fmt.Sprintf(`        <div class="stat critical"><div class="value">%d</div><div class="label">Critical</div></div>
`, critCount))
	sb.WriteString(fmt.Sprintf(`        <div class="stat high"><div class="value">%d</div><div class="label">High</div></div>
`, highCount))
	sb.WriteString(fmt.Sprintf(`        <div class="stat medium"><div class="value">%d</div><div class="label">Medium</div></div>
`, medCount))
	sb.WriteString(fmt.Sprintf(`        <div class="stat low"><div class="value">%d</div><div class="label">Low</div></div>
`, lowCount))
	sb.WriteString(fmt.Sprintf(`        <div class="stat"><div class="value">%d</div><div class="label">Tests Run</div></div>
`, len(state.ActionHistory)))
	sb.WriteString(fmt.Sprintf(`        <div class="stat"><div class="value">%d</div><div class="label">Credentials</div></div>
`, len(state.Credentials)))
	sb.WriteString(`    </div>
</div>
`)

	// Credentials alert
	if len(state.Credentials) > 0 {
		sb.WriteString(`<div class="cred-alert">
    <h3>⚠️ CRITICAL: Credentials Exposed</h3>
    <p>The following credentials were extracted during testing (passwords hashed for security):</p>
    <table>
        <tr><th>Username</th><th>Password (Masked)</th><th>Service</th><th>Hash</th></tr>
`)
		for _, cred := range state.Credentials {
			// Hash password for report - never store plaintext
			salt := util.GenerateSalt(cred.Username, cred.Service, cred.Target)
			hash := util.HashPassword(cred.Password, salt)
			masked := util.SanitizePassword(cred.Password)
			sb.WriteString(fmt.Sprintf("        <tr><td><strong>%s</strong></td><td><code>%s</code></td><td>%s</td><td><small>%s</small></td></tr>\n",
				cred.Username, masked, cred.Service, hash[:16]+"..."))
		}
		sb.WriteString(`    </table>
    <p><small>Full password hashes available in JSON export for verification purposes.</small></p>
</div>
`)
	}

	// Test Results
	sb.WriteString(`<div class="card">
    <h2>Test Results</h2>
`)
	for _, action := range state.ActionHistory {
		statusClass := ""
		if !action.Success {
			statusClass = " failed"
		}
		sb.WriteString(fmt.Sprintf(`    <div class="test-item%s">
        <div class="name">%s <span class="badge %s">%s</span></div>
        <div class="target">%s</div>
`, statusClass, action.Type, func() string {
			if action.Success {
				return "success"
			}
			return "failed"
		}(), func() string {
			if action.Success {
				return "SUCCESS"
			}
			return "FAILED"
		}(), action.Target))

		if action.Result != "" && len(action.Result) < 1000 {
			sb.WriteString(fmt.Sprintf(`        <div class="output">%s</div>
`, action.Result))
		}
		sb.WriteString(`    </div>
`)
	}
	sb.WriteString(`</div>
`)

	// Vulnerabilities
	if len(state.Vulnerabilities) > 0 {
		sb.WriteString(`<div class="card">
    <h2>Vulnerabilities</h2>
    <table>
        <tr><th>Severity</th><th>Type</th><th>Target</th><th>Description</th></tr>
`)
		for _, v := range state.Vulnerabilities {
			sb.WriteString(fmt.Sprintf(`        <tr>
            <td><span class="badge %s">%s</span></td>
            <td>%s</td>
            <td>%s</td>
            <td>%s</td>
        </tr>
`, strings.ToLower(v.Severity), strings.ToUpper(v.Severity), v.Type, v.Target, v.Description))
		}
		sb.WriteString(`    </table>
</div>
`)
	}

	// Footer
	sb.WriteString(`<div class="footer">
    <p>Generated by PentestAI</p>
    <p>CONFIDENTIAL - FOR AUTHORIZED USE ONLY</p>
</div>
</body>
</html>`)

	return sb.String()
}

func (c *Console) generateMarkdownReport(state *ai.PentestState) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# Penetration Test Report\n\n"))
	sb.WriteString(fmt.Sprintf("**Target:** %s\n\n", state.Target))
	sb.WriteString(fmt.Sprintf("**Date:** %s\n\n", time.Now().Format("January 2, 2006")))
	sb.WriteString("---\n\n")

	// Credentials alert
	if len(state.Credentials) > 0 {
		sb.WriteString("## ⚠️ CRITICAL: Exposed Credentials\n\n")
		sb.WriteString("| Username | Password (Masked) | Service | Hash |\n")
		sb.WriteString("|----------|-------------------|---------|------|\n")
		for _, cred := range state.Credentials {
			// Hash password for report - never store plaintext
			salt := util.GenerateSalt(cred.Username, cred.Service, cred.Target)
			hash := util.HashPassword(cred.Password, salt)
			masked := util.SanitizePassword(cred.Password)
			sb.WriteString(fmt.Sprintf("| **%s** | `%s` | %s | `%s...` |\n", cred.Username, masked, cred.Service, hash[:16]))
		}
		sb.WriteString("\n**Immediate action required: Change all exposed passwords.**\n\n")
		sb.WriteString("*Note: Passwords are masked and hashed for security. Full hashes available in JSON export.*\n\n")
		sb.WriteString("---\n\n")
	}

	// Summary
	critCount := 0
	highCount := 0
	medCount := 0
	for _, v := range state.Vulnerabilities {
		switch strings.ToLower(v.Severity) {
		case "critical":
			critCount++
		case "high":
			highCount++
		case "medium":
			medCount++
		}
	}

	sb.WriteString("## Executive Summary\n\n")
	sb.WriteString(fmt.Sprintf("- **Critical:** %d\n", critCount))
	sb.WriteString(fmt.Sprintf("- **High:** %d\n", highCount))
	sb.WriteString(fmt.Sprintf("- **Medium:** %d\n", medCount))
	sb.WriteString(fmt.Sprintf("- **Tests Run:** %d\n", len(state.ActionHistory)))
	sb.WriteString(fmt.Sprintf("- **Credentials Found:** %d\n\n", len(state.Credentials)))

	// Test Results
	sb.WriteString("## Test Results\n\n")
	for _, action := range state.ActionHistory {
		status := "✅"
		if !action.Success {
			status = "❌"
		}
		sb.WriteString(fmt.Sprintf("### %s %s\n\n", status, action.Type))
		sb.WriteString(fmt.Sprintf("**Target:** %s\n\n", action.Target))
		if action.Result != "" && len(action.Result) < 500 {
			sb.WriteString("```\n")
			sb.WriteString(action.Result)
			sb.WriteString("\n```\n\n")
		}
	}

	// Vulnerabilities
	if len(state.Vulnerabilities) > 0 {
		sb.WriteString("## Vulnerabilities\n\n")
		sb.WriteString("| Severity | Type | Target | Description |\n")
		sb.WriteString("|----------|------|--------|-------------|\n")
		for _, v := range state.Vulnerabilities {
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", v.Severity, v.Type, v.Target, v.Description))
		}
	}

	// CVE Intelligence - Enrich vulnerabilities with NVD/Exploit-DB data
	if c.vulnLookup != nil && len(state.Vulnerabilities) > 0 {
		sb.WriteString("\n## Vulnerability Intelligence (CVE Details)\n\n")
		sb.WriteString("*Data enriched from NVD and Exploit-DB*\n\n")

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		// Look up CVEs based on vulnerability types and services
		cveInfos := c.lookupVulnerabilityCVEs(ctx, state)

		if len(cveInfos) > 0 {
			for _, info := range cveInfos {
				// Severity emoji
				severityEmoji := "ℹ️"
				switch strings.ToUpper(info.Severity) {
				case "CRITICAL":
					severityEmoji = "🔴"
				case "HIGH":
					severityEmoji = "🟠"
				case "MEDIUM":
					severityEmoji = "🟡"
				case "LOW":
					severityEmoji = "🟢"
				}

				sb.WriteString(fmt.Sprintf("### %s %s\n\n", severityEmoji, info.CVE))
				sb.WriteString(fmt.Sprintf("**Title:** %s\n\n", info.Title))

				if info.CVSS != nil {
					sb.WriteString(fmt.Sprintf("**CVSS Score:** %.1f (%s)\n\n", info.CVSS.BaseScore, info.Severity))
				}

				if info.Description != "" {
					desc := info.Description
					if len(desc) > 500 {
						desc = desc[:500] + "..."
					}
					sb.WriteString(fmt.Sprintf("**Description:** %s\n\n", desc))
				}

				if info.HasPublicExploit {
					sb.WriteString("**⚠️ PUBLIC EXPLOIT AVAILABLE**\n\n")
				}

				if info.Remediation != nil && info.Remediation.Summary != "" {
					sb.WriteString(fmt.Sprintf("**Remediation:** %s\n\n", info.Remediation.Summary))
					if len(info.Remediation.PatchURLs) > 0 {
						sb.WriteString("**Patch URLs:**\n")
						for _, url := range info.Remediation.PatchURLs[:min(3, len(info.Remediation.PatchURLs))] {
							sb.WriteString(fmt.Sprintf("- %s\n", url))
						}
						sb.WriteString("\n")
					}
				}

				sb.WriteString("---\n\n")
			}

			// Priority summary
			sb.WriteString("### Remediation Priority\n\n")
			sb.WriteString("| Priority | Count | Action |\n")
			sb.WriteString("|----------|-------|--------|\n")
			critical, high, medium, low := 0, 0, 0, 0
			hasExploit := 0
			for _, info := range cveInfos {
				switch strings.ToUpper(info.Severity) {
				case "CRITICAL":
					critical++
				case "HIGH":
					high++
				case "MEDIUM":
					medium++
				case "LOW":
					low++
				}
				if info.HasPublicExploit {
					hasExploit++
				}
			}
			if critical > 0 {
				sb.WriteString(fmt.Sprintf("| 🔴 Critical | %d | **Fix immediately** |\n", critical))
			}
			if high > 0 {
				sb.WriteString(fmt.Sprintf("| 🟠 High | %d | Fix within 24-48 hours |\n", high))
			}
			if medium > 0 {
				sb.WriteString(fmt.Sprintf("| 🟡 Medium | %d | Schedule for patching |\n", medium))
			}
			if low > 0 {
				sb.WriteString(fmt.Sprintf("| 🟢 Low | %d | Address in next maintenance |\n", low))
			}
			if hasExploit > 0 {
				sb.WriteString(fmt.Sprintf("\n**⚠️ WARNING:** %d vulnerabilities have public exploits!\n", hasExploit))
			}
		} else {
			sb.WriteString("*No additional CVE data found for detected vulnerabilities.*\n")
		}
	}

	sb.WriteString("\n---\n\n*Generated by PentestAI*\n")

	return sb.String()
}

func parsePorts(s string) []int {
	var ports []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.Split(part, "-")
			if len(bounds) == 2 {
				start, _ := strconv.Atoi(bounds[0])
				end, _ := strconv.Atoi(bounds[1])
				for p := start; p <= end; p++ {
					ports = append(ports, p)
				}
			}
		} else {
			p, _ := strconv.Atoi(part)
			if p > 0 {
				ports = append(ports, p)
			}
		}
	}
	return ports
}

// lookupVulnerabilityCVEs enriches vulnerabilities with CVE data from NVD/Exploit-DB
func (c *Console) lookupVulnerabilityCVEs(ctx context.Context, state *ai.PentestState) []*exploit.VulnerabilityInfo {
	if c.vulnLookup == nil {
		return nil
	}

	var results []*exploit.VulnerabilityInfo
	seen := make(map[string]bool)

	// Map vulnerability types to likely CVEs/products
	vulnTypeToCVE := map[string][]string{
		"sqli":                   {"sql injection"},
		"sql_injection":          {"sql injection"},
		"xss":                    {"cross-site scripting", "xss"},
		"lfi":                    {"local file inclusion", "path traversal"},
		"rce":                    {"remote code execution"},
		"command_injection":      {"command injection", "os command"},
		"cmd_injection":          {"command injection", "os command"},
		"ssrf":                   {"server-side request forgery", "ssrf"},
		"redis_unauth":           {"redis"},
		"mongodb_unauth":         {"mongodb"},
		"ssh_weak":               {"ssh"},
		"ssh_weak_credentials":   {"ssh", "openssh"},
		"ftp_anonymous":          {"ftp anonymous"},
		"rpc_command_injection":  {"xml-rpc", "xmlrpc", "remote code execution"},
		"xmlrpc_exploit":         {"xml-rpc", "xmlrpc"},
		"jsonrpc_exploit":        {"json-rpc", "jsonrpc"},
		"grpc_exploit":           {"grpc"},
		"grpc_command_injection": {"grpc", "remote code execution"},
		"ssl_vulnerabilities":    {"ssl", "tls", "openssl"},
		"auth_headers":           {"authentication bypass"},
	}

	// Map services to products for CVE lookup
	serviceToCVE := map[string]string{
		"redis":         "redis",
		"mongodb":       "mongodb",
		"mysql":         "mysql",
		"postgresql":    "postgresql",
		"elasticsearch": "elasticsearch",
		"apache":        "apache http server",
		"nginx":         "nginx",
		"tomcat":        "apache tomcat",
		"jenkins":       "jenkins",
	}

	// Look up CVEs for each vulnerability type
	for _, vuln := range state.Vulnerabilities {
		vulnType := strings.ToLower(vuln.Type)

		// Try to find relevant CVEs
		searchTerms := vulnTypeToCVE[vulnType]
		if len(searchTerms) == 0 {
			searchTerms = []string{vulnType}
		}

		for _, term := range searchTerms {
			if seen[term] {
				continue
			}
			seen[term] = true

			// Search local exploit database
			localResults := c.framework.SearchExploits(term)
			for _, entry := range localResults {
				if len(entry.CVE) > 0 {
					// Look up full CVE details
					for _, cveID := range entry.CVE {
						if seen[cveID] {
							continue
						}
						seen[cveID] = true

						info, err := c.vulnLookup.LookupCVE(ctx, cveID)
						if err == nil && info != nil {
							results = append(results, info)
							if len(results) >= 10 { // Limit to 10 CVEs
								return results
							}
						}
					}
				}
			}
		}
	}

	// Also check discovered services
	for _, svc := range state.Services {
		service := strings.ToLower(svc.Name)
		if product, ok := serviceToCVE[service]; ok {
			if seen[product] {
				continue
			}
			seen[product] = true

			// Search for service-specific vulnerabilities
			infos, err := c.vulnLookup.LookupByService(ctx, service, product, svc.Version)
			if err == nil {
				for _, info := range infos {
					if info.CVE != "" && !seen[info.CVE] {
						seen[info.CVE] = true
						results = append(results, info)
						if len(results) >= 10 {
							return results
						}
					}
				}
			}
		}
	}

	return results
}

// cmdAutoFix generates remediation fixes for vulnerabilities found in a scan
func (c *Console) cmdAutoFix(args []string) {
	if len(args) == 0 {
		fmt.Printf("%s[-]%s Usage: autofix [--safe|--review|--apply-lab|--ai] <scan_result.json>\n", colorRed, colorReset)
		fmt.Println("  --safe      : Auto-apply safe fixes (security headers, configs)")
		fmt.Println("  --review    : Generate all patches for human review (default)")
		fmt.Println("  --apply-lab : Patch lab containers using pre-defined secure versions")
		fmt.Println("  --ai        : AI-driven dynamic fixing (analyzes code and generates fixes)")
		fmt.Println("\nExamples:")
		fmt.Println("  autofix --apply-lab output/scans/agents_127_0_0_1_*.json")
		fmt.Println("  autofix --ai output/scans/agents_127_0_0_1_*.json")
		return
	}

	// Parse arguments
	mode := remediation.FixModeReview // Default to review mode (safe)
	applyLab := false
	aiMode := false
	var scanFile string

	for _, arg := range args {
		switch arg {
		case "--safe":
			mode = remediation.FixModeSafe
		case "--review":
			mode = remediation.FixModeReview
		case "--apply-lab":
			applyLab = true
			mode = remediation.FixModeSafe
		case "--ai":
			aiMode = true
		default:
			if !strings.HasPrefix(arg, "-") {
				scanFile = arg
			}
		}
	}

	// If --apply-lab, patch the containers based on scan results
	if applyLab {
		if scanFile == "" {
			fmt.Printf("%s[-]%s --apply-lab requires a scan file\n", colorRed, colorReset)
			fmt.Println("Example: autofix --apply-lab output/scans/agents_127_0_0_1_*.json")
			return
		}
		c.applyLabFixes(scanFile)
		return
	}

	// If --ai mode, use AI-driven dynamic fixing
	if aiMode {
		if scanFile == "" {
			fmt.Printf("%s[-]%s --ai requires a scan file\n", colorRed, colorReset)
			fmt.Println("Example: autofix --ai output/scans/agents_127_0_0_1_*.json")
			return
		}
		c.applyAIFixes(scanFile)
		return
	}

	if scanFile == "" {
		// Try to use last scan result
		if c.lastScanState != nil {
			fmt.Printf("%s[*]%s Using last autopwn scan results\n", colorBlue, colorReset)
		} else {
			fmt.Printf("%s[-]%s No scan file specified and no recent scan results\n", colorRed, colorReset)
			return
		}
	}

	// Load vulnerabilities from scan file or last state
	var vulns []remediation.VulnInput

	if scanFile != "" {
		// Load from JSON file
		data, err := os.ReadFile(scanFile)
		if err != nil {
			fmt.Printf("%s[-]%s Failed to read scan file: %v\n", colorRed, colorReset, err)
			return
		}

		var scanResult struct {
			Vulnerabilities []struct {
				Type        string `json:"type"`
				Target      string `json:"target"`
				Service     string `json:"service"`
				Description string `json:"description"`
				Evidence    string `json:"evidence"`
			} `json:"vulnerabilities"`
		}

		if err := json.Unmarshal(data, &scanResult); err != nil {
			fmt.Printf("%s[-]%s Failed to parse scan file: %v\n", colorRed, colorReset, err)
			return
		}

		for _, v := range scanResult.Vulnerabilities {
			vulns = append(vulns, remediation.VulnInput{
				Type:        v.Type,
				Target:      v.Target,
				Service:     v.Service,
				Description: v.Description,
				Evidence:    v.Evidence,
			})
		}

		fmt.Printf("%s[*]%s Loaded %d vulnerabilities from %s\n", colorBlue, colorReset, len(vulns), scanFile)
	} else if c.lastScanState != nil {
		// Use last scan state
		for _, v := range c.lastScanState.Vulnerabilities {
			vulns = append(vulns, remediation.VulnInput{
				Type:        v.Type,
				Target:      v.Target,
				Service:     v.Service,
				Description: v.Description,
				Evidence:    v.Evidence,
			})
		}
		fmt.Printf("%s[*]%s Using %d vulnerabilities from last scan\n", colorBlue, colorReset, len(vulns))
	}

	if len(vulns) == 0 {
		fmt.Printf("%s[*]%s No vulnerabilities found to fix\n", colorYellow, colorReset)
		return
	}

	// Create autofix instance
	outputDir := "output"
	fixer := remediation.NewAutoFixer(mode, outputDir)

	// Print mode
	modeStr := "REVIEW"
	if mode == remediation.FixModeSafe {
		modeStr = "SAFE"
	}

	fmt.Printf("\n%s╔══════════════════════════════════════════════════════════════╗%s\n", colorBold+colorCyan, colorReset)
	fmt.Printf("%s║              AUTOFIX - %s MODE                          ║%s\n", colorBold+colorCyan, modeStr, colorReset)
	fmt.Printf("%s╚══════════════════════════════════════════════════════════════╝%s\n\n", colorBold+colorCyan, colorReset)

	if mode == remediation.FixModeSafe {
		fmt.Printf("%s[*]%s Safe mode: Only applying fixes that cannot break functionality\n", colorBlue, colorReset)
	} else {
		fmt.Printf("%s[*]%s Review mode: Generating patches for human review\n", colorBlue, colorReset)
	}

	// Generate fixes
	result := fixer.GenerateFixes(vulns)

	// Print report
	report := fixer.GenerateReport(result)
	fmt.Println(report)

	// Summary
	fmt.Printf("\n%s[+]%s Remediation complete!\n", colorGreen, colorReset)
	fmt.Printf("    Patches saved to: %s/patches/\n", outputDir)

	if result.FixesApplied > 0 {
		fmt.Printf("    %s%d fixes auto-applied%s (safe fixes)\n", colorGreen, result.FixesApplied, colorReset)
	}
	if result.FixesPending > 0 {
		fmt.Printf("    %s%d fixes pending review%s\n", colorYellow, result.FixesPending, colorReset)
	}

	fmt.Printf("\n%s[*]%s Next steps:\n", colorBlue, colorReset)
	fmt.Println("    1. Review patches in output/patches/")
	fmt.Println("    2. Test in staging environment")
	fmt.Println("    3. Apply to production")
	fmt.Println("    4. Re-run: autopwn <target> to verify fixes")
}

// labFixMapping maps vulnerability types to lab service fixes
var labFixMapping = map[string]struct {
	service       string // Docker service name
	vulnFile      string // Vulnerable file path in container
	secureFile    string // Secure file path (local)
	containerPath string // Path inside container
	description   string
}{
	// XML-RPC vulnerabilities
	"rpc_command_injection": {"vuln-lab", "apps/xmlrpc-server/server.py", "lab/vuln-lab-image/apps/xmlrpc-server/server_secure.py", "/app/xmlrpc/server.py", "XML-RPC command injection"},
	"xmlrpc":                {"vuln-lab", "apps/xmlrpc-server/server.py", "lab/vuln-lab-image/apps/xmlrpc-server/server_secure.py", "/app/xmlrpc/server.py", "XML-RPC vulnerability"},
	"xml-rpc":               {"vuln-lab", "apps/xmlrpc-server/server.py", "lab/vuln-lab-image/apps/xmlrpc-server/server_secure.py", "/app/xmlrpc/server.py", "XML-RPC vulnerability"},

	// gRPC vulnerabilities
	"grpc_command_injection": {"vuln-lab", "apps/grpc-server/server.py", "lab/vuln-lab-image/apps/grpc-server/server_secure.py", "/app/grpc/server.py", "gRPC command injection"},
	"grpc":                   {"vuln-lab", "apps/grpc-server/server.py", "lab/vuln-lab-image/apps/grpc-server/server_secure.py", "/app/grpc/server.py", "gRPC vulnerability"},

	// JSON-RPC vulnerabilities
	"rpc_info_disclosure": {"vuln-lab", "apps/jsonrpc-server/server.js", "lab/vuln-lab-image/apps/jsonrpc-server/server_secure.js", "/app/jsonrpc/server.js", "JSON-RPC info disclosure"},
	"jsonrpc":             {"vuln-lab", "apps/jsonrpc-server/server.js", "lab/vuln-lab-image/apps/jsonrpc-server/server_secure.js", "/app/jsonrpc/server.js", "JSON-RPC vulnerability"},
	"json-rpc":            {"vuln-lab", "apps/jsonrpc-server/server.js", "lab/vuln-lab-image/apps/jsonrpc-server/server_secure.js", "/app/jsonrpc/server.js", "JSON-RPC vulnerability"},

	// Flask vulnerabilities
	"command_injection":         {"vuln-lab", "apps/vuln-flask/app.py", "lab/vuln-lab-image/apps/vuln-flask/app_secure.py", "/app/flask/app.py", "Flask command injection"},
	"ssti":                      {"vuln-lab", "apps/vuln-flask/app.py", "lab/vuln-lab-image/apps/vuln-flask/app_secure.py", "/app/flask/app.py", "Flask SSTI"},
	"insecure_deserialization":  {"vuln-lab", "apps/vuln-flask/app.py", "lab/vuln-lab-image/apps/vuln-flask/app_secure.py", "/app/flask/app.py", "Flask insecure deserialization"},
	"ssrf":                      {"vuln-lab", "apps/vuln-flask/app.py", "lab/vuln-lab-image/apps/vuln-flask/app_secure.py", "/app/flask/app.py", "Flask SSRF"},
	"flask":                     {"vuln-lab", "apps/vuln-flask/app.py", "lab/vuln-lab-image/apps/vuln-flask/app_secure.py", "/app/flask/app.py", "Flask vulnerability"},
	"information_disclosure":    {"vuln-lab", "apps/vuln-flask/app.py", "lab/vuln-lab-image/apps/vuln-flask/app_secure.py", "/app/flask/app.py", "Information disclosure"},
}

// applyLabFixes patches the lab Docker containers based on vulnerabilities found
func (c *Console) applyLabFixes(scanFile string) {
	fmt.Printf("\n%s╔══════════════════════════════════════════════════════════════╗%s\n", colorBold+colorCyan, colorReset)
	fmt.Printf("%s║          APPLYING FIXES TO LAB CONTAINERS                    ║%s\n", colorBold+colorCyan, colorReset)
	fmt.Printf("%s╚══════════════════════════════════════════════════════════════╝%s\n\n", colorBold+colorCyan, colorReset)

	// Load vulnerabilities from scan file
	data, err := os.ReadFile(scanFile)
	if err != nil {
		fmt.Printf("%s[-]%s Failed to read scan file: %v\n", colorRed, colorReset, err)
		return
	}

	var scanResult struct {
		Vulnerabilities []struct {
			Type        string `json:"type"`
			Target      string `json:"target"`
			Service     string `json:"service"`
			Severity    string `json:"severity"`
			Description string `json:"description"`
		} `json:"vulnerabilities"`
	}

	if err := json.Unmarshal(data, &scanResult); err != nil {
		fmt.Printf("%s[-]%s Failed to parse scan file: %v\n", colorRed, colorReset, err)
		return
	}

	fmt.Printf("%s[*]%s Loaded %d vulnerabilities from %s\n", colorBlue, colorReset, len(scanResult.Vulnerabilities), scanFile)

	// Track which services need to be patched and containers to update
	patchedFiles := make(map[string]bool)
	containerPatches := []struct {
		secureFile    string
		containerPath string
		description   string
		severity      string
	}{}

	for _, vuln := range scanResult.Vulnerabilities {
		// Check if we have a fix for this vulnerability type
		fix, exists := labFixMapping[vuln.Type]
		if !exists {
			// Try matching by service name
			if vuln.Service != "" {
				fix, exists = labFixMapping[vuln.Service]
			}
		}
		if !exists {
			// Try partial match on type
			for key, f := range labFixMapping {
				if strings.Contains(strings.ToLower(vuln.Type), strings.ToLower(key)) ||
					strings.Contains(strings.ToLower(key), strings.ToLower(vuln.Type)) {
					fix = f
					exists = true
					break
				}
			}
		}

		if !exists {
			continue // No fix available for this vuln type
		}

		// Skip if already patched this file
		if patchedFiles[fix.containerPath] {
			continue
		}

		// Check if secure version exists
		if _, err := os.Stat(fix.secureFile); os.IsNotExist(err) {
			fmt.Printf("%s[!]%s No secure version for %s at %s\n", colorYellow, colorReset, fix.description, fix.secureFile)
			continue
		}

		containerPatches = append(containerPatches, struct {
			secureFile    string
			containerPath string
			description   string
			severity      string
		}{fix.secureFile, fix.containerPath, fix.description, vuln.Severity})
		patchedFiles[fix.containerPath] = true
	}

	if len(containerPatches) == 0 {
		fmt.Printf("\n%s[*]%s No patchable vulnerabilities found in scan\n", colorYellow, colorReset)
		return
	}

	// Find the running vuln-lab container
	containerName := "vuln-lab"
	checkCmd := exec.Command("docker", "ps", "-q", "-f", "name="+containerName)
	containerID, err := checkCmd.Output()
	if err != nil || len(strings.TrimSpace(string(containerID))) == 0 {
		fmt.Printf("%s[-]%s Container '%s' not running. Start it with:\n", colorRed, colorReset, containerName)
		fmt.Printf("    cd lab/vuln-lab-image && docker-compose up -d\n")
		return
	}

	fmt.Printf("%s[*]%s Found running container: %s\n", colorBlue, colorReset, containerName)

	// Apply patches by copying secure files into container
	patchedCount := 0
	for _, patch := range containerPatches {
		fmt.Printf("%s[*]%s Patching: %s\n", colorBlue, colorReset, patch.description)

		// Docker cp the secure file into the container
		cpCmd := exec.Command("docker", "cp", patch.secureFile, containerName+":"+patch.containerPath)
		if output, err := cpCmd.CombinedOutput(); err != nil {
			fmt.Printf("%s[-]%s Failed to patch %s: %v\n    %s\n", colorRed, colorReset, patch.description, err, string(output))
			continue
		}

		fmt.Printf("%s[+]%s %sPATCHED%s: %s (%s)\n", colorGreen, colorReset, colorGreen, colorReset, patch.description, patch.severity)
		patchedCount++
	}

	if patchedCount == 0 {
		fmt.Printf("\n%s[-]%s No patches applied successfully\n", colorRed, colorReset)
		return
	}

	fmt.Printf("\n%s[+]%s Applied %d patches\n", colorGreen, colorReset, patchedCount)

	// Restart services in container using supervisorctl
	fmt.Printf("\n%s[*]%s Restarting services in container...\n", colorBlue, colorReset)
	restartCmd := exec.Command("docker", "exec", containerName, "supervisorctl", "restart", "all")
	if output, err := restartCmd.CombinedOutput(); err != nil {
		fmt.Printf("%s[!]%s Service restart warning: %v\n", colorYellow, colorReset, err)
		fmt.Printf("    Output: %s\n", strings.TrimSpace(string(output)))
		fmt.Printf("    You may need to restart manually: docker restart %s\n", containerName)
	} else {
		fmt.Printf("%s[+]%s Services restarted\n", colorGreen, colorReset)
	}

	fmt.Printf("\n%s[+]%s Fixes applied successfully!\n", colorGreen, colorReset)
	fmt.Printf("\n%s[*]%s Verify fixes with: agents 127.0.0.1\n", colorBlue, colorReset)
	fmt.Printf("%s[*]%s The patched vulnerabilities should now be FIXED\n", colorBlue, colorReset)
}

// revertLabFixes restores vulnerable versions for testing
func (c *Console) revertLabFixes() {
	fixes := []struct {
		name       string
		vulnerable string
	}{
		{"XML-RPC", "lab/services/xmlrpc/server.py"},
		{"gRPC", "lab/services/grpc/server.py"},
		{"JSON-RPC", "lab/services/jsonrpc/server.py"},
	}

	for _, fix := range fixes {
		backupPath := fix.vulnerable + ".vuln"
		if _, err := os.Stat(backupPath); err == nil {
			data, _ := os.ReadFile(backupPath)
			os.WriteFile(fix.vulnerable, data, 0644)
			fmt.Printf("%s[*]%s Reverted: %s\n", colorBlue, colorReset, fix.name)
		}
	}

	cmd := exec.Command("docker-compose", "-f", "lab/docker-compose.yml", "up", "-d", "--build", "xmlrpc", "grpc-server", "jsonrpc")
	cmd.Run()
	fmt.Printf("%s[+]%s Lab reverted to vulnerable state\n", colorGreen, colorReset)
}

// Vulnerabilities that REQUIRE human involvement - cannot be auto-fixed safely
var humanRequiredVulns = map[string]string{
	"ssh":                     "SSH hardening could lock out users - requires key setup first",
	"weak_credentials":        "Password changes require human decision on new credentials",
	"default_credentials":     "Credential changes require human decision",
	"mysql_weak_credentials":  "Database credential changes require application updates",
	"postgres_weak_password":  "Database credential changes require application updates",
	"mongodb_unauth":          "Enabling auth requires creating admin user first",
	"redis_unauth":            "Enabling auth requires updating all client applications",
	"ssl_certificate":         "Certificate replacement requires procurement/generation",
	"tls_weak_cipher":         "Cipher changes may break legacy clients",
}

// Vulnerabilities that CAN be auto-fixed safely by AI
var autoFixableVulns = map[string]bool{
	"command_injection":        true,
	"rpc_command_injection":    true,
	"sql_injection":            true,
	"ssti":                     true,
	"ssrf":                     true,
	"path_traversal":           true,
	"xxe":                      true,
	"insecure_deserialization": true,
	"information_disclosure":   true,
	"security_header":          true,
	"missing_header":           true,
}

// applyAIFixes uses AI to dynamically analyze and fix vulnerabilities
func (c *Console) applyAIFixes(scanFile string) {
	fmt.Printf("\n%s╔══════════════════════════════════════════════════════════════╗%s\n", colorBold+colorCyan, colorReset)
	fmt.Printf("%s║          AI-DRIVEN VULNERABILITY FIXING                      ║%s\n", colorBold+colorCyan, colorReset)
	fmt.Printf("%s╚══════════════════════════════════════════════════════════════╝%s\n\n", colorBold+colorCyan, colorReset)

	// Load vulnerabilities from scan file
	data, err := os.ReadFile(scanFile)
	if err != nil {
		fmt.Printf("%s[-]%s Failed to read scan file: %v\n", colorRed, colorReset, err)
		return
	}

	var scanResult struct {
		Vulnerabilities []struct {
			Type        string `json:"type"`
			Target      string `json:"target"`
			Port        int    `json:"port"`
			Service     string `json:"service"`
			Severity    string `json:"severity"`
			Description string `json:"description"`
			Evidence    string `json:"evidence"`
		} `json:"vulnerabilities"`
	}

	if err := json.Unmarshal(data, &scanResult); err != nil {
		fmt.Printf("%s[-]%s Failed to parse scan file: %v\n", colorRed, colorReset, err)
		return
	}

	fmt.Printf("%s[*]%s Loaded %d vulnerabilities from %s\n", colorBlue, colorReset, len(scanResult.Vulnerabilities), scanFile)

	// Categorize vulnerabilities
	var autoFixable []ai.VulnForFix
	var humanRequired []struct {
		vuln   string
		reason string
	}

	for _, v := range scanResult.Vulnerabilities {
		vulnLower := strings.ToLower(v.Type)

		// Check if human required
		humanReason := ""
		for key, reason := range humanRequiredVulns {
			if strings.Contains(vulnLower, key) {
				humanReason = reason
				break
			}
		}

		if humanReason != "" {
			humanRequired = append(humanRequired, struct {
				vuln   string
				reason string
			}{v.Type, humanReason})
			continue
		}

		// Check if auto-fixable
		canAutoFix := false
		for key := range autoFixableVulns {
			if strings.Contains(vulnLower, key) {
				canAutoFix = true
				break
			}
		}

		if canAutoFix {
			// Extract port from target if not provided
			port := v.Port
			if port == 0 {
				port = extractPortFromTarget(v.Target)
			}
			autoFixable = append(autoFixable, ai.VulnForFix{
				Type:        v.Type,
				Target:      v.Target,
				Port:        port,
				Service:     v.Service,
				Severity:    v.Severity,
				Description: v.Description,
				Evidence:    v.Evidence,
			})
		} else {
			// Unknown - add to human required for safety
			humanRequired = append(humanRequired, struct {
				vuln   string
				reason string
			}{v.Type, "Unknown vulnerability type - human review required"})
		}
	}

	// Report human-required vulns first
	if len(humanRequired) > 0 {
		fmt.Printf("\n%s═══ VULNERABILITIES REQUIRING HUMAN INVOLVEMENT ═══%s\n", colorYellow, colorReset)
		fmt.Printf("%s(These cannot be auto-fixed safely - manual remediation required)%s\n\n", colorYellow, colorReset)

		for _, hr := range humanRequired {
			fmt.Printf("  %s⚠%s  %s\n", colorYellow, colorReset, hr.vuln)
			fmt.Printf("      Reason: %s\n\n", hr.reason)
		}
	}

	if len(autoFixable) == 0 {
		fmt.Printf("\n%s[*]%s No auto-fixable vulnerabilities found\n", colorYellow, colorReset)
		return
	}

	// Create AI fixer
	aiFixer, err := ai.NewAIFixer("vuln-lab", "output")
	if err != nil {
		fmt.Printf("%s[-]%s Failed to initialize AI fixer: %v\n", colorRed, colorReset, err)
		return
	}

	fmt.Printf("\n%s═══ AUTO-FIXABLE VULNERABILITIES (%d) ═══%s\n\n", colorGreen, len(autoFixable), colorReset)

	ctx := context.Background()
	fixedCount := 0
	failedCount := 0

	for _, vuln := range autoFixable {
		fmt.Printf("%s[AI]%s Analyzing: %s on port %d\n", colorBold+colorMagenta, colorReset, vuln.Type, vuln.Port)

		result, err := aiFixer.GenerateAIFix(ctx, vuln)
		if err != nil {
			fmt.Printf("     %s[-]%s Analysis failed: %v\n", colorRed, colorReset, err)
			failedCount++
			continue
		}

		if result.Error != "" && result.FixedCode == "" {
			fmt.Printf("     %s[!]%s Could not generate fix: %s\n", colorYellow, colorReset, result.Error)
			if result.Explanation != "" {
				fmt.Printf("     Guidance: %s\n", truncateString(result.Explanation, 200))
			}
			failedCount++
			continue
		}

		if result.FixedCode != "" {
			fmt.Printf("     %s[+]%s Fix generated for %s in container %s\n", colorGreen, colorReset, result.SourceFile, result.ContainerName)
			fmt.Printf("     Explanation: %s\n", truncateString(result.Explanation, 150))

			// Apply the fix
			if err := aiFixer.ApplyFix(result); err != nil {
				fmt.Printf("     %s[-]%s Failed to apply fix: %v\n", colorRed, colorReset, err)
				failedCount++
			} else {
				fmt.Printf("     %s[+]%s %sFIX APPLIED%s to %s:%s\n", colorGreen, colorReset, colorGreen, colorReset, result.ContainerName, result.ContainerPath)
				fixedCount++

				// Restart this specific container
				fmt.Printf("     %s[*]%s Restarting container %s...\n", colorBlue, colorReset, result.ContainerName)
				if err := aiFixer.RestartContainerService(result.ContainerName); err != nil {
					fmt.Printf("     %s[!]%s Container restart warning: %v\n", colorYellow, colorReset, err)
				} else {
					fmt.Printf("     %s[+]%s Container %s restarted\n", colorGreen, colorReset, result.ContainerName)
				}
			}
		}
		fmt.Println()
	}

	// Summary
	fmt.Printf("\n%s═══ AI AUTOFIX SUMMARY ═══%s\n", colorBold+colorCyan, colorReset)
	fmt.Printf("  Total vulnerabilities: %d\n", len(scanResult.Vulnerabilities))
	fmt.Printf("  %sAuto-fixed:%s %d\n", colorGreen, colorReset, fixedCount)
	fmt.Printf("  %sFailed/Skipped:%s %d\n", colorYellow, colorReset, failedCount)
	fmt.Printf("  %sHuman required:%s %d\n", colorRed, colorReset, len(humanRequired))

	if fixedCount > 0 {
		fmt.Printf("\n%s[+]%s Verify fixes with: agents 127.0.0.1\n", colorGreen, colorReset)
	}

	if len(humanRequired) > 0 {
		fmt.Printf("\n%s[!]%s Remember: %d vulnerabilities require human remediation\n", colorYellow, colorReset, len(humanRequired))
	}
}

// truncateString truncates a string to maxLen and adds "..." if truncated
func truncateString(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// extractPortFromTarget extracts port number from target strings like "127.0.0.1:8086" or "http://127.0.0.1:8080"
func extractPortFromTarget(target string) int {
	// Remove protocol prefix if present
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")

	// Find the last colon followed by digits
	lastColon := strings.LastIndex(target, ":")
	if lastColon == -1 {
		return 0
	}

	// Extract the port part (handle paths like :8080/path)
	portStr := target[lastColon+1:]
	if slashIdx := strings.Index(portStr, "/"); slashIdx != -1 {
		portStr = portStr[:slashIdx]
	}

	var port int
	fmt.Sscanf(portStr, "%d", &port)
	return port
}

// cmdAutoPwnAgents runs the multi-agent parallel pentest
func (c *Console) cmdAutoPwnAgents(args []string) {
	if len(args) == 0 {
		fmt.Printf("%s[-]%s Usage: autopwn-agents <target> [--quick] [--turbo] [--max-actions N] [--timeout M]\n", colorRed, colorReset)
		fmt.Println("  Example: agents 192.168.1.1")
		fmt.Println("  Example: agents 127.0.0.1 --quick        # Fast scan, no AI (~1s)")
		fmt.Println("  Example: agents 127.0.0.1 --turbo        # Fast + AI parallel (~30s)")
		fmt.Println("  Example: agents 127.0.0.1 --max-actions 15")
		fmt.Println("\nMulti-agent mode runs specialized agents in parallel:")
		fmt.Println("  - Recon Agent: Port scanning, service discovery")
		fmt.Println("  - Web Agent: Web vulnerabilities (SQLi, XSS, etc)")
		fmt.Println("  - Auth Agent: SSH, FTP, Redis, MongoDB")
		fmt.Println("  - RPC Agent: XML-RPC, JSON-RPC, gRPC")
		fmt.Println("  - SSL Agent: TLS/SSL security")
		fmt.Println("  - Post-Exploit Agent: Credential spray, hash cracking")
		return
	}

	target := args[0]
	maxActions := 15
	timeout := 10 * time.Minute
	quickMode := false
	turboMode := false

	for i := 1; i < len(args); i++ {
		if args[i] == "--max-actions" && i+1 < len(args) {
			maxActions, _ = strconv.Atoi(args[i+1])
			i++
		}
		if args[i] == "--timeout" && i+1 < len(args) {
			mins, _ := strconv.Atoi(args[i+1])
			timeout = time.Duration(mins) * time.Minute
			i++
		}
		if args[i] == "--quick" || args[i] == "-q" {
			quickMode = true
			maxActions = 5
			timeout = 2 * time.Minute
		}
		if args[i] == "--turbo" || args[i] == "-t" {
			turboMode = true
			maxActions = 8 // Reduced for speed
			timeout = 3 * time.Minute
		}
	}

	fmt.Printf("\n%s%s╔══════════════════════════════════════════════════════════════╗%s\n", colorBold, colorCyan, colorReset)
	if quickMode {
		fmt.Printf("%s%s║        QUICK VULNERABILITY SCAN                               ║%s\n", colorBold, colorCyan, colorReset)
	} else if turboMode {
		fmt.Printf("%s%s║        TURBO PENETRATION TEST (AI parallel)                  ║%s\n", colorBold, colorCyan, colorReset)
	} else {
		fmt.Printf("%s%s║        MULTI-AGENT PARALLEL PENETRATION TEST                 ║%s\n", colorBold, colorCyan, colorReset)
	}
	fmt.Printf("%s%s╚══════════════════════════════════════════════════════════════╝%s\n\n", colorBold, colorCyan, colorReset)

	fmt.Printf("%s[*]%s Target: %s\n", colorBlue, colorReset, target)
	if quickMode {
		fmt.Printf("%s[*]%s Mode: QUICK (skipping AI exploration)\n", colorBlue, colorReset)
	} else if turboMode {
		fmt.Printf("%s[*]%s Mode: TURBO (AI runs in parallel with agents)\n", colorBlue, colorReset)
	}
	fmt.Printf("%s[*]%s Max Actions per Agent: %d\n", colorBlue, colorReset, maxActions)
	fmt.Printf("%s[*]%s Timeout: %v\n", colorBlue, colorReset, timeout)
	fmt.Printf("%s[*]%s Parallel agents will coordinate their efforts.\n\n", colorBlue, colorReset)

	// Create coordinator
	coordinator := ai.NewCoordinator(target, c.framework, c.ai)
	coordinator.SetMaxActionsPerAgent(maxActions)
	coordinator.SetTimeout(timeout)
	coordinator.SetQuickMode(quickMode)
	coordinator.SetTurboMode(turboMode)

	// Set up callbacks for progress reporting
	coordinator.SetCallbacks(ai.AgentCallbacks{
		OnAction: func(agent string, action, target string) {
			agentColor := colorCyan
			switch agent {
			case "recon":
				agentColor = colorBlue
			case "web":
				agentColor = colorYellow
			case "auth":
				agentColor = colorMagenta
			case "rpc":
				agentColor = colorGreen
			case "ssl":
				agentColor = colorRed
			case "post_exploit":
				agentColor = colorCyan
			case "coordinator":
				agentColor = colorBold + colorCyan
			}
			fmt.Printf("%s[%s]%s %s -> %s\n", agentColor, strings.ToUpper(agent), colorReset, action, target)
		},
		OnFinding: func(agent string, finding ai.Finding) {
			sevColor := colorBlue
			sevIcon := "ℹ"
			switch strings.ToLower(finding.Severity) {
			case "critical":
				sevColor = colorRed + colorBold
				sevIcon = "🔴"
			case "high":
				sevColor = colorRed
				sevIcon = "🟠"
			case "medium":
				sevColor = colorYellow
				sevIcon = "🟡"
			case "low":
				sevColor = colorCyan
				sevIcon = "🔵"
			}
			fmt.Printf("\n%s╔══ VULNERABILITY FOUND ══╗%s\n", sevColor, colorReset)
			fmt.Printf("%s[%s %s]%s %s (%s)\n", sevColor, sevIcon, strings.ToUpper(finding.Severity), colorReset, finding.Type, agent)
			fmt.Printf("  %sTarget:%s  %s\n", colorBold, colorReset, finding.Target)
			fmt.Printf("  %sDesc:%s    %s\n", colorBold, colorReset, finding.Description)
			if finding.Evidence != "" {
				// Truncate evidence for terminal display
				evidence := finding.Evidence
				if len(evidence) > 200 {
					evidence = evidence[:200] + "..."
				}
				// Remove newlines for cleaner display
				evidence = strings.ReplaceAll(evidence, "\n", " ")
				fmt.Printf("  %sEvidence:%s %s\n", colorBold, colorReset, evidence)
			}
			fmt.Printf("%s╚═════════════════════════╝%s\n", sevColor, colorReset)
		},
		OnCredential: func(agent string, cred ai.Credential) {
			fmt.Printf("%s[CRED]%s %s:%s @ %s\n", colorGreen+colorBold, colorReset, cred.Username, cred.Password, cred.Service)
		},
		OnComplete: func(agent string, actions int, findings int) {
			if agent == "coordinator" {
				fmt.Printf("\n%s[DONE]%s Total actions: %d, Total findings: %d\n", colorGreen+colorBold, colorReset, actions, findings)
			}
		},
		OnError: func(agent string, err error) {
			fmt.Printf("%s[ERR]%s %s: %v\n", colorRed, colorReset, agent, err)
		},
	})

	// Run the multi-agent pentest
	ctx := context.Background()
	if err := coordinator.Run(ctx); err != nil {
		fmt.Printf("%s[-]%s Multi-agent pentest failed: %v\n", colorRed, colorReset, err)
		return
	}

	// Get results
	results := coordinator.GetResults()

	fmt.Printf("\n%s%s═══════════════════ SUMMARY ═══════════════════%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("Ports discovered: %d\n", len(results.OpenPorts))
	fmt.Printf("Vulnerabilities: %d\n", len(results.Vulnerabilities))
	fmt.Printf("Credentials: %d\n", len(results.Credentials))

	// Show agent status
	fmt.Printf("\n%sAgent Status:%s\n", colorBold, colorReset)
	for name, status := range coordinator.GetState().GetAgentStatus() {
		statusColor := colorGreen
		if status.Status == "error" {
			statusColor = colorRed
		}
		duration := status.EndTime.Sub(status.StartTime)
		fmt.Printf("  %s: %s%s%s (%.1fs)\n", name, statusColor, status.Status, colorReset, duration.Seconds())
	}

	// Convert ScanState to PentestState for report compatibility
	if results != nil {
		c.lastScanState = c.convertScanStateToPentestState(results)
	}

	// Auto-save JSON and generate PDF report
	if results != nil && (len(results.Vulnerabilities) > 0 || len(results.Credentials) > 0) {
		os.MkdirAll("output/scans", 0755)
		timestamp := time.Now().Format("20060102_150405")
		jsonFile := fmt.Sprintf("output/scans/agents_%s_%s.json", strings.ReplaceAll(target, ".", "_"), timestamp)
		pdfFile := fmt.Sprintf("output/scans/agents_%s_%s.pdf", strings.ReplaceAll(target, ".", "_"), timestamp)

		if err := c.saveAgentsReportJSON(jsonFile, results); err != nil {
			fmt.Printf("%s[-]%s Failed to save report: %v\n", colorRed, colorReset, err)
		} else {
			fmt.Printf("\n%s[+]%s JSON report saved: %s\n", colorGreen, colorReset, jsonFile)

			// Auto-generate PDF
			c.generatePDF(jsonFile, pdfFile)
		}
	}
}

// convertScanStateToPentestState converts a ScanState to PentestState for report compatibility
func (c *Console) convertScanStateToPentestState(state *ai.ScanState) *ai.PentestState {
	if state == nil {
		return nil
	}

	// Convert credentials
	var credentials []ai.CredentialFind
	for _, cred := range state.Credentials {
		credentials = append(credentials, ai.CredentialFind{
			Username: cred.Username,
			Password: cred.Password,
			Hash:     cred.Hash,
			Service:  cred.Service,
			Target:   cred.Target,
		})
	}

	// Extract services from open ports (if available in action history)
	var services []ai.ServiceInfo
	for _, port := range state.OpenPorts {
		services = append(services, ai.ServiceInfo{
			Host: port.Host,
			Port: port.Port,
			Name: "unknown", // Will be enriched if available
		})
	}

	return &ai.PentestState{
		Target:          state.Target,
		Scope:           []string{state.Target},
		Phase:           "completed",
		DiscoveredHosts: state.DiscoveredHosts,
		OpenPorts:       state.OpenPorts,
		Services:        services,
		Vulnerabilities: state.Vulnerabilities,
		Credentials:     credentials,
		Sessions:        nil, // Not available from ScanState
		ActionHistory:   state.ActionHistory,
	}
}

// cmdTrain runs multiple training iterations
func (c *Console) cmdTrain(args []string) {
	if len(args) == 0 {
		fmt.Printf("%s[-]%s Usage: train <target> [iterations]\n", colorRed, colorReset)
		fmt.Println("  Example: train localhost 10")
		fmt.Println("  Example: train 192.168.1.1 20")
		fmt.Println("\nRuns multiple agents scans to train the AEI (Adaptive Exploitation Intelligence)")
		return
	}

	target := args[0]
	iterations := 10 // default

	if len(args) > 1 {
		fmt.Sscanf(args[1], "%d", &iterations)
	}

	fmt.Printf("\n%s%s╔══════════════════════════════════════════════════════════════╗%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s║              AEI TRAINING MODE                               ║%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s╚══════════════════════════════════════════════════════════════╝%s\n\n", colorBold, colorCyan, colorReset)

	fmt.Printf("%s[*]%s Target: %s\n", colorBlue, colorReset, target)
	fmt.Printf("%s[*]%s Iterations: %d\n", colorBlue, colorReset, iterations)
	fmt.Printf("%s[*]%s Mode: Turbo (AI parallel)\n\n", colorBlue, colorReset)

	for i := 1; i <= iterations; i++ {
		fmt.Printf("\n%s%s══════════════════════════════════════════════════════════════%s\n", colorBold, colorYellow, colorReset)
		fmt.Printf("%s%s  TRAINING ITERATION %d/%d%s\n", colorBold, colorYellow, i, iterations, colorReset)
		fmt.Printf("%s%s══════════════════════════════════════════════════════════════%s\n\n", colorBold, colorYellow, colorReset)

		// Run agents in turbo mode
		c.cmdAutoPwnAgents([]string{target, "--turbo"})

		fmt.Printf("\n%s[+]%s Iteration %d complete\n", colorGreen, colorReset, i)

		// Brief pause between iterations
		if i < iterations {
			fmt.Printf("%s[*]%s Pausing 3 seconds before next iteration...\n", colorBlue, colorReset)
			time.Sleep(3 * time.Second)
		}
	}

	fmt.Printf("\n%s%s╔══════════════════════════════════════════════════════════════╗%s\n", colorBold, colorGreen, colorReset)
	fmt.Printf("%s%s║              TRAINING COMPLETE                               ║%s\n", colorBold, colorGreen, colorReset)
	fmt.Printf("%s%s╚══════════════════════════════════════════════════════════════╝%s\n\n", colorBold, colorGreen, colorReset)
	fmt.Printf("%s[+]%s Completed %d training iterations on %s\n", colorGreen, colorReset, iterations, target)
	fmt.Printf("%s[*]%s AEI training data saved to output/training/aei_data.json\n", colorBlue, colorReset)
}
