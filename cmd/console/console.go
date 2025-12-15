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

	"pentestai/internal/ai"
	"pentestai/internal/exploit"
	"pentestai/internal/recon"
	"pentestai/internal/remediation"
	"pentestai/internal/webapp"
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
	currentModule exploit.Exploit
	workspace     string
	history       []string
	running       bool
	lastScanState *ai.PentestState  // Store last autopwn state for reporting
	lastReport    *ai.PentestReport // Store last autopwn report
}

func NewConsole() *Console {
	return &Console{
		framework:  exploit.NewFramework(),
		scanner:    recon.NewScanner(),
		webScanner: webapp.NewWebScanner(),
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
		return fmt.Sprintf("%spentestai%s %s(%s%s%s)%s > ",
			colorBold+colorRed, colorReset,
			colorReset, colorRed, info.Name, colorReset, colorReset)
	}
	return fmt.Sprintf("%spentestai%s > ", colorBold+colorRed, colorReset)
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
	case "ai":
		c.cmdAI(args)
	case "analyze":
		c.cmdAnalyze(args)
	case "autopwn", "auto":
		c.cmdAutoPwn(args)
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
			fmt.Printf("    %s:%s\n", cred.Username, cred.Password)
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
			switch strings.ToLower(finding.Severity) {
			case "critical":
				sevColor = colorRed + colorBold
			case "high":
				sevColor = colorRed
			case "medium":
				sevColor = colorYellow
			}
			fmt.Printf("%s[VULN]%s %s%s%s - %s\n",
				colorMagenta, colorReset, sevColor, finding.Severity, colorReset, finding.Type)
			fmt.Printf("       Target: %s\n", finding.Target)
			fmt.Printf("       %s\n", finding.Description)
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
					fmt.Printf("  %s:%s @ %s (%s)\n", cred.Username, cred.Password, cred.Target, cred.Service)
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
	Username string `json:"username"`
	Password string `json:"password"`
	Hash     string `json:"hash"`
	Type     string `json:"type"`
	Source   string `json:"source"`
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

	// Convert credentials
	for _, cred := range state.Credentials {
		data.Credentials = append(data.Credentials, CredEntry{
			Username: cred.Username,
			Password: cred.Password,
			Type:     "password",
			Source:   cred.Service,
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
    <p>The following credentials were extracted during testing:</p>
    <table>
        <tr><th>Username</th><th>Password</th><th>Source</th></tr>
`)
		for _, cred := range state.Credentials {
			sb.WriteString(fmt.Sprintf("        <tr><td><strong>%s</strong></td><td><code>%s</code></td><td>%s</td></tr>\n",
				cred.Username, cred.Password, cred.Service))
		}
		sb.WriteString(`    </table>
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
		sb.WriteString("| Username | Password | Source |\n")
		sb.WriteString("|----------|----------|--------|\n")
		for _, cred := range state.Credentials {
			sb.WriteString(fmt.Sprintf("| **%s** | `%s` | %s |\n", cred.Username, cred.Password, cred.Service))
		}
		sb.WriteString("\n**Immediate action required: Change all exposed passwords.**\n\n")
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

// cmdAutoFix generates remediation fixes for vulnerabilities found in a scan
func (c *Console) cmdAutoFix(args []string) {
	if len(args) == 0 {
		fmt.Printf("%s[-]%s Usage: autofix [--safe|--review|--apply-lab] <scan_result.json>\n", colorRed, colorReset)
		fmt.Println("  --safe      : Auto-apply safe fixes (security headers, configs)")
		fmt.Println("  --review    : Generate all patches for human review (default)")
		fmt.Println("  --apply-lab : Actually patch and rebuild the lab Docker containers")
		fmt.Println("\nExample: autofix --apply-lab output/scans/pentest_127_0_0_1_20251213.json")
		return
	}

	// Parse arguments
	mode := remediation.FixModeReview // Default to review mode (safe)
	applyLab := false
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
			fmt.Println("Example: autofix --apply-lab output/scans/pentest_127_0_0_1_*.json")
			return
		}
		c.applyLabFixes(scanFile)
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
	service     string // Docker service name
	vulnFile    string // Vulnerable file path
	secureFile  string // Secure file path
	description string
}{
	"rpc_command_injection":  {"xmlrpc", "lab/services/xmlrpc/server.py", "lab/services/xmlrpc/server_secure.py", "XML-RPC command injection"},
	"xmlrpc":                 {"xmlrpc", "lab/services/xmlrpc/server.py", "lab/services/xmlrpc/server_secure.py", "XML-RPC vulnerability"},
	"grpc_command_injection": {"grpc-server", "lab/services/grpc/server.py", "lab/services/grpc/server_secure.py", "gRPC command injection"},
	"grpc":                   {"grpc-server", "lab/services/grpc/server.py", "lab/services/grpc/server_secure.py", "gRPC vulnerability"},
	"rpc_info_disclosure":    {"jsonrpc", "lab/services/jsonrpc/server.py", "lab/services/jsonrpc/server_secure.py", "JSON-RPC info disclosure"},
	"jsonrpc":                {"jsonrpc", "lab/services/jsonrpc/server.py", "lab/services/jsonrpc/server_secure.py", "JSON-RPC vulnerability"},
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

	// Track which services need to be patched and rebuilt
	servicesToRebuild := make(map[string]bool)
	patchedFiles := make(map[string]bool)

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
				if strings.Contains(vuln.Type, key) || strings.Contains(key, vuln.Type) {
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
		if patchedFiles[fix.vulnFile] {
			continue
		}

		// Check if secure version exists
		if _, err := os.Stat(fix.secureFile); os.IsNotExist(err) {
			fmt.Printf("%s[!]%s No secure version for %s\n", colorYellow, colorReset, fix.description)
			continue
		}

		// Backup original if not already backed up
		backupPath := fix.vulnFile + ".vuln"
		if _, err := os.Stat(backupPath); os.IsNotExist(err) {
			origData, err := os.ReadFile(fix.vulnFile)
			if err != nil {
				fmt.Printf("%s[-]%s Failed to read %s: %v\n", colorRed, colorReset, fix.vulnFile, err)
				continue
			}
			if err := os.WriteFile(backupPath, origData, 0644); err != nil {
				fmt.Printf("%s[-]%s Failed to backup %s: %v\n", colorRed, colorReset, fix.vulnFile, err)
				continue
			}
			fmt.Printf("%s[*]%s Backed up: %s\n", colorBlue, colorReset, fix.vulnFile)
		}

		// Apply the fix
		secureData, err := os.ReadFile(fix.secureFile)
		if err != nil {
			fmt.Printf("%s[-]%s Failed to read secure file: %v\n", colorRed, colorReset, err)
			continue
		}
		if err := os.WriteFile(fix.vulnFile, secureData, 0644); err != nil {
			fmt.Printf("%s[-]%s Failed to apply fix: %v\n", colorRed, colorReset, err)
			continue
		}

		fmt.Printf("%s[+]%s %sPATCHED%s: %s (%s)\n", colorGreen, colorReset, colorGreen, colorReset, fix.description, vuln.Severity)
		patchedFiles[fix.vulnFile] = true
		servicesToRebuild[fix.service] = true
	}

	if len(servicesToRebuild) == 0 {
		fmt.Printf("\n%s[*]%s No patchable vulnerabilities found in scan\n", colorYellow, colorReset)
		return
	}

	fmt.Printf("\n%s[+]%s Patched %d services\n", colorGreen, colorReset, len(servicesToRebuild))

	// Build list of services to rebuild
	var services []string
	for svc := range servicesToRebuild {
		services = append(services, svc)
	}

	// Rebuild only affected containers
	fmt.Printf("\n%s[*]%s Rebuilding Docker containers: %v\n", colorBlue, colorReset, services)

	args := append([]string{"-f", "lab/docker-compose.yml", "up", "-d", "--build"}, services...)
	cmd := exec.Command("docker-compose", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Printf("%s[-]%s Failed to rebuild containers: %v\n", colorRed, colorReset, err)
		fmt.Printf("    Try manually: cd lab && docker-compose up -d --build %s\n", strings.Join(services, " "))
		return
	}

	fmt.Printf("\n%s[+]%s Containers rebuilt successfully!\n", colorGreen, colorReset)
	fmt.Printf("\n%s[*]%s Verify fixes with: autopwn 127.0.0.1\n", colorBlue, colorReset)
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
