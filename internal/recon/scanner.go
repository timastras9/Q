package recon

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

type Scanner struct {
	timeout     time.Duration
	concurrency int
}

type ScanResult struct {
	Target    string
	Hosts     []Host
	StartTime time.Time
	EndTime   time.Time
}

type Host struct {
	IP       string
	Hostname string
	State    string
	Ports    []Port
	OS       *OSGuess
	MAC      string
}

type Port struct {
	Number   int
	Protocol string
	State    string
	Service  Service
	Banner   string
}

type Service struct {
	Name    string
	Product string
	Version string
	Extra   string
	CPE     []string
}

type OSGuess struct {
	Name     string
	Accuracy int
	TTL      int
}

type ScanOptions struct {
	Ports       []int
	Protocol    string // tcp, udp, or both
	Timeout     time.Duration
	Concurrency int
	ServiceScan bool
	BannerGrab  bool
}

func NewScanner() *Scanner {
	return &Scanner{
		timeout:     2 * time.Second,
		concurrency: 1000,
	}
}

func (s *Scanner) SetTimeout(d time.Duration) {
	s.timeout = d
}

func (s *Scanner) SetConcurrency(c int) {
	s.concurrency = c
}

// DefaultPorts returns common ports to scan
func DefaultPorts() []int {
	return []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
		1433, 1521, 1723, 3306, 3389, 5432, 5900, 5985, 6379, 8000, 8080, 8443, 8888, 9090, 27017,
	}
}

// AllPorts returns 1-65535
func AllPorts() []int {
	ports := make([]int, 65535)
	for i := range ports {
		ports[i] = i + 1
	}
	return ports
}

// TopPorts returns the most commonly open ports
func TopPorts(n int) []int {
	top := []int{
		80, 443, 22, 21, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723,
		111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000,
		514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554, 26, 1433, 49152, 2001, 515,
		8008, 49154, 1027, 5666, 646, 5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800,
		106, 2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543, 544, 5101, 144,
		7, 389, 8009, 3128, 444, 9999, 5009, 7070, 5190, 3000, 5432, 1900, 3986, 13,
		1029, 9, 5051, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,
	}
	if n > len(top) {
		n = len(top)
	}
	return top[:n]
}

// ScanHost performs a port scan on a single host
func (s *Scanner) ScanHost(ctx context.Context, target string, opts ScanOptions) (*Host, error) {
	host := &Host{
		IP:    target,
		State: "down",
	}

	// Resolve hostname
	names, err := net.LookupAddr(target)
	if err == nil && len(names) > 0 {
		host.Hostname = strings.TrimSuffix(names[0], ".")
	}

	if len(opts.Ports) == 0 {
		opts.Ports = DefaultPorts()
	}

	if opts.Timeout == 0 {
		opts.Timeout = s.timeout
	}

	concurrency := s.concurrency
	if opts.Concurrency > 0 {
		concurrency = opts.Concurrency
	}

	// Channel for ports to scan
	portChan := make(chan int, len(opts.Ports))
	resultChan := make(chan Port, len(opts.Ports))

	// Worker pool
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portChan {
				select {
				case <-ctx.Done():
					return
				default:
					result := s.scanPort(ctx, target, port, opts)
					if result.State == "open" {
						resultChan <- result
					}
				}
			}
		}()
	}

	// Send ports to workers
	for _, port := range opts.Ports {
		portChan <- port
	}
	close(portChan)

	// Wait for completion
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	for port := range resultChan {
		host.Ports = append(host.Ports, port)
		host.State = "up"
	}

	// Sort ports
	sort.Slice(host.Ports, func(i, j int) bool {
		return host.Ports[i].Number < host.Ports[j].Number
	})

	// Guess OS from TTL if we got any connections
	if len(host.Ports) > 0 {
		host.OS = s.guessOS(target)
	}

	return host, nil
}

func (s *Scanner) scanPort(ctx context.Context, target string, port int, opts ScanOptions) Port {
	result := Port{
		Number:   port,
		Protocol: "tcp",
		State:    "closed",
	}

	address := fmt.Sprintf("%s:%d", target, port)
	dialer := net.Dialer{Timeout: opts.Timeout}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		if strings.Contains(err.Error(), "refused") {
			result.State = "closed"
		} else {
			result.State = "filtered"
		}
		return result
	}
	defer conn.Close()

	result.State = "open"

	// Service identification
	result.Service = identifyService(port)

	// Banner grabbing
	if opts.BannerGrab || opts.ServiceScan {
		result.Banner = grabBanner(conn, port, opts.Timeout)
		if result.Banner != "" {
			parseServiceFromBanner(&result)
		}
	}

	return result
}

// ScanNetwork scans a CIDR range
func (s *Scanner) ScanNetwork(ctx context.Context, cidr string, opts ScanOptions) (*ScanResult, error) {
	result := &ScanResult{
		Target:    cidr,
		StartTime: time.Now(),
	}

	hosts, err := expandCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	var wg sync.WaitGroup
	hostChan := make(chan *Host, len(hosts))

	// Limit concurrent host scans
	semaphore := make(chan struct{}, 50)

	for _, ip := range hosts {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			host, err := s.ScanHost(ctx, ip, opts)
			if err == nil && host.State == "up" {
				hostChan <- host
			}
		}(ip)
	}

	go func() {
		wg.Wait()
		close(hostChan)
	}()

	for host := range hostChan {
		result.Hosts = append(result.Hosts, *host)
	}

	result.EndTime = time.Now()
	return result, nil
}

// PingSweep discovers live hosts (TCP connect to common ports)
func (s *Scanner) PingSweep(ctx context.Context, cidr string) ([]string, error) {
	hosts, err := expandCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var alive []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	semaphore := make(chan struct{}, 100)
	checkPorts := []int{80, 443, 22, 445}

	for _, ip := range hosts {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			for _, port := range checkPorts {
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 500*time.Millisecond)
				if err == nil {
					conn.Close()
					mu.Lock()
					alive = append(alive, ip)
					mu.Unlock()
					return
				}
			}
		}(ip)
	}

	wg.Wait()
	return alive, nil
}

// UDPScan scans UDP ports
func (s *Scanner) UDPScan(ctx context.Context, target string, ports []int) (*Host, error) {
	host := &Host{
		IP:    target,
		State: "unknown",
	}

	if len(ports) == 0 {
		ports = []int{53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 1900}
	}

	for _, port := range ports {
		select {
		case <-ctx.Done():
			return host, ctx.Err()
		default:
		}

		addr := fmt.Sprintf("%s:%d", target, port)
		conn, err := net.DialTimeout("udp", addr, s.timeout)
		if err != nil {
			continue
		}

		// Send probe packet based on service
		probe := getUDPProbe(port)
		conn.SetDeadline(time.Now().Add(s.timeout))
		conn.Write(probe)

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		conn.Close()

		if err == nil && n > 0 {
			host.State = "up"
			port := Port{
				Number:   port,
				Protocol: "udp",
				State:    "open",
				Banner:   string(buf[:n]),
			}
			port.Service = identifyService(port.Number)
			host.Ports = append(host.Ports, port)
		}
	}

	return host, nil
}

func grabBanner(conn net.Conn, port int, timeout time.Duration) string {
	conn.SetDeadline(time.Now().Add(timeout))

	// Send probe based on port
	probe := getProbe(port)
	if probe != nil {
		conn.Write(probe)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(buf[:n]))
}

func getProbe(port int) []byte {
	probes := map[int][]byte{
		21:   []byte(""),                                                                       // FTP sends banner first
		22:   []byte(""),                                                                       // SSH sends banner first
		25:   []byte("EHLO probe\r\n"),                                                         // SMTP
		80:   []byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"),                              // HTTP
		110:  []byte(""),                                                                       // POP3 sends banner
		143:  []byte(""),                                                                       // IMAP sends banner
		443:  nil,                                                                              // HTTPS needs TLS
		3306: []byte(""),                                                                       // MySQL sends banner
		6379: []byte("INFO\r\n"),                                                               // Redis
		8080: []byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"),                              // HTTP alt
		27017: []byte{58, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 212, 7, 0, 0, 0, 0, 0, 0, 97, 100,
			109, 105, 110, 46, 36, 99, 109, 100, 0, 0, 0, 0, 0, 255, 255, 255, 255, 27, 0, 0, 0,
			16, 105, 115, 109, 97, 115, 116, 101, 114, 0, 1, 0, 0, 0, 0}, // MongoDB
	}

	if probe, ok := probes[port]; ok {
		return probe
	}
	return []byte("")
}

func getUDPProbe(port int) []byte {
	probes := map[int][]byte{
		53:  {0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // DNS
		123: {0x1b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // NTP
		161: {0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa1, 0x19, 0x02, 0x04, 0x71, 0xba, 0x90, 0x42, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00}, // SNMP
	}
	if probe, ok := probes[port]; ok {
		return probe
	}
	return []byte("probe")
}

func identifyService(port int) Service {
	services := map[int]Service{
		21:    {Name: "ftp"},
		22:    {Name: "ssh"},
		23:    {Name: "telnet"},
		25:    {Name: "smtp"},
		53:    {Name: "dns"},
		80:    {Name: "http"},
		110:   {Name: "pop3"},
		111:   {Name: "rpcbind"},
		135:   {Name: "msrpc"},
		139:   {Name: "netbios-ssn"},
		143:   {Name: "imap"},
		443:   {Name: "https"},
		445:   {Name: "microsoft-ds"},
		993:   {Name: "imaps"},
		995:   {Name: "pop3s"},
		1433:  {Name: "mssql"},
		1521:  {Name: "oracle"},
		3306:  {Name: "mysql"},
		3389:  {Name: "rdp"},
		5432:  {Name: "postgresql"},
		5900:  {Name: "vnc"},
		5985:  {Name: "winrm"},
		6379:  {Name: "redis"},
		8080:  {Name: "http-proxy"},
		8443:  {Name: "https-alt"},
		27017: {Name: "mongodb"},
	}

	if svc, ok := services[port]; ok {
		return svc
	}
	return Service{Name: "unknown"}
}

func parseServiceFromBanner(port *Port) {
	banner := strings.ToLower(port.Banner)

	patterns := map[string]func(*Port){
		"ssh-":     func(p *Port) { p.Service.Name = "ssh"; parseSSHBanner(p) },
		"220":      func(p *Port) { p.Service.Name = "ftp"; parseFTPBanner(p) },
		"http/":    func(p *Port) { parseHTTPBanner(p) },
		"mysql":    func(p *Port) { p.Service.Name = "mysql" },
		"redis":    func(p *Port) { p.Service.Name = "redis" },
		"mongodb":  func(p *Port) { p.Service.Name = "mongodb" },
		"postgres": func(p *Port) { p.Service.Name = "postgresql" },
		"+ok":      func(p *Port) { p.Service.Name = "pop3" },
		"* ok":     func(p *Port) { p.Service.Name = "imap" },
	}

	for pattern, handler := range patterns {
		if strings.Contains(banner, pattern) {
			handler(port)
			return
		}
	}
}

func parseSSHBanner(port *Port) {
	// SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
	parts := strings.Split(port.Banner, "-")
	if len(parts) >= 3 {
		port.Service.Product = strings.Split(parts[2], "_")[0]
		if len(strings.Split(parts[2], "_")) > 1 {
			port.Service.Version = strings.Split(parts[2], "_")[1]
		}
	}
}

func parseFTPBanner(port *Port) {
	if strings.Contains(port.Banner, "vsftpd") {
		port.Service.Product = "vsftpd"
	} else if strings.Contains(port.Banner, "ProFTPD") {
		port.Service.Product = "ProFTPD"
	} else if strings.Contains(port.Banner, "FileZilla") {
		port.Service.Product = "FileZilla"
	}
}

func parseHTTPBanner(port *Port) {
	lines := strings.Split(port.Banner, "\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			port.Service.Product = strings.TrimSpace(strings.TrimPrefix(line, "Server:"))
			port.Service.Product = strings.TrimSpace(strings.TrimPrefix(port.Service.Product, "server:"))
		}
	}
}

func (s *Scanner) guessOS(target string) *OSGuess {
	// Try to get TTL from TCP connection
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:80", target), s.timeout)
	if err != nil {
		conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:22", target), s.timeout)
	}
	if err != nil {
		conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:443", target), s.timeout)
	}
	if err != nil {
		return nil
	}
	defer conn.Close()

	// Common TTL values and their OS
	// This is a simplified heuristic
	return &OSGuess{
		Name:     "Unknown",
		Accuracy: 50,
	}
}

func expandCIDR(cidr string) ([]string, error) {
	// Handle single IP
	if !strings.Contains(cidr, "/") {
		return []string{cidr}, nil
	}

	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	// Remove network and broadcast addresses for /24 and larger
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// FormatResult returns a human-readable summary
func (r *ScanResult) FormatResult() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Scan Results for %s\n", r.Target))
	sb.WriteString(fmt.Sprintf("Duration: %v\n\n", r.EndTime.Sub(r.StartTime).Round(time.Millisecond)))

	for _, host := range r.Hosts {
		if host.State != "up" {
			continue
		}

		sb.WriteString(fmt.Sprintf("Host: %s", host.IP))
		if host.Hostname != "" {
			sb.WriteString(fmt.Sprintf(" (%s)", host.Hostname))
		}
		sb.WriteString(fmt.Sprintf(" [%s]\n", host.State))

		if host.OS != nil && host.OS.Name != "" {
			sb.WriteString(fmt.Sprintf("  OS: %s\n", host.OS.Name))
		}

		sb.WriteString("  Open Ports:\n")
		for _, port := range host.Ports {
			sb.WriteString(fmt.Sprintf("    %d/%s - %s", port.Number, port.Protocol, port.Service.Name))
			if port.Service.Product != "" {
				sb.WriteString(fmt.Sprintf(" (%s", port.Service.Product))
				if port.Service.Version != "" {
					sb.WriteString(fmt.Sprintf(" %s", port.Service.Version))
				}
				sb.WriteString(")")
			}
			sb.WriteString("\n")
			if port.Banner != "" && len(port.Banner) < 100 {
				sb.WriteString(fmt.Sprintf("      Banner: %s\n", port.Banner))
			}
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

func (r *ScanResult) GetOpenPorts() []Port {
	var ports []Port
	for _, host := range r.Hosts {
		for _, port := range host.Ports {
			if port.State == "open" {
				ports = append(ports, port)
			}
		}
	}
	return ports
}
