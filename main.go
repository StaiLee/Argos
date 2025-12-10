package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// --- 1. CONFIGURATION & CONSTANTES ---

const (
	AppVersion = "4.2.0 (The Oracle)"
	AppName    = "ARGOS PANOPTES"

	// ANSI Colors
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
	ColorBold   = "\033[1m"
	ColorGrey   = "\033[90m"
	ColorOrange = "\033[38;5;208m"
)

var CommonPorts = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
	110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
	3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
	8443: "HTTPS-Alt", 9000: "Portainer", 27017: "MongoDB",
}

// Score de risque
var RiskWeights = map[int]int{
	21: 20, 23: 30, 445: 25, 3389: 15, 80: 5, 443: 0, 22: 5,
}

// --- 2. STRUCTURES DE DONNÉES ---

type ScanTarget struct {
	IP   string
	Port int
}

type ScanResult struct {
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Service   string `json:"service"`
	Banner    string `json:"banner,omitempty"`
	WebTitle  string `json:"web_title,omitempty"`
	WebServer string `json:"web_server,omitempty"`
	RiskScore int    `json:"risk_score"`
}

type ScanProfile struct {
	ID        string
	Name      string
	Desc      string
	Tactics   string
	Timeout   time.Duration
	Delay     time.Duration
	Threads   int
	PortRange string
	Randomize bool
}

// --- 3. INTELLIGENCE MODULES ---

func probeHTTP(ip string, port int, timeout time.Duration) (string, string) {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d", scheme, ip, port)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   timeout + 500*time.Millisecond,
	}

	resp, err := client.Get(url)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()

	serverHeader := resp.Header.Get("Server")
	if serverHeader == "" {
		serverHeader = "Hidden"
	}

	buffer := make([]byte, 2048)
	n, _ := io.ReadFull(resp.Body, buffer)
	content := string(buffer[:n])

	re := regexp.MustCompile(`(?i)<title>(.*?)</title>`)
	matches := re.FindStringSubmatch(content)
	title := "No Title"
	if len(matches) > 1 {
		title = strings.TrimSpace(matches[1])
	}

	return title, serverHeader
}

// --- 4. LOGIQUE MÉTIER (CORE) ---

func scanPort(ctx context.Context, target ScanTarget, timeout time.Duration) *ScanResult {
	select {
	case <-ctx.Done():
		return nil
	default:
	}

	address := fmt.Sprintf("%s:%d", target.IP, target.Port)
	d := net.Dialer{Timeout: timeout}

	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buffer := make([]byte, 256)
	n, _ := conn.Read(buffer)
	banner := strings.TrimSpace(string(buffer[:n]))

	banner = strings.Map(func(r rune) rune {
		if r >= 32 && r <= 126 {
			return r
		}
		return -1
	}, banner)

	service := CommonPorts[target.Port]
	if service == "" {
		service = "TCP"
	}

	webTitle := ""
	webServer := ""
	if target.Port == 80 || target.Port == 443 || target.Port == 8080 || target.Port == 8443 {
		webTitle, webServer = probeHTTP(target.IP, target.Port, timeout)
	}

	risk := RiskWeights[target.Port]
	if risk == 0 {
		risk = 1
	}

	return &ScanResult{
		IP:        target.IP,
		Port:      target.Port,
		Service:   service,
		Banner:    banner,
		WebTitle:  webTitle,
		WebServer: webServer,
		RiskScore: risk,
	}
}

func worker(ctx context.Context, jobs <-chan ScanTarget, results chan<- *ScanResult, wg *sync.WaitGroup, profile ScanProfile) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case target, ok := <-jobs:
			if !ok {
				return
			}
			if profile.Delay > 0 {
				jitter := time.Duration(rand.Intn(int(profile.Delay)/2) + int(profile.Delay)/2)
				time.Sleep(jitter)
			}
			res := scanPort(ctx, target, profile.Timeout)
			if res != nil {
				results <- res
			} else {
				results <- nil
			}
		}
	}
}

// --- 5. VISUALS & REPORTING ---

func generateHTMLReport(filename string, results []ScanResult) {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ARGOS RECON REPORT</title>
    <style>
        body { background-color: #0d0d0d; color: #00ff41; font-family: 'Courier New', monospace; padding: 20px; }
        h1 { text-align: center; text-shadow: 0 0 10px #00ff41; border-bottom: 2px solid #00ff41; padding-bottom: 10px; }
        .stats { display: flex; justify-content: space-around; margin: 20px 0; background: #1a1a1a; padding: 15px; border-radius: 5px; }
        .stat-box { text-align: center; }
        .stat-val { font-size: 2em; font-weight: bold; color: #fff; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #333; padding: 12px; text-align: left; }
        th { background-color: #1a1a1a; color: #fff; }
        tr:hover { background-color: #111; }
        .critical { color: #ff3333; font-weight: bold; }
        .web-info { color: #00bfff; font-size: 0.9em; }
        .footer { margin-top: 50px; text-align: center; color: #555; font-size: 0.8em; }
    </style>
</head>
<body>
    <h1>👁️ ARGOS PANOPTES // INTELLIGENCE REPORT</h1>
    <div class="stats">
        <div class="stat-box"><div class="stat-val">` + strconv.Itoa(len(results)) + `</div><div>Open Ports</div></div>
        <div class="stat-box"><div class="stat-val">TARGET</div><div>Secured</div></div>
        <div class="stat-box"><div class="stat-val">` + time.Now().Format("15:04:05") + `</div><div>Time</div></div>
    </div>
    <table>
        <tr><th>IP</th><th>PORT</th><th>SERVICE</th><th>DETAILS / BANNER</th><th>RISK</th></tr>`

	for _, r := range results {
		details := r.Banner
		if r.WebTitle != "" {
			details = fmt.Sprintf("<span class='web-info'>[WEB] %s (%s)</span>", r.WebTitle, r.WebServer)
		} else if details == "" {
			details = "-"
		}

		riskClass := ""
		riskTxt := "LOW"
		if r.RiskScore >= 20 {
			riskClass = "critical"
			riskTxt = "CRITICAL"
		} else if r.RiskScore >= 10 {
			riskTxt = "HIGH"
		}

		html += fmt.Sprintf("<tr><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td class='%s'>%s</td></tr>",
			r.IP, r.Port, r.Service, details, riskClass, riskTxt)
	}

	html += `</table><div class="footer">GENERATED BY ARGOS PANOPTES v4.2.0</div></body></html>`

	_ = os.WriteFile(filename, []byte(html), 0644)
	fmt.Printf("%s[✓] Rapport HTML généré : %s%s\n", ColorGreen, filename, ColorReset)
}

func printRiskBar(totalRisk int) {
	level := "LOW"
	color := ColorGreen
	barLength := 20

	fill := 0
	if totalRisk > 0 {
		fill = totalRisk / 5
	}
	if fill > barLength {
		fill = barLength
	}

	if totalRisk > 50 {
		level = "CRITICAL"
		color = ColorRed
	} else if totalRisk > 20 {
		level = "ELEVATED"
		color = ColorOrange
	}

	bar := strings.Repeat("█", fill) + strings.Repeat("░", barLength-fill)
	fmt.Printf("\n%sTHREAT ASSESSMENT:%s\n", ColorBold, ColorReset)
	fmt.Printf("[%s%s%s] LEVEL: %s%s%s (Score: %d)\n", color, bar, ColorReset, color, level, ColorReset, totalRisk)
}

// --- 6. VISUELS ---

func rgb(r, g, b int) string { return fmt.Sprintf("\033[38;2;%d;%d;%dm", r, g, b) }

func gradient(text string, startR, startG, startB, endR, endG, endB int) string {
	var result string
	length := len(text)
	if length == 0 {
		return text
	}
	for i, char := range text {
		r := startR + int(float64(endR-startR)*float64(i)/float64(length))
		g := startG + int(float64(endG-startG)*float64(i)/float64(length))
		b := startB + int(float64(endB-startB)*float64(i)/float64(length))
		result += rgb(r, g, b) + string(char)
	}
	return result + ColorReset
}

func printBanner(modeID string) {
	lines := []string{
		`    ___    ____  ______  ____  _____`,
		`   /   |  / __ \/ ____/ / __ \/ ___/`,
		`  / /| | / /_/ / / __  / / / /\__ \ `,
		` / ___ |/ _, _/ /_/ / / /_/ /___/ / `,
		`/_/  |_/_/ |_|\____/  \____//____/  `,
	}
	var sR, sG, sB, eR, eG, eB int
	var subTitleColor string
	switch modeID {
	case "shadow":
		sR, sG, sB = 40, 40, 40
		eR, eG, eB = 220, 220, 220
		subTitleColor = ColorGrey
	case "blitz":
		sR, sG, sB = 255, 255, 0
		eR, eG, eB = 255, 0, 0
		subTitleColor = ColorYellow
	case "titan":
		sR, sG, sB = 0, 0, 150
		eR, eG, eB = 0, 255, 255
		subTitleColor = ColorCyan
	default:
		sR, sG, sB = 0, 100, 0
		eR, eG, eB = 50, 255, 50
		subTitleColor = ColorGreen
	}
	fmt.Println()
	for _, line := range lines {
		fmt.Println(gradient(line, sR, sG, sB, eR, eG, eB))
	}
	fmt.Println()

	if modeID != "help" {
		fmt.Printf("  :: %s :: %sMODE %s ACTIVATED%s\n", AppVersion, subTitleColor, strings.ToUpper(modeID), ColorReset)
	} else {
		fmt.Printf("  :: %s :: %sORACLE SYSTEM ONLINE%s\n", AppVersion, subTitleColor, ColorReset)
	}
	fmt.Println(strings.Repeat("-", 60))
}

func updateProgressBar(current, total int) {
	percent := float64(current) / float64(total) * 100
	width := 40
	completed := int(float64(width) * (float64(current) / float64(total)))
	bar := strings.Repeat("█", completed) + strings.Repeat("░", width-completed)
	color := ColorBlue
	if percent > 90 {
		color = ColorGreen
	}
	fmt.Printf("\r%s[%s] %.1f%%%s", color, bar, percent, ColorReset)
}

// --- 7. MAIN ---

func main() {
	profiles := map[string]ScanProfile{
		"scout": {
			ID: "scout", Name: "SCOUT",
			Desc:    "Standard Recon (Default). Top 1024 ports.",
			Tactics: "Use for initial discovery. Balanced speed/noise.",
			Timeout: 500 * time.Millisecond, Delay: 0, Threads: 500, PortRange: "1-1024", Randomize: false},
		"shadow": {
			ID: "shadow", Name: "SHADOW",
			Desc:    "Stealth/Evasion. Slow, randomized delays.",
			Tactics: "Use against Firewalls/IDS or Red Team Ops. Very slow but safe.",
			Timeout: 2000 * time.Millisecond, Delay: 1500 * time.Millisecond, Threads: 10, PortRange: "1-1000", Randomize: true},
		"blitz": {
			ID: "blitz", Name: "BLITZ",
			Desc:    "Aggressive Strike. Max speed, noisy.",
			Tactics: "Use for CTFs, internal labs, or when noise doesn't matter.",
			Timeout: 200 * time.Millisecond, Delay: 0, Threads: 2000, PortRange: "1-1024", Randomize: false},
		"titan": {
			ID: "titan", Name: "TITAN",
			Desc:    "Deep Audit. Scans ALL 65,535 ports.",
			Tactics: "Use for full vulnerability assessment. Takes time.",
			Timeout: 600 * time.Millisecond, Delay: 0, Threads: 800, PortRange: "1-65535", Randomize: false},
	}

	// --- CUSTOM HELP MENU DETAILLÉ ---
	flag.Usage = func() {
		printBanner("help")
		fmt.Printf("%sUSAGE:%s\n  ./argos -host <TARGET> [FLAGS]\n\n", ColorBold, ColorReset)

		fmt.Printf("%sTACTICAL GUIDE (WHICH MODE TO CHOOSE?):%s\n", ColorCyan, ColorReset)
		modeOrder := []string{"scout", "shadow", "blitz", "titan"}
		for _, key := range modeOrder {
			p := profiles[key]
			fmt.Printf("  %s%-8s%s : %s\n", ColorGreen, strings.ToUpper(p.ID), ColorReset, p.Desc)
			fmt.Printf("             %s→ %s%s\n\n", ColorGrey, p.Tactics, ColorReset)
		}

		fmt.Printf("%sEXAMPLES:%s\n", ColorCyan, ColorReset)
		fmt.Printf("  %s1. Quick Scan (Default)%s\n", ColorWhite, ColorReset)
		fmt.Printf("     argos -host 192.168.1.15\n\n")
		fmt.Printf("  %s2. Stealth Scan (Evasion / Red Team)%s\n", ColorWhite, ColorReset)
		fmt.Printf("     argos -host 10.10.10.5 -mode shadow\n\n")
		fmt.Printf("  %s3. Network Sweep (Find alive hosts fast)%s\n", ColorWhite, ColorReset)
		fmt.Printf("     argos -host 192.168.1.0/24 -mode blitz\n\n")
		fmt.Printf("  %s4. Full Audit (HTML/JSON Report)%s\n", ColorWhite, ColorReset)
		fmt.Printf("     argos -host 10.10.10.5 -mode titan -html report.html -json report.json\n\n")

		fmt.Printf("%sFLAGS:%s\n", ColorCyan, ColorReset)
		fmt.Printf("  -host    : Target IP or CIDR (e.g. 192.168.1.1 or 10.0.0.0/24)\n")
		fmt.Printf("  -mode    : Scan Profile (scout, shadow, blitz, titan)\n")
		fmt.Printf("  -html    : Generate HTML Intelligence Report (Dark Mode / Visuals)\n")
		fmt.Printf("  -json    : Export to JSON file\n")
		fmt.Printf("  -p       : Custom ports (e.g. 80,443). Overrides mode defaults.\n")
		fmt.Printf("  -random  : Shuffle ports (Anti-IDS).\n")
	}

	hostPtr := flag.String("host", "", "Target")
	portsPtr := flag.String("p", "default", "Ports")
	profilePtr := flag.String("mode", "scout", "Mode")
	shufflePtr := flag.Bool("random", false, "Randomize")
	jsonPtr := flag.String("json", "", "JSON Export")
	htmlPtr := flag.String("html", "", "HTML Report")
	dryRunPtr := flag.Bool("dry", false, "Dry Run")
	flag.Parse()

	if *hostPtr == "" {
		flag.Usage()
		return
	}

	// Config Mode
	modeKey := strings.ToLower(*profilePtr)
	if modeKey == "tytan" {
		modeKey = "titan"
	}

	prof, exists := profiles[modeKey]
	if !exists {
		prof = profiles["scout"]
		fmt.Printf("Mode inconnu, fallback Scout.\n")
	}

	printBanner(prof.ID)

	// Ports
	portStr := *portsPtr
	if portStr == "default" {
		portStr = prof.PortRange
	}
	ports, _ := parsePorts(portStr)
	if prof.Randomize || *shufflePtr {
		rand.Seed(time.Now().UnixNano())
		rand.Shuffle(len(ports), func(i, j int) { ports[i], ports[j] = ports[j], ports[i] })
	}

	ips, _ := parseTargets(*hostPtr)
	totalJobs := len(ips) * len(ports)

	fmt.Printf("%s[+] Mode    : %s%s\n", ColorCyan, prof.Name, ColorReset)
	fmt.Printf("%s[+] Threads : %d%s\n", ColorCyan, prof.Threads, ColorReset)
	fmt.Printf("%s[+] Targets : %d IP(s) x %d Ports%s\n", ColorGreen, len(ips), len(ports), ColorReset)
	if *htmlPtr != "" {
		fmt.Printf("%s[+] Report  : HTML Activated%s\n", ColorOrange, ColorReset)
	}
	fmt.Println(strings.Repeat("-", 60))

	if *dryRunPtr {
		return
	}

	// Execution
	jobs := make(chan ScanTarget, prof.Threads)
	results := make(chan *ScanResult, prof.Threads)
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	go func() { c := make(chan os.Signal, 1); signal.Notify(c, os.Interrupt); <-c; cancel() }()
	defer cancel()

	for i := 0; i < prof.Threads; i++ {
		wg.Add(1)
		go worker(ctx, jobs, results, &wg, prof)
	}

	go func() {
		for _, ip := range ips {
			for _, p := range ports {
				select {
				case <-ctx.Done():
					return
				case jobs <- ScanTarget{IP: ip, Port: p}:
				}
			}
		}
		close(jobs)
	}()
	go func() { wg.Wait(); close(results) }()

	// Collection
	var finalResults []ScanResult
	totalRisk := 0
	count := 0
	start := time.Now()

	for r := range results {
		count++
		if count%20 == 0 || count == totalJobs {
			updateProgressBar(count, totalJobs)
		}
		if r != nil {
			finalResults = append(finalResults, *r)
			totalRisk += r.RiskScore
		}
	}

	// Output
	fmt.Println()
	sort.Slice(finalResults, func(i, j int) bool { return finalResults[i].Port < finalResults[j].Port })

	fmt.Printf("%-16s %-8s %-12s %-30s\n", "IP", "PORT", "SERVICE", "INTELLIGENCE")
	fmt.Println(strings.Repeat("-", 75))

	for _, r := range finalResults {
		info := r.Banner
		color := ColorCyan

		if r.WebTitle != "" {
			info = fmt.Sprintf("Title: %s | Srv: %s", r.WebTitle, r.WebServer)
			color = ColorOrange
		} else if info == "" {
			info = "-"
		}
		if len(info) > 40 {
			info = info[:37] + "..."
		}

		portColor := ColorBold
		if r.RiskScore >= 20 {
			portColor = ColorRed
		}

		fmt.Printf("%s%-16s %-8d %-12s %s%s%s\n", portColor, r.IP, r.Port, r.Service, color, info, ColorReset)
	}

	printRiskBar(totalRisk)

	if *jsonPtr != "" {
		d, _ := json.MarshalIndent(finalResults, "", "  ")
		_ = os.WriteFile(*jsonPtr, d, 0644)
	}
	if *htmlPtr != "" {
		generateHTMLReport(*htmlPtr, finalResults)
	}

	fmt.Printf("\n[FIN] Scan terminé en %s.\n", time.Since(start))
}

// --- 8. HELPERS ---

func parseTargets(input string) ([]string, error) {
	if !strings.Contains(input, "/") {
		return []string{input}, nil
	}
	_, ipv4Net, err := net.ParseCIDR(input)
	if err != nil {
		return nil, err
	}
	var ips []string
	start := binary.BigEndian.Uint32(ipv4Net.IP)
	mask := binary.BigEndian.Uint32(ipv4Net.Mask)
	end := (start & mask) | (mask ^ 0xffffffff)
	for i := start + 1; i < end; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		ips = append(ips, ip.String())
	}
	return ips, nil
}

func parsePorts(s string) ([]int, error) {
	var p []int
	if s == "all" {
		for i := 1; i <= 65535; i++ {
			p = append(p, i)
		}
		return p, nil
	}
	parts := strings.Split(s, ",")
	for _, v := range parts {
		if strings.Contains(v, "-") {
			sp := strings.Split(v, "-")
			s, _ := strconv.Atoi(sp[0])
			e, _ := strconv.Atoi(sp[1])
			for i := s; i <= e; i++ {
				p = append(p, i)
			}
		} else {
			i, _ := strconv.Atoi(v)
			p = append(p, i)
		}
	}
	return p, nil
}
