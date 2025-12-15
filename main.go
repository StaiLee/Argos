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
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ---------------------------------------------------------
// CONFIGURATION & CONSTANTS
// ---------------------------------------------------------

const (
	// AppVersion denotes the current release build.
	AppVersion = "5.0.0"
	// AppName is the binary name.
	AppName = "ARGOS"
)

// CommonPorts maps standard TCP ports to their service names.
var CommonPorts = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
	110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
	3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
	8443: "HTTPS-Alt", 9000: "Portainer", 27017: "MongoDB",
}

// RiskWeights assigns a threat level to specific ports (higher is riskier).
var RiskWeights = map[int]int{
	21: 20, 23: 30, 445: 25, 3389: 15, 80: 5, 443: 0, 22: 5,
}

// ---------------------------------------------------------
// THEME ENGINE
// ---------------------------------------------------------

// Theme defines the color palette for the TUI.
type Theme struct {
	Primary   lipgloss.Color
	Secondary lipgloss.Color
	Dark      lipgloss.Color
	Text      lipgloss.Color
	Gradient  []string
}

// Pre-defined tactical themes.
var (
	ThemeBlitz = Theme{
		Primary:   lipgloss.Color("#FF2200"), // Neon Red
		Secondary: lipgloss.Color("#FF8800"), // Magma Orange
		Dark:      lipgloss.Color("#1a0500"),
		Text:      lipgloss.Color("#FFCC00"),
		Gradient:  []string{"#FF0000", "#FF4400", "#FF8800"},
	}
	ThemeTitan = Theme{
		Primary:   lipgloss.Color("#00FFFF"), // Cyan
		Secondary: lipgloss.Color("#0066FF"), // Electric Blue
		Dark:      lipgloss.Color("#00051a"),
		Text:      lipgloss.Color("#E0FFFF"),
		Gradient:  []string{"#0000FF", "#0088FF", "#00FFFF"},
	}
	ThemeShadow = Theme{
		Primary:   lipgloss.Color("#FFFFFF"), // Pure White
		Secondary: lipgloss.Color("#666666"), // Grey
		Dark:      lipgloss.Color("#111111"),
		Text:      lipgloss.Color("#AAAAAA"),
		Gradient:  []string{"#333333", "#888888", "#FFFFFF"},
	}
	ThemeScout = Theme{
		Primary:   lipgloss.Color("#00FF00"), // Matrix Green
		Secondary: lipgloss.Color("#004400"),
		Dark:      lipgloss.Color("#001100"),
		Text:      lipgloss.Color("#AAFFAA"),
		Gradient:  []string{"#003300", "#00AA00", "#00FF00"},
	}
)

// renderGradient applies a color gradient to a string.
func renderGradient(text string, colors []string) string {
	if len(text) == 0 {
		return ""
	}
	var s strings.Builder
	for i, char := range text {
		idx := int(float64(i) / float64(len(text)) * float64(len(colors)-1))
		s.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color(colors[idx])).Render(string(char)))
	}
	return s.String()
}

// ---------------------------------------------------------
// DATA STRUCTURES
// ---------------------------------------------------------

// ScanTarget represents a single unit of work (IP + Port).
type ScanTarget struct {
	IP   string
	Port int
}

// ScanResult holds the findings for a specific port.
type ScanResult struct {
	IP        string
	Service   string
	Banner    string // Raw banner from service
	WebTitle  string // HTML <title> tag
	WebServer string // HTTP Server header
	Port      int
	RiskScore int
	Timestamp time.Time
}

// ScanProfile defines the operational parameters (speed, stealth, theme).
type ScanProfile struct {
	ID        string
	Name      string
	Desc      string
	Timeout   time.Duration
	Delay     time.Duration
	Threads   int
	PortRange string
	Randomize bool
	DeepScan  bool // Enables banner grabbing
	Theme     Theme
}

// ---------------------------------------------------------
// UI MODEL: HELP / MANUAL
// ---------------------------------------------------------

type helpModel struct {
	pages         []string
	pageIdx       int
	width, height int
	quitting      bool
}

func initialHelpModel() helpModel { return helpModel{pages: buildPages(), pageIdx: 0} }
func (m helpModel) Init() tea.Cmd { return nil }

func (m helpModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "right", "l", "enter", " ":
			if m.pageIdx < len(m.pages)-1 {
				m.pageIdx++
			}
		case "left", "h", "backspace":
			if m.pageIdx > 0 {
				m.pageIdx--
			}
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}
	return m, nil
}

func (m helpModel) View() string {
	if m.quitting {
		return ""
	}
	content := m.pages[m.pageIdx]

	// Navigation Footer
	navStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#555"))
	activeDot := lipgloss.NewStyle().Foreground(ThemeTitan.Primary).Render("●")
	inactiveDot := lipgloss.NewStyle().Foreground(lipgloss.Color("#333")).Render("○")

	dots := ""
	for i := 0; i < len(m.pages); i++ {
		if i == m.pageIdx {
			dots += activeDot + " "
		} else {
			dots += inactiveDot + " "
		}
	}

	nav := fmt.Sprintf("\n%s\n%s", dots, navStyle.Render("[ARROWS] FLIP PAGE  •  [Q] EXIT SYSTEM"))

	frame := lipgloss.NewStyle().
		Border(lipgloss.DoubleBorder()).
		BorderForeground(ThemeTitan.Primary).
		Padding(1, 3).
		Width(90).
		Align(lipgloss.Center)

	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center,
		lipgloss.JoinVertical(lipgloss.Center, frame.Render(content), nav),
	)
}

func buildPages() []string {
	// Text Styles
	t := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFF")).Background(lipgloss.Color("#F06")).Padding(0, 1).Render
	h := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#0FF")).MarginTop(1).Render
	c := lipgloss.NewStyle().Foreground(lipgloss.Color("#0F0")).Background(lipgloss.Color("#222")).Padding(0, 1).Render
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("#666")).Render

	// PAGE 1: COVER
	p1 := fmt.Sprintf(`
%s

ARGOS v%s
by StaiLee

%s
%s

"The giant with a hundred eyes."
`, renderGradient("/// CLASSIFIED MILITARY GRADE SOFTWARE ///", ThemeBlitz.Gradient),
		AppVersion,
		dim("Authorized Personnel Only"),
		dim("System Ready."))

	// PAGE 2: ARCHITECTURE
	p2 := fmt.Sprintf(`
%s

Argos utilizes a massive concurrent architecture based on Golang Goroutines.
Unlike traditional threaded scanners, it spawns thousands of micro-threads.

%s
1. %s : Generates targets (IP:Port) into a buffered channel.
2. %s : Connects and performs TCP Handshake.
3. %s : (New) If Deep Scan is on, waits for banners or sends probes.
4. %s : Analyzes Banner, HTTP Headers, and calculates Risk Score.

%s
Argos performs a full TCP Connect Scan.
SYN-ACK = Open. RST = Closed. Timeout = Filtered.
`, t("SYSTEM ARCHITECTURE"), h("WORKFLOW"), c("Feeder"), c("Worker Pool"), c("Identity Module"), c("The Oracle"), h("NETWORK PROTOCOL"))

	// PAGE 3: MODES
	p3 := fmt.Sprintf(`
%s

%s
%s
Target: Initial Recon / Daily Checks.
Specs:  Balanced speed. Top 1024 ports.

%s
%s
Target: Red Teaming / Evasion.
Specs:  Slow, Randomized Jitter, Anti-IDS.

%s
%s
Target: CTF / Internal Networks.
Specs:  MAX SPEED (2000 threads). Fire at will.

%s
%s
Target: Full Audits.
Specs:  Deep Scan (65,535 ports). Heavy load.
`, t("TACTICAL PROFILES"),
		h("1. SCOUT"), c("-mode scout"),
		h("2. SHADOW"), c("-mode shadow"),
		h("3. BLITZ"), c("-mode blitz"),
		h("4. TITAN"), c("-mode titan"))

	// PAGE 4: FLAGS
	p4 := fmt.Sprintf(`
%s

%s
The target address. Supports IP (1.1.1.1) or CIDR (10.0.0.0/24).

%s
Select operational profile: scout, shadow, blitz, titan.

%s
Enable Active Service Fingerprinting (Banner Grabbing).
Significantly slower but provides version details (SSH, HTTP, FTP).

%s
Define custom ports. Examples: %s, %s, %s.

%s
Randomize scan order to reduce detection risk (Anti-IDS).

%s
Export intelligence to external files.
`,
		t("MISSION PARAMETERS (FLAGS)"),
		c("-host <TARGET>"),
		c("-mode <PROFILE>"),
		c("-deep"),
		c("-p <RANGE>"), c("80,443"), c("1-1024"), c("all"),
		c("-random"),
		c("-html <FILE> / -json <FILE>"))

	// PAGE 5: ADVANCED USAGE
	p5 := fmt.Sprintf(`
%s

%s
Attempt to identify Service Versions (SSH, FTP, HTTP versions):
%s

%s
Find all web servers on a subnet in seconds:
%s

%s
Scan a specific server slowly to avoid detection:
%s

%s
Generate a client-ready HTML report with full details:
%s
`, t("ADVANCED OPERATIONS"),
		h("DEEP IDENTITY SCAN"), c("argos -host 10.10.10.5 -deep"),
		h("SUBNET SWEEP"), c("argos -host 192.168.1.0/24 -p 80,443 -mode blitz"),
		h("STEALTH MISSION"), c("argos -host 10.10.10.5 -mode shadow -p 1-5000"),
		h("REPORTING"), c("argos -host target.ip -mode titan -html report.html"))

	// PAGE 6: DISCLAIMER
	p6 := fmt.Sprintf(`
%s

Argos is intended for %s and %s purposes only.
Scanning networks without permission is illegal.

The developers assume no liability for misuse of this tool.

%s
`, t("LEGAL DISCLAIMER"), c("educational"), c("authorized testing"), dim("© 2025 Argos Project"))

	return []string{p1, p2, p3, p4, p5, p6}
}

// ---------------------------------------------------------
// UI MODEL: MAIN DASHBOARD
// ---------------------------------------------------------

type tickMsg time.Time

type scanModel struct {
	results       []ScanResult
	resultsChan   chan *ScanResult
	viewport      viewport.Model
	spinner       spinner.Model
	totalJobs     int
	completed     int
	width, height int
	finished      bool
	quitting      bool
	startTime     time.Time
	profile       ScanProfile
	targetStr     string
	theme         Theme
	countCritical int
	countHigh     int
	countLow      int
	logBuffer     string

	// Telemetry Data
	sparkline  []int
	goroutines int
	ramUsage   string
	localIP    string
}

type scanResultMsg *ScanResult
type scanFinishedMsg struct{}

// initialScanModel sets up the initial state of the TUI.
func initialScanModel(rChan chan *ScanResult, total int, prof ScanProfile, target string) scanModel {
	s := spinner.New()
	s.Spinner = spinner.Pulse
	s.Style = lipgloss.NewStyle().Foreground(prof.Theme.Primary)
	vp := viewport.New(0, 0)

	locIP := "127.0.0.1"
	// Attempt to determine outbound IP
	if conn, err := net.Dial("udp", "8.8.8.8:80"); err == nil {
		locIP = conn.LocalAddr().(*net.UDPAddr).IP.String()
		conn.Close()
	}

	return scanModel{
		results:     make([]ScanResult, 0),
		resultsChan: rChan,
		spinner:     s,
		viewport:    vp,
		totalJobs:   total,
		completed:   0,
		startTime:   time.Now(),
		profile:     prof,
		targetStr:   target,
		theme:       prof.Theme,
		sparkline:   make([]int, 30),
		localIP:     locIP,
	}
}

func waitForResult(sub chan *ScanResult) tea.Cmd {
	return func() tea.Msg {
		res, ok := <-sub
		if !ok {
			return scanFinishedMsg{}
		}
		return scanResultMsg(res)
	}
}

func tickCmd() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// ---------------------------------------------------------
// APPLICATION LOGIC (UPDATE LOOP)
// ---------------------------------------------------------

func (m scanModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, waitForResult(m.resultsChan), tickCmd())
}

func (m scanModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "q" || msg.Type == tea.KeyCtrlC {
			m.quitting = true
			return m, tea.Quit
		}
		var cmd tea.Cmd
		m.viewport, cmd = m.viewport.Update(msg)
		return m, cmd

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		h := m.height - 9
		if h < 10 {
			h = 10
		}
		m.viewport.Width = int(float64(m.width) * 0.60)
		m.viewport.Height = h
		return m, nil

	case spinner.TickMsg:
		if m.finished {
			return m, nil
		}
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case tickMsg:
		// Update Telemetry
		activity := 0
		if m.completed > 0 && !m.finished {
			activity = rand.Intn(3)
		}
		m.sparkline = append(m.sparkline[1:], activity)

		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		m.ramUsage = fmt.Sprintf("%d MB", mem.Alloc/1024/1024)
		m.goroutines = runtime.NumGoroutine()

		if !m.finished {
			return m, tickCmd()
		}
		return m, nil

	case scanResultMsg:
		m.completed++
		var cmds []tea.Cmd
		if msg != nil {
			m.results = append(m.results, *msg)
			// Risk Scoring logic
			if (*msg).RiskScore >= 20 {
				m.countCritical++
			} else if (*msg).RiskScore >= 10 {
				m.countHigh++
			} else {
				m.countLow++
			}

			// Visual feedback on sparkline
			m.sparkline[len(m.sparkline)-1] = 8

			// Log formatting
			line := formatLogLine(*msg, m.theme)
			m.logBuffer += line + "\n"
			m.viewport.SetContent(m.logBuffer)
			m.viewport.GotoBottom()
		}
		cmds = append(cmds, waitForResult(m.resultsChan))
		return m, tea.Batch(cmds...)

	case scanFinishedMsg:
		m.finished = true
		return m, nil
	}
	return m, nil
}

// ---------------------------------------------------------
// RENDER LOGIC (VIEW)
// ---------------------------------------------------------

// renderCustomBar draws a progress bar manually to ensure color accuracy.
func renderCustomBar(width int, pct float64, c lipgloss.Color) string {
	if pct > 1.0 {
		pct = 1.0
	}
	wFilled := int(float64(width) * pct)
	if wFilled < 0 {
		wFilled = 0
	}
	wEmpty := width - wFilled
	if wEmpty < 0 {
		wEmpty = 0
	}

	filled := strings.Repeat("█", wFilled)
	empty := strings.Repeat("░", wEmpty)

	return lipgloss.NewStyle().Foreground(c).Render(filled) + lipgloss.NewStyle().Foreground(lipgloss.Color("#333")).Render(empty)
}

func (m scanModel) View() string {
	if m.quitting {
		return ""
	}

	cPrim := m.theme.Primary
	cSec := m.theme.Secondary
	cDark := m.theme.Dark

	// Dynamic Border Color
	border := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(cSec)
	if m.finished {
		border = border.BorderForeground(cPrim)
	}

	// 1. Header
	headTxt := fmt.Sprintf(" %s %s │ OPERATION: %s ", AppName, AppVersion, m.profile.Name)
	title := renderGradient(headTxt, m.theme.Gradient)
	header := border.Copy().Width(m.width - 2).Align(lipgloss.Center).Render(title)

	// Layout Calculation
	leftW := int(float64(m.width) * 0.30)
	rightW := m.width - leftW - 6

	// Styles
	lbl := lipgloss.NewStyle().Foreground(cPrim).Bold(true).Render
	val := lipgloss.NewStyle().Foreground(m.theme.Text).Render
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("#444")).Render

	// Metrics Calculation
	elapsed := time.Since(m.startTime).Round(time.Second)
	rate := 0.0
	if time.Since(m.startTime).Seconds() > 0 {
		rate = float64(m.completed) / time.Since(m.startTime).Seconds()
	}

	eta := "CALC..."
	if rate > 0 {
		rem := time.Duration(int(float64(m.totalJobs-m.completed)/rate)) * time.Second
		eta = rem.String()
	}
	if m.finished {
		eta = "0s"
	}

	// Sparkline Construction
	spark := ""
	bars := []string{" ", "▂", "▃", "▄", "▅", "▆", "▇", "█"}
	for _, v := range m.sparkline {
		if v >= len(bars) {
			v = len(bars) - 1
		}
		spark += bars[v]
	}
	sparkRender := lipgloss.NewStyle().Foreground(cSec).Render(spark)

	// 2. Left Panel (Telemetry)
	blockTarget := lipgloss.JoinVertical(lipgloss.Left,
		lbl("TARGET IDENTITY"),
		val(m.targetStr),
		dim("Deep Scan: "+strconv.FormatBool(m.profile.DeepScan)))

	blockTime := lipgloss.JoinVertical(lipgloss.Left,
		lbl("MISSION CLOCK"),
		val(elapsed.String()),
		dim("ETA: "+eta))

	blockProgress := lipgloss.JoinVertical(lipgloss.Left,
		lbl("PROGRESSION"),
		val(fmt.Sprintf("%d/%d", m.completed, m.totalJobs)),
		dim(fmt.Sprintf("%.0f p/s", rate)))

	blockSys := lipgloss.JoinVertical(lipgloss.Left,
		lbl("SYSTEM DIAGNOSTICS"),
		val(fmt.Sprintf("RAM: %s", m.ramUsage)),
		val(fmt.Sprintf("GRT: %d", m.goroutines)),
		val(fmt.Sprintf("IP : %s", m.localIP)))

	// Risk Gauges
	totRisk := float64(m.countCritical + m.countHigh + m.countLow)
	if totRisk == 0 {
		totRisk = 1
	}
	lenCrit := int((float64(m.countCritical) / totRisk) * 10)
	lenHigh := int((float64(m.countHigh) / totRisk) * 10)
	lenLow := int((float64(m.countLow) / totRisk) * 10)

	blockRisk := lipgloss.JoinVertical(lipgloss.Left,
		lbl("THREAT INTEL"),
		fmt.Sprintf("%s %s %d", lipgloss.NewStyle().Foreground(lipgloss.Color("#F00")).Render("CRT"), strings.Repeat("█", lenCrit), m.countCritical),
		fmt.Sprintf("%s %s %d", lipgloss.NewStyle().Foreground(lipgloss.Color("#FA0")).Render("HGH"), strings.Repeat("█", lenHigh), m.countHigh),
		fmt.Sprintf("%s %s %d", lipgloss.NewStyle().Foreground(lipgloss.Color("#0F0")).Render("LOW"), strings.Repeat("█", lenLow), m.countLow),
	)

	leftContent := lipgloss.JoinVertical(lipgloss.Left,
		blockTarget, "\n", blockTime, "\n", blockProgress, "\n", blockRisk, "\n", blockSys, "\n", lbl("NET ACTIVITY"), sparkRender,
	)

	leftP := border.Copy().Width(leftW).Height(m.viewport.Height).Background(cDark).Padding(1, 2).Render(leftContent)

	// 3. Right Panel (Logs)
	rightP := border.Copy().Width(rightW).Height(m.viewport.Height).Render(m.viewport.View())

	// 4. Footer & Progress Bar
	spin := m.spinner.View()
	msg := "SCANNING..."
	if m.finished {
		spin = "✅"
		msg = "MISSION ACCOMPLIE."
	}

	barWidth := m.width - 40
	pct := float64(m.completed) / float64(m.totalJobs)
	barRender := renderCustomBar(barWidth, pct, cPrim)
	pctText := fmt.Sprintf("%.0f%%", pct*100)

	inf := lipgloss.JoinHorizontal(lipgloss.Center,
		lipgloss.NewStyle().Width(4).Render(spin),
		lipgloss.NewStyle().Foreground(m.theme.Text).Width(25).Render(msg),
		barRender,
		lipgloss.NewStyle().Width(6).Align(lipgloss.Right).Foreground(cPrim).Render(pctText),
	)
	foot := border.Copy().Width(m.width - 2).Render(
		lipgloss.JoinVertical(lipgloss.Center, inf, lipgloss.NewStyle().Foreground(lipgloss.Color("#555")).Render("[Q] DISCONNECT   [ARROWS] SCROLL FEED")),
	)

	return lipgloss.JoinVertical(lipgloss.Left, header, lipgloss.JoinHorizontal(lipgloss.Top, leftP, rightP), foot)
}

func formatLogLine(r ScanResult, t Theme) string {
	ts := r.Timestamp.Format("15:04:05.000")
	tsStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#444")).Render(ts)

	icon := "[TCP]"
	style := lipgloss.NewStyle().Foreground(t.Secondary)

	// Append banner info if available
	infoText := r.Service
	if r.Banner != "" {
		// Clean banner (remove newlines, trim)
		cleanBanner := strings.ReplaceAll(r.Banner, "\n", " ")
		cleanBanner = strings.ReplaceAll(cleanBanner, "\r", "")
		if len(cleanBanner) > 30 {
			cleanBanner = cleanBanner[:30] + "..."
		}
		infoText += " | " + cleanBanner
	}

	// Threat styling
	if r.RiskScore >= 20 {
		icon = "[CRT]"
		style = style.Copy().Foreground(lipgloss.Color("#FF0000")).Bold(true)
	} else if r.WebTitle != "" {
		icon = "[WEB]"
		style = style.Copy().Foreground(t.Primary)
		infoText += " | " + r.WebTitle
	}

	info := fmt.Sprintf("%-16s:%-5d", r.IP, r.Port)

	return fmt.Sprintf("%s %s %s %s",
		tsStyle,
		style.Render(icon),
		lipgloss.NewStyle().Foreground(lipgloss.Color("#EEE")).Render(info),
		lipgloss.NewStyle().Foreground(t.Primary).Render(infoText),
	)
}

// ---------------------------------------------------------
// WORKERS & IDENTITY ENGINE (NETWORK LAYER)
// ---------------------------------------------------------

// probeHTTP attempts to fetch web headers and title.
func probeHTTP(ip string, port int, timeout time.Duration) (string, string) {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d", scheme, ip, port)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: timeout + 500*time.Millisecond}

	// ACTIVE PROBE: HEAD Request to get headers without body
	resp, err := client.Head(url)
	if err != nil {
		// Fallback to GET if HEAD fails
		resp, err = client.Get(url)
		if err != nil {
			return "", ""
		}
	}
	defer resp.Body.Close()

	srv := resp.Header.Get("Server")
	if srv == "" {
		srv = "Unknown Web Server"
	}

	// Fetch a small chunk of body for title if possible
	title := "No Title"
	if resp.Request.Method == "GET" {
		buf := make([]byte, 2048)
		n, _ := io.ReadFull(resp.Body, buf)
		re := regexp.MustCompile(`(?i)<title>(.*?)</title>`)
		matches := re.FindStringSubmatch(string(buf[:n]))
		if len(matches) > 1 {
			title = strings.TrimSpace(matches[1])
		}
	}

	return title, srv
}

// grabBanner attempts to read the initial server greeting (for SSH, FTP, etc).
func grabBanner(ip string, port int, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(2 * time.Second)) // Wait 2s for greeting
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}

	// Filter non-printable characters
	banner := string(buf[:n])
	return strings.Map(func(r rune) rune {
		if r >= 32 && r <= 126 {
			return r
		}
		return -1
	}, banner)
}

// scanPort performs the actual TCP connection and optional deep scanning.
func scanPort(ctx context.Context, target ScanTarget, timeout time.Duration, deep bool) *ScanResult {
	select {
	case <-ctx.Done():
		return nil
	default:
	}

	// 1. Basic Connect Scan
	addr := net.JoinHostPort(target.IP, strconv.Itoa(target.Port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil
	}
	conn.Close() // Close initial check connection

	svc := CommonPorts[target.Port]
	if svc == "" {
		svc = "TCP"
	}
	risk := RiskWeights[target.Port]
	if risk == 0 {
		risk = 1
	}
	banner := ""
	wTitle, wSrv := "", ""

	// 2. DEEP SCAN (Identity Module)
	if deep {
		// Identify Web Services
		if target.Port == 80 || target.Port == 443 || target.Port == 8080 || target.Port == 8443 {
			wTitle, wSrv = probeHTTP(target.IP, target.Port, timeout)
			if wSrv != "" {
				banner = wSrv
			}
		} else {
			// Identify Generic TCP Services (SSH, FTP...)
			banner = grabBanner(target.IP, target.Port, timeout)
		}
	}

	return &ScanResult{
		IP:        target.IP,
		Port:      target.Port,
		Service:   svc,
		Banner:    banner,
		WebTitle:  wTitle,
		WebServer: wSrv,
		RiskScore: risk,
		Timestamp: time.Now(),
	}
}

// worker acts as a consumer for the jobs channel.
func worker(ctx context.Context, jobs <-chan ScanTarget, results chan<- *ScanResult, wg *sync.WaitGroup, prof ScanProfile) {
	defer wg.Done()
	for target := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
			if prof.Delay > 0 {
				time.Sleep(time.Duration(rand.Intn(int(prof.Delay))))
			}
			// Execute scan with profile settings
			res := scanPort(ctx, target, prof.Timeout, prof.DeepScan)
			results <- res
		}
	}
}

// ---------------------------------------------------------
// MAIN EXECUTION
// ---------------------------------------------------------

func main() {
	// Define Scan Profiles
	profiles := map[string]ScanProfile{
		"scout":  {ID: "scout", Name: "SCOUT", Timeout: 500 * time.Millisecond, Threads: 500, PortRange: "1-1024", Theme: ThemeScout},
		"shadow": {ID: "shadow", Name: "SHADOW", Timeout: 2000 * time.Millisecond, Delay: 1500 * time.Millisecond, Threads: 10, PortRange: "1-1000", Randomize: true, Theme: ThemeShadow},
		"blitz":  {ID: "blitz", Name: "BLITZ", Timeout: 200 * time.Millisecond, Threads: 2000, PortRange: "1-1024", Theme: ThemeBlitz},
		"titan":  {ID: "titan", Name: "TITAN", Timeout: 600 * time.Millisecond, Threads: 800, PortRange: "1-65535", Theme: ThemeTitan},
	}

	// Parse Command Line Flags
	hostPtr := flag.String("host", "", "Target IP or CIDR range")
	profilePtr := flag.String("mode", "scout", "Scan profile (scout, shadow, blitz, titan)")
	jsonPtr := flag.String("json", "", "Output results to JSON file")
	htmlPtr := flag.String("html", "", "Output results to HTML report")
	deepPtr := flag.Bool("deep", false, "Enable Deep Service Identity Scan (Slow)")
	flag.Parse()

	// Show Help if no host is provided
	if *hostPtr == "" {
		p := tea.NewProgram(initialHelpModel(), tea.WithAltScreen())
		if _, err := p.Run(); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		return
	}

	// Setup Profile
	modeKey := strings.ToLower(*profilePtr)
	if modeKey == "tytan" {
		modeKey = "titan"
	}
	prof, exists := profiles[modeKey]
	if !exists {
		prof = profiles["scout"]
	}

	// Inject Flags into Profile
	prof.DeepScan = *deepPtr

	// Target Generation
	ports, _ := parsePorts(prof.PortRange)
	ips, _ := parseTargets(*hostPtr)
	if prof.Randomize {
		rand.Seed(time.Now().UnixNano())
		rand.Shuffle(len(ports), func(i, j int) { ports[i], ports[j] = ports[j], ports[i] })
	}
	totalJobs := len(ips) * len(ports)

	// Concurrency Channels
	jobs := make(chan ScanTarget, prof.Threads)
	results := make(chan *ScanResult, prof.Threads)
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Spawn Workers
	for i := 0; i < prof.Threads; i++ {
		wg.Add(1)
		go worker(ctx, jobs, results, &wg, prof)
	}

	// Job Feeder
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
		wg.Wait()
		close(results)
	}()

	// Start UI
	p := tea.NewProgram(initialScanModel(results, totalJobs, prof, *hostPtr), tea.WithAltScreen())
	finalModel, err := p.Run()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Post-Scan Reporting
	if m, ok := finalModel.(scanModel); ok {
		if *jsonPtr != "" {
			d, _ := json.MarshalIndent(m.results, "", "  ")
			_ = os.WriteFile(*jsonPtr, d, 0644)
		}
		if *htmlPtr != "" {
			generateHTMLReport(*htmlPtr, m.results)
		}
		// Final Clean Output
		s := lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Bold(true)
		fmt.Println(s.Render(fmt.Sprintf("\n[+] SESSION CLOSED. %d ports identified on %s.\n", len(m.results), *hostPtr)))
	}
}

// ---------------------------------------------------------
// UTILITIES & HELPERS
// ---------------------------------------------------------

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

func generateHTMLReport(filename string, results []ScanResult) {
	f, _ := os.Create(filename)
	defer f.Close()
	f.WriteString("<html><body style='background:#111;color:#0f0'><h1>ARGOS REPORT</h1><ul>")
	for _, r := range results {
		f.WriteString(fmt.Sprintf("<li>%s:%d (%s)</li>", r.IP, r.Port, r.Service))
	}
	f.WriteString("</ul></body></html>")

	s := lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Bold(true)
	fmt.Println(s.Render(fmt.Sprintf("[✓] HTML Report saved: %s", filename)))
}
