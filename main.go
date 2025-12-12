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

// --- 1. CONFIGURATION ---

const (
	AppVersion = "5.0.0(OMEGA)"
	AppName    = "ARGOS PANOPTES"
	ColorReset = "\033[0m"
	ColorGreen = "\033[32m"
)

var CommonPorts = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
	110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
	3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
	8443: "HTTPS-Alt", 9000: "Portainer", 27017: "MongoDB",
}

var RiskWeights = map[int]int{
	21: 20, 23: 30, 445: 25, 3389: 15, 80: 5, 443: 0, 22: 5,
}

// --- 2. THEMES ---

type Theme struct {
	Primary   lipgloss.Color
	Secondary lipgloss.Color
	Dark      lipgloss.Color
	Text      lipgloss.Color
	Gradient  []string
}

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

// --- 3. STRUCTURES ---

type ScanTarget struct {
	IP   string
	Port int
}
type ScanResult struct {
	IP, Service, Banner, WebTitle, WebServer string
	Port, RiskScore                          int
	Timestamp                                time.Time
}
type ScanProfile struct {
	ID, Name, Desc string
	Timeout, Delay time.Duration
	Threads        int
	PortRange      string
	Randomize      bool
	Theme          Theme
}

// --- 4. HELP MODEL (LE MANUEL ULTIME) ---

type helpModel struct {
	pages                  []string
	pageIdx, width, height int
	quitting               bool
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

	frame := lipgloss.NewStyle().Border(lipgloss.DoubleBorder()).BorderForeground(ThemeTitan.Primary).Padding(1, 3).Width(90).Align(lipgloss.Center)
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, lipgloss.JoinVertical(lipgloss.Center, frame.Render(content), nav))
}

func buildPages() []string {
	// Styles
	t := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFF")).Background(lipgloss.Color("#F06")).Padding(0, 1).Render
	h := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#0FF")).MarginTop(1).Render
	c := lipgloss.NewStyle().Foreground(lipgloss.Color("#0F0")).Background(lipgloss.Color("#222")).Padding(0, 1).Render
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("#666")).Render

	// PAGE 1: COVER
	p1 := fmt.Sprintf(`
%s

ARGOS PANOPTES by StaiLee
   

%s
%s

"The giant with a hundred eyes."
`, renderGradient("/// SIERRA TANGO ALPHA INDIA OMEGA ///", ThemeBlitz.Gradient),
		dim("Authorized Personnel Only"),
		dim("System Ready."))

	// PAGE 2: ARCHITECTURE
	p2 := fmt.Sprintf(`
%s

Argos utilizes a massive concurrent architecture based on Golang Goroutines.
Unlike traditional threaded scanners, it spawns thousands of micro-threads.

%s
1. %s : Generates targets (IP:Port) into a buffered channel.
2. %s : Consume targets and execute TCP Handshake.
3. %s : Analyzes Banner, HTTP Headers, and calculates Risk Score.
4. %s : Renders the TUI Dashboard in real-time.

%s
Argos performs a full TCP Connect Scan (Syscall connect()).
SYN-ACK = Open. RST = Closed. Timeout = Filtered.
`, t("SYSTEM ARCHITECTURE"), h("WORKFLOW"), c("Feeder"), c("Worker Pool"), c("The Oracle"), c("UI Engine"), h("NETWORK PROTOCOL"))

	// PAGE 3: MODES
	p3 := fmt.Sprintf(`
%s

%s
%s
Target: Initial Recon / Daily Checks.
Specs:  Balanced speed (500 threads). Default config.

%s
%s
Target: Red Teaming / Evasion.
Specs:  Slow, Randomized Jitter (0-1.5s), Anti-IDS Shuffling.
Color:  Ghost White.

%s
%s
Target: CTF / Internal Networks / Destruction.
Specs:  MAX SPEED (2000 threads), No Delay. Fire at will.
Color:  Neon Red.

%s
%s
Target: Full Audits.
Specs:  Deep Scan (65,535 ports). Heavy load.
Color:  Cyan.
`, t("TACTICAL PROFILES"),
		h("1. SCOUT"), c("-mode scout"),
		h("2. SHADOW (Stealth)"), c("-mode shadow"),
		h("3. BLITZ (Aggressive)"), c("-mode blitz"),
		h("4. TITAN (Audit)"), c("-mode titan"))

	// PAGE 4: ADVANCED USAGE
	p4 := fmt.Sprintf(`
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

%s
Randomize port order to bypass simple firewall rules:
%s
`, t("ADVANCED OPERATIONS"),
		h("SUBNET SWEEP"), c("argos -host 192.168.1.0/24 -p 80,443,8080 -mode blitz"),
		h("STEALTH MISSION"), c("argos -host 10.10.10.5 -mode shadow -p 1-5000"),
		h("FULL AUDIT"), c("argos -host 10.10.50.2 -mode titan -html report.html"),
		h("EVASION"), c("argos -host <IP> -random -mode shadow"))

	// PAGE 5: DISCLAIMER
	p5 := fmt.Sprintf(`
%s

Argos is intended for %s and %s purposes only.
Scanning networks without permission is illegal.

The developers assume no liability for misuse of this tool.

%s
`, t("LEGAL DISCLAIMER"), c("educational"), c("authorized testing"), dim("© 2025 Argos Project"))

	return []string{p1, p2, p3, p4, p5}
}

// --- 5. SCAN MODEL ---

type tickMsg time.Time

type scanModel struct {
	results                             []ScanResult
	resultsChan                         chan *ScanResult
	viewport                            viewport.Model
	spinner                             spinner.Model
	totalJobs, completed, width, height int
	finished, quitting                  bool
	startTime                           time.Time
	profile                             ScanProfile
	targetStr                           string
	theme                               Theme
	countCritical, countHigh, countLow  int
	logBuffer                           string

	// Real Telemetry
	sparkline  []int
	goroutines int
	ramUsage   string
	localIP    string
}

type scanResultMsg *ScanResult
type scanFinishedMsg struct{}

func initialScanModel(rChan chan *ScanResult, total int, prof ScanProfile, target string) scanModel {
	// CUSTOM SPINNER & VIEWPORT
	s := spinner.New()
	s.Spinner = spinner.Pulse
	s.Style = lipgloss.NewStyle().Foreground(prof.Theme.Primary)
	vp := viewport.New(0, 0)

	locIP := "127.0.0.1"
	if conn, err := net.Dial("udp", "8.8.8.8:80"); err == nil {
		locIP = conn.LocalAddr().(*net.UDPAddr).IP.String()
		conn.Close()
	}

	return scanModel{
		results: make([]ScanResult, 0), resultsChan: rChan, spinner: s, viewport: vp,
		totalJobs: total, completed: 0, startTime: time.Now(), profile: prof, targetStr: target, theme: prof.Theme,
		sparkline: make([]int, 30), localIP: locIP,
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

// --- 6. LOGIC ---

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
		// TELEMETRIE
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
			if (*msg).RiskScore >= 20 {
				m.countCritical++
			} else if (*msg).RiskScore >= 10 {
				m.countHigh++
			} else {
				m.countLow++
			}

			// Boost sparkline
			m.sparkline[len(m.sparkline)-1] = 8

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

// --- 7. VIEW (UI GOD MODE) ---

// Custom Bar Renderer (Correction Couleur & Fluidité)
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

	border := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(cSec)
	if m.finished {
		border = border.BorderForeground(cPrim)
	}

	// HEADER
	headTxt := fmt.Sprintf(" ARGOS %s │ OPERATION: %s ", AppVersion, m.profile.Name)
	title := renderGradient(headTxt, m.theme.Gradient)
	header := border.Copy().Width(m.width - 2).Align(lipgloss.Center).Render(title)

	// LAYOUT
	leftW := int(float64(m.width) * 0.30)
	rightW := m.width - leftW - 6

	// LEFT PANEL (TELEMETRY)
	lbl := lipgloss.NewStyle().Foreground(cPrim).Bold(true).Render
	val := lipgloss.NewStyle().Foreground(m.theme.Text).Render
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("#444")).Render

	elapsed := time.Since(m.startTime).Round(time.Second)
	rate := 0.0
	if time.Since(m.startTime).Seconds() > 0 {
		rate = float64(m.completed) / time.Since(m.startTime).Seconds()
	}

	eta := "CALCULATING..."
	if rate > 0 {
		rem := time.Duration(int(float64(m.totalJobs-m.completed)/rate)) * time.Second
		eta = rem.String()
	}
	if m.finished {
		eta = "0s"
	}

	// Sparkline Render
	spark := ""
	bars := []string{" ", "▂", "▃", "▄", "▅", "▆", "▇", "█"}
	for _, v := range m.sparkline {
		if v >= len(bars) {
			v = len(bars) - 1
		}
		spark += bars[v]
	}
	sparkRender := lipgloss.NewStyle().Foreground(cSec).Render(spark)

	// Panel Assembly
	blockTarget := lipgloss.JoinVertical(lipgloss.Left,
		lbl("TARGET IDENTITY"), val(m.targetStr), dim("Scanning Protocols Active"))

	blockTime := lipgloss.JoinVertical(lipgloss.Left,
		lbl("MISSION CLOCK"), val(elapsed.String()), dim("ETA: "+eta))

	blockProgress := lipgloss.JoinVertical(lipgloss.Left,
		lbl("PROGRESSION"), val(fmt.Sprintf("%d/%d", m.completed, m.totalJobs)), dim(fmt.Sprintf("%.0f packets/sec", rate)))

	blockSys := lipgloss.JoinVertical(lipgloss.Left,
		lbl("SYSTEM DIAGNOSTICS"),
		val(fmt.Sprintf("RAM: %s", m.ramUsage)),
		val(fmt.Sprintf("GRT: %d", m.goroutines)),
		val(fmt.Sprintf("IP : %s", m.localIP)))

	// Barres de risque
	totRisk := float64(m.countCritical + m.countHigh + m.countLow)
	if totRisk == 0 {
		totRisk = 1
	}
	lenCrit := int((float64(m.countCritical) / totRisk) * 10)
	lenHigh := int((float64(m.countHigh) / totRisk) * 10)
	lenLow := int((float64(m.countLow) / totRisk) * 10)

	blockRisk := lipgloss.JoinVertical(lipgloss.Left,
		lbl("THREAT INTELLIGENCE"),
		fmt.Sprintf("%s %s %d", lipgloss.NewStyle().Foreground(lipgloss.Color("#F00")).Render("CRT"), strings.Repeat("█", lenCrit), m.countCritical),
		fmt.Sprintf("%s %s %d", lipgloss.NewStyle().Foreground(lipgloss.Color("#FA0")).Render("HGH"), strings.Repeat("█", lenHigh), m.countHigh),
		fmt.Sprintf("%s %s %d", lipgloss.NewStyle().Foreground(lipgloss.Color("#0F0")).Render("LOW"), strings.Repeat("█", lenLow), m.countLow),
	)

	leftContent := lipgloss.JoinVertical(lipgloss.Left,
		blockTarget, "\n", blockTime, "\n", blockProgress, "\n", blockRisk, "\n", blockSys, "\n", lbl("NET ACTIVITY"), sparkRender,
	)

	leftP := border.Copy().Width(leftW).Height(m.viewport.Height).Background(cDark).Padding(1, 2).Render(leftContent)

	// RIGHT PANEL (LOGS)
	rightP := border.Copy().Width(rightW).Height(m.viewport.Height).Render(m.viewport.View())

	// FOOTER
	spin := m.spinner.View()
	msg := "SCANNING SECTORS..."
	if m.finished {
		spin = "✅"
		msg = "MISSION ACCOMPLIE."
	}

	// BARRE DE PROGRESSION CUSTOM
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

	if r.RiskScore >= 20 {
		icon = "[CRT]"
		style = style.Copy().Foreground(lipgloss.Color("#FF0000")).Bold(true)
	} else if r.WebTitle != "" {
		icon = "[WEB]"
		style = style.Copy().Foreground(t.Primary)
	}

	info := fmt.Sprintf("%-16s:%-5d", r.IP, r.Port)
	srv := fmt.Sprintf("%s", r.Service)
	extra := ""
	if r.WebTitle != "" {
		extra = " │ " + r.WebTitle
	}

	return fmt.Sprintf("%s %s %s %s%s",
		tsStyle,
		style.Render(icon),
		lipgloss.NewStyle().Foreground(lipgloss.Color("#EEE")).Render(info),
		lipgloss.NewStyle().Foreground(t.Text).Faint(true).Render(srv),
		lipgloss.NewStyle().Foreground(t.Primary).Render(extra),
	)
}

// --- 8. WORKERS ---

func probeHTTP(ip string, port int, timeout time.Duration) (string, string) {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d", scheme, ip, port)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: timeout + 500*time.Millisecond}
	resp, err := client.Get(url)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	srv := resp.Header.Get("Server")
	if srv == "" {
		srv = "Hidden"
	}
	buf := make([]byte, 2048)
	n, _ := io.ReadFull(resp.Body, buf)
	re := regexp.MustCompile(`(?i)<title>(.*?)</title>`)
	matches := re.FindStringSubmatch(string(buf[:n]))
	title := "No Title"
	if len(matches) > 1 {
		title = strings.TrimSpace(matches[1])
	}
	return title, srv
}

func scanPort(ctx context.Context, target ScanTarget, timeout time.Duration) *ScanResult {
	select {
	case <-ctx.Done():
		return nil
	default:
	}
	addr := net.JoinHostPort(target.IP, strconv.Itoa(target.Port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	banner := strings.Map(func(r rune) rune {
		if r >= 32 && r <= 126 {
			return r
		}
		return -1
	}, string(buf[:n]))
	svc := CommonPorts[target.Port]
	if svc == "" {
		svc = "TCP"
	}
	wTitle, wSrv := "", ""
	if target.Port == 80 || target.Port == 443 || target.Port == 8080 {
		wTitle, wSrv = probeHTTP(target.IP, target.Port, timeout)
	}
	risk := RiskWeights[target.Port]
	if risk == 0 {
		risk = 1
	}
	return &ScanResult{IP: target.IP, Port: target.Port, Service: svc, Banner: banner, WebTitle: wTitle, WebServer: wSrv, RiskScore: risk, Timestamp: time.Now()}
}

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
			res := scanPort(ctx, target, prof.Timeout)
			results <- res
		}
	}
}

// --- 9. MAIN ---

func main() {
	profiles := map[string]ScanProfile{
		"scout":  {ID: "scout", Name: "SCOUT", Timeout: 500 * time.Millisecond, Threads: 500, PortRange: "1-1024", Theme: ThemeScout},
		"shadow": {ID: "shadow", Name: "SHADOW", Timeout: 2000 * time.Millisecond, Delay: 1500 * time.Millisecond, Threads: 10, PortRange: "1-1000", Randomize: true, Theme: ThemeShadow},
		"blitz":  {ID: "blitz", Name: "BLITZ", Timeout: 200 * time.Millisecond, Threads: 2000, PortRange: "1-1024", Theme: ThemeBlitz},
		"titan":  {ID: "titan", Name: "TITAN", Timeout: 600 * time.Millisecond, Threads: 800, PortRange: "1-65535", Theme: ThemeTitan},
	}

	hostPtr := flag.String("host", "", "IP")
	profilePtr := flag.String("mode", "scout", "Mode")
	jsonPtr := flag.String("json", "", "JSON")
	htmlPtr := flag.String("html", "", "HTML")
	flag.Parse()

	if *hostPtr == "" {
		p := tea.NewProgram(initialHelpModel(), tea.WithAltScreen())
		if _, err := p.Run(); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		return
	}

	modeKey := strings.ToLower(*profilePtr)
	if modeKey == "tytan" {
		modeKey = "titan"
	}
	prof, exists := profiles[modeKey]
	if !exists {
		prof = profiles["scout"]
	}

	ports, _ := parsePorts(prof.PortRange)
	ips, _ := parseTargets(*hostPtr)
	if prof.Randomize {
		rand.Seed(time.Now().UnixNano())
		rand.Shuffle(len(ports), func(i, j int) { ports[i], ports[j] = ports[j], ports[i] })
	}
	totalJobs := len(ips) * len(ports)

	jobs := make(chan ScanTarget, prof.Threads)
	results := make(chan *ScanResult, prof.Threads)
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
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
		wg.Wait()
		close(results)
	}()

	p := tea.NewProgram(initialScanModel(results, totalJobs, prof, *hostPtr), tea.WithAltScreen())
	finalModel, err := p.Run()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if m, ok := finalModel.(scanModel); ok {
		if *jsonPtr != "" {
			d, _ := json.MarshalIndent(m.results, "", "  ")
			_ = os.WriteFile(*jsonPtr, d, 0644)
		}
		if *htmlPtr != "" {
			generateHTMLReport(*htmlPtr, m.results)
		}
		fmt.Printf("\n%s[+] SESSION CLOSED.%s %d ports identified on %s.\n", ColorGreen, ColorReset, len(m.results), *hostPtr)
	}
}

// --- UTILS ---
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
	fmt.Printf("%s[✓] Rapport HTML : %s%s\n", ColorGreen, filename, ColorReset)
}
