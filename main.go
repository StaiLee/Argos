package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// --- 1. CONFIGURATION & CONSTANTES ---

const (
	AppVersion = "3.1.0 (Chameleon)"
	AppName    = "ARGOS PANOPTES"

	// ANSI Colors
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorBold   = "\033[1m"
)

var CommonPorts = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
	110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
	3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
	8443: "HTTPS-Alt", 9000: "Portainer", 27017: "MongoDB",
}

// --- 2. STRUCTURES DE DONNÉES ---

type ScanTarget struct {
	IP   string
	Port int
}

type ScanResult struct {
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	State   string `json:"state"`
	Service string `json:"service"`
	Banner  string `json:"banner,omitempty"`
}

type ScanProfile struct {
	Name    string
	Timeout time.Duration
	Delay   time.Duration
	Threads int
}

// --- 3. LOGIQUE MÉTIER (CORE) ---

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

	conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	buffer := make([]byte, 512)
	n, _ := conn.Read(buffer)

	banner := strings.TrimSpace(string(buffer[:n]))
	service := CommonPorts[target.Port]
	if service == "" {
		service = "Unknown"
	}

	return &ScanResult{
		IP:      target.IP,
		Port:    target.Port,
		State:   "Open",
		Service: service,
		Banner:  banner,
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
				time.Sleep(profile.Delay)
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

// --- 4. UTILITAIRES & UX (ADAPTATIF) ---

func rgb(r, g, b int) string {
	return fmt.Sprintf("\033[38;2;%d;%d;%dm", r, g, b)
}

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

// printBanner adaptatif selon le mode
func printBanner(mode string) {
	fmt.Print("\033[H\033[2J") // Clear screen
	lines := []string{
		`    ___    ____  ______  ____  _____`,
		`   /   |  / __ \/ ____/ / __ \/ ___/`,
		`  / /| | / /_/ / / __  / / / /\__ \ `,
		` / ___ |/ _, _/ /_/ / / /_/ /___/ / `,
		`/_/  |_/_/ |_|\____/  \____//____/  `,
	}

	// Définition des couleurs selon le mode
	var sR, sG, sB, eR, eG, eB int
	var subTitleColor string

	switch mode {
	case "stealth":
		// ROUGE TACTIQUE (Rouge vif vers Rouge sombre)
		sR, sG, sB = 255, 0, 0
		eR, eG, eB = 60, 0, 0
		subTitleColor = ColorRed
	case "insane":
		// SURCHAUFFE (Jaune vers Rouge)
		sR, sG, sB = 255, 255, 0
		eR, eG, eB = 255, 0, 0
		subTitleColor = ColorYellow
	default:
		// CYBERPUNK (Cyan vers Violet) - Mode Normal
		sR, sG, sB = 0, 255, 255
		eR, eG, eB = 180, 0, 255
		subTitleColor = ColorCyan
	}

	fmt.Println()
	for _, line := range lines {
		fmt.Println(gradient(line, sR, sG, sB, eR, eG, eB))
		time.Sleep(30 * time.Millisecond)
	}
	fmt.Println()

	// Affichage du sous-titre stylé
	modeUpper := strings.ToUpper(mode)
	fmt.Printf("  :: %s :: %sMODE %s ACTIVATED%s\n", AppVersion, subTitleColor, modeUpper, ColorReset)
	fmt.Println(strings.Repeat("-", 60))
	fmt.Println()
}

func updateProgressBar(current, total int) {
	percent := float64(current) / float64(total) * 100
	width := 40
	completed := int(float64(width) * (float64(current) / float64(total)))
	barColor := ColorBlue
	if percent > 90 {
		barColor = ColorGreen
	}
	bar := strings.Repeat("█", completed) + strings.Repeat("░", width-completed)
	fmt.Printf("\r%s[%s] %.1f%%%s", barColor, bar, percent, ColorReset)
}

// --- 5. PARSING ---

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

func parsePorts(portStr string) ([]int, error) {
	var ports []int
	if portStr == "all" {
		for i := 1; i <= 65535; i++ {
			ports = append(ports, i)
		}
		return ports, nil
	}
	ranges := strings.Split(portStr, ",")
	for _, r := range ranges {
		if strings.Contains(r, "-") {
			parts := strings.Split(r, "-")
			start, _ := strconv.Atoi(parts[0])
			end, _ := strconv.Atoi(parts[1])
			for i := start; i <= end; i++ {
				ports = append(ports, i)
			}
		} else {
			p, _ := strconv.Atoi(r)
			ports = append(ports, p)
		}
	}
	return ports, nil
}

// --- 6. MAIN ---

func main() {
	// Flags
	hostPtr := flag.String("host", "127.0.0.1", "Cible IP ou CIDR")
	portsPtr := flag.String("p", "1-1024", "Ports")
	profilePtr := flag.String("mode", "normal", "Mode: stealth, normal, insane")
	shufflePtr := flag.Bool("random", false, "Mélanger l'ordre des ports (Anti-IDS)")
	jsonPtr := flag.String("json", "", "Export JSON")
	dryRunPtr := flag.Bool("dry", false, "Simulation seulement (pas de scan)")
	flag.Parse()

	// APPEL DU BANNER AVEC LE MODE
	printBanner(*profilePtr)

	// Configuration des Profils
	profiles := map[string]ScanProfile{
		"stealth": {Name: "Stealth (Paranoid)", Timeout: 2000 * time.Millisecond, Delay: 300 * time.Millisecond, Threads: 5},
		"normal":  {Name: "Normal (Aggressive)", Timeout: 500 * time.Millisecond, Delay: 0, Threads: 500},
		"insane":  {Name: "Insane (Beast Mode)", Timeout: 200 * time.Millisecond, Delay: 0, Threads: 2000},
	}

	selectedProfile, exists := profiles[*profilePtr]
	if !exists {
		selectedProfile = profiles["normal"]
	}

	ips, _ := parseTargets(*hostPtr)
	ports, _ := parsePorts(*portsPtr)

	if *shufflePtr {
		fmt.Printf("%s[🎲] Randomisation des ports activée (Evasion)%s\n", ColorPurple, ColorReset)
		rand.Seed(time.Now().UnixNano())
		rand.Shuffle(len(ports), func(i, j int) { ports[i], ports[j] = ports[j], ports[i] })
	}

	totalJobs := len(ips) * len(ports)
	fmt.Printf("%s[+] Mode     : %s%s\n", ColorCyan, selectedProfile.Name, ColorReset)
	fmt.Printf("%s[+] Threads  : %d workers%s\n", ColorCyan, selectedProfile.Threads, ColorReset)
	fmt.Printf("%s[+] Cibles   : %d IP(s) x %d Ports%s\n", ColorGreen, len(ips), len(ports), ColorReset)
	fmt.Println(strings.Repeat("-", 60))

	if *dryRunPtr {
		fmt.Println("[!] DRY RUN TERMINÉ. Aucun paquet envoyé.")
		return
	}

	// Engine
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() { <-c; fmt.Println("\n[!] Arrêt demandé..."); cancel() }()
	defer cancel()

	jobs := make(chan ScanTarget, selectedProfile.Threads)
	results := make(chan *ScanResult, selectedProfile.Threads)
	var wg sync.WaitGroup

	for i := 0; i < selectedProfile.Threads; i++ {
		wg.Add(1)
		go worker(ctx, jobs, results, &wg, selectedProfile)
	}

	go func() {
		for _, ip := range ips {
			for _, p := range ports {
				select {
				case <-ctx.Done():
					close(jobs)
					return
				case jobs <- ScanTarget{IP: ip, Port: p}:
				}
			}
		}
		close(jobs)
	}()

	go func() { wg.Wait(); close(results) }()

	// Collection
	var openResults []ScanResult
	processed := 0
	start := time.Now()

	for res := range results {
		processed++
		if processed%50 == 0 || processed == totalJobs {
			updateProgressBar(processed, totalJobs)
		}
		if res != nil {
			openResults = append(openResults, *res)
		}
	}

	// Rapport
	fmt.Println()
	sort.Slice(openResults, func(i, j int) bool { return openResults[i].Port < openResults[j].Port })

	fmt.Printf("%-16s %-8s %-12s %-25s\n", "IP", "PORT", "SERVICE", "BANNER")
	fmt.Println(strings.Repeat("-", 65))
	for _, r := range openResults {
		banner := r.Banner
		if len(banner) > 22 {
			banner = banner[:19] + "..."
		}
		if banner == "" {
			banner = "-"
		}
		fmt.Printf("%s%-16s %-8d %-12s %s%s%s\n", ColorBold, r.IP, r.Port, r.Service, ColorCyan, banner, ColorReset)
	}

	if *jsonPtr != "" {
		file, _ := json.MarshalIndent(openResults, "", "  ")
		_ = os.WriteFile(*jsonPtr, file, 0644)
		fmt.Printf("\n%s[✓] Sauvegarde JSON : %s%s\n", ColorGreen, *jsonPtr, ColorReset)
	}

	fmt.Printf("\n[FIN] %d ports ouverts en %s.\n", len(openResults), time.Since(start))
}
