package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
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
	AppVersion = "2.1.0"
	AppName    = "ARGOS"

	// ANSI Colors (Base)
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorCyan   = "\033[36m"
	ColorBold   = "\033[1m"
)

// CommonPorts : Fallback pour identifier les services
var CommonPorts = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
	110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
	3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
	8443: "HTTPS-Alt", 9000: "Portainer",
}

// --- 2. FONCTIONS GRAPHIQUES (UX) ---

// rgb génère une séquence ANSI TrueColor
func rgb(r, g, b int) string {
	return fmt.Sprintf("\033[38;2;%d;%d;%dm", r, g, b)
}

// gradient applique un dégradé linéaire sur du texte
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

// printBanner affiche le logo animé avec dégradé
func printBanner() {
	// Clear screen
	fmt.Print("\033[H\033[2J")

	lines := []string{
		`    ___    ____  ______  ____  _____`,
		`   /   |  / __ \/ ____/ / __ \/ ___/`,
		`  / /| | / /_/ / / __  / / / /\__ \ `,
		` / ___ |/ _, _/ /_/ / / /_/ /___/ / `,
		`/_/  |_/_/ |_|\____/  \____//____/  `,
	}

	// Dégradé Cyan (0,255,255) vers Violet (180,0,255)
	startR, startG, startB := 0, 255, 255
	endR, endG, endB := 180, 0, 255

	fmt.Println()
	// Animation d'apparition ligne par ligne
	for _, line := range lines {
		fmt.Println(gradient(line, startR, startG, startB, endR, endG, endB))
		time.Sleep(50 * time.Millisecond)
	}

	fmt.Println()
	// Sous-titre
	info := fmt.Sprintf("  :: %s v%s ::  Target Acquired", AppName, AppVersion)
	fmt.Println(gradient(info, 255, 255, 255, 100, 100, 100)) // Blanc vers Gris

	fmt.Println(strings.Repeat("-", 60))
	fmt.Println()
}

// updateProgressBar affiche la barre de progression
func updateProgressBar(current, total int) {
	percent := float64(current) / float64(total) * 100
	width := 40
	completed := int(float64(width) * (float64(current) / float64(total)))

	// Couleur dynamique de la barre (Bleu vers Vert)
	barColor := ColorBlue
	if percent > 90 {
		barColor = ColorGreen
	}

	bar := strings.Repeat("█", completed) + strings.Repeat("░", width-completed)
	fmt.Printf("\r%s[%s] %.1f%%%s", barColor, bar, percent, ColorReset)
}

// --- 3. STRUCTURES & SCANNER CORE ---

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

func scanTarget(ctx context.Context, target ScanTarget, timeout time.Duration) *ScanResult {
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

	// Banner Grabbing
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buffer := make([]byte, 1024)
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

func worker(ctx context.Context, jobs <-chan ScanTarget, results chan<- *ScanResult, wg *sync.WaitGroup, timeout time.Duration) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case target, ok := <-jobs:
			if !ok {
				return
			}
			res := scanTarget(ctx, target, timeout)
			if res != nil {
				results <- res
			} else {
				results <- nil // Signal de progression
			}
		}
	}
}

// --- 4. UTILITAIRES RÉSEAU ---

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

func parseTargets(input string) ([]string, error) {
	if !strings.Contains(input, "/") {
		return []string{input}, nil
	}
	_, ipv4Net, err := net.ParseCIDR(input)
	if err != nil {
		return nil, err
	}
	var ips []string
	start := ip2int(ipv4Net.IP)
	mask := binary.BigEndian.Uint32(ipv4Net.Mask)
	end := (start & mask) | (mask ^ 0xffffffff)
	for i := start + 1; i < end; i++ {
		ips = append(ips, int2ip(i).String())
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
			p, err := strconv.Atoi(r)
			if err != nil {
				return nil, err
			}
			ports = append(ports, p)
		}
	}
	return ports, nil
}

// --- 5. MAIN ---

func main() {
	// Flags
	hostPtr := flag.String("host", "127.0.0.1", "IP cible ou CIDR (ex: 192.168.1.0/24)")
	portsPtr := flag.String("p", "1-1024", "Ports à scanner")
	threadsPtr := flag.Int("t", 500, "Nombre de workers")
	timeoutPtr := flag.Int("timeout", 500, "Timeout (ms)")
	jsonPtr := flag.String("json", "", "Fichier de sortie JSON")
	flag.Parse()

	printBanner()

	// Initialisation
	ips, err := parseTargets(*hostPtr)
	if err != nil {
		fmt.Printf("%s[!] Erreur CIDR: %v%s\n", ColorRed, err, ColorReset)
		return
	}
	ports, err := parsePorts(*portsPtr)
	if err != nil {
		fmt.Printf("%s[!] Erreur Ports: %v%s\n", ColorRed, err, ColorReset)
		return
	}

	totalJobs := len(ips) * len(ports)
	fmt.Printf("%s[+] Cible(s) : %d IP(s)%s\n", ColorGreen, len(ips), ColorReset)
	fmt.Printf("%s[+] Ports    : %d ports/ip%s\n", ColorGreen, len(ports), ColorReset)
	fmt.Printf("%s[+] Threads  : %d workers%s\n", ColorCyan, *threadsPtr, ColorReset)
	fmt.Printf("%s[+] Total    : %d scans estimés%s\n\n", ColorYellow, totalJobs, ColorReset)

	// Context (Graceful Shutdown)
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\n\n" + ColorRed + "[!] Arrêt d'urgence demandé..." + ColorReset)
		cancel()
	}()
	defer cancel()

	// Channels
	jobs := make(chan ScanTarget, *threadsPtr)
	results := make(chan *ScanResult, *threadsPtr)
	var wg sync.WaitGroup

	// Lancement Workers
	for i := 0; i < *threadsPtr; i++ {
		wg.Add(1)
		go worker(ctx, jobs, results, &wg, time.Duration(*timeoutPtr)*time.Millisecond)
	}

	// Feeder
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

	// Closer
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collection résultats
	var openResults []ScanResult
	processed := 0

	for res := range results {
		processed++
		// Update UI moins fréquent pour la perf
		if processed%50 == 0 || processed == totalJobs {
			updateProgressBar(processed, totalJobs)
		}
		if res != nil {
			openResults = append(openResults, *res)
		}
	}

	// Rapport Final
	fmt.Println("\n")
	sort.Slice(openResults, func(i, j int) bool {
		if openResults[i].IP == openResults[j].IP {
			return openResults[i].Port < openResults[j].Port
		}
		return openResults[i].IP < openResults[j].IP
	})

	fmt.Printf("%-16s %-8s %-12s %-25s\n", "IP", "PORT", "SERVICE", "BANNER")
	fmt.Println(strings.Repeat("-", 65))

	for _, r := range openResults {
		banner := r.Banner
		if len(banner) > 25 {
			banner = banner[:22] + "..."
		}
		if banner == "" {
			banner = "-"
		}

		fmt.Printf("%s%-16s %-8d %-12s %s%s%s\n",
			ColorBold, r.IP, r.Port, r.Service,
			ColorCyan, banner, ColorReset)
	}

	// JSON Export
	if *jsonPtr != "" {
		file, _ := json.MarshalIndent(openResults, "", "  ")
		_ = os.WriteFile(*jsonPtr, file, 0644)
		fmt.Printf("\n%s[✓] Sauvegardé dans %s%s\n", ColorGreen, *jsonPtr, ColorReset)
	}

	fmt.Printf("\n[FIN] %d ports ouverts trouvés.\n", len(openResults))
}
