package models

import "time"

// --- LES STRUCTURES DE RENSEIGNEMENT ---

// Target représente les coordonnées de frappe précises.
type Target struct {
	IP   string
	Port int
}

// ScanResult est l'artefact de renseignement remonté par les workers.
type ScanResult struct {
	IP        string    `json:"ip"`
	Port      int       `json:"port"`
	Service   string    `json:"service"`
	State     string    `json:"state"` // "open", "closed", "filtered"
	Banner    string    `json:"banner,omitempty"`
	WebTitle  string    `json:"web_title,omitempty"`
	WebServer string    `json:"web_server,omitempty"`
	RiskScore int       `json:"risk_score"`
	Timestamp time.Time `json:"timestamp"`
}

// --- LES STRUCTURES DE COMMANDEMENT ---

// Profile définit les paramètres tactiques de la mission (Scout, Blitz, Titan...).
type Profile struct {
	ID        string
	Name      string
	Desc      string
	Timeout   time.Duration
	Delay     time.Duration
	Threads   int
	PortRange string
	Randomize bool
	DeepScan  bool
	ThemeName string // Ex: "blitz", "titan". Découplé du moteur de rendu UI !
}

// ProxyDef représente un noeud de rebond pour le Ghost Engine.
type ProxyDef struct {
	Address  string `json:"address"`
	Protocol string `json:"protocol"` // Ex: "socks5", "http"
}

// Constants pour l'évaluation des menaces (The Oracle)
var CommonPorts = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
	110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
	3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
	8443: "HTTPS-Alt", 9000: "Portainer", 27017: "MongoDB",
}

var RiskWeights = map[int]int{
	21: 20, 23: 30, 445: 25, 3389: 15, 80: 5, 443: 0, 22: 5,
}
