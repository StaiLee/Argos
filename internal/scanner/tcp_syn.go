package scanner

import (
	"context"
	"errors"
	"net"
	"time"

	"argos/internal/models"
	"argos/internal/network"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// TCPSynProbe est l'arme furtive (Half-Open Scan).
// ATTENTION: Nécessite les privilèges root (sudo).
type TCPSynProbe struct {
	localIP   net.IP
	localPort layers.TCPPort
	handle    *pcap.Handle
}

func NewTCPSynProbe() (*TCPSynProbe, error) {
	// 1. Découverte de notre propre interface réseau sortante
	localIP, err := getOutboundIP()
	if err != nil {
		return nil, err
	}

	// 2. Ouverture du capteur de paquets (Sniffer) sur l'interface par défaut (eth0/wlan0)
	// En production, il faut déterminer l'interface dynamiquement. Pour l'exemple, "eth0" (Kali par défaut).
	handle, err := pcap.OpenLive("eth0", 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, errors.New("impossible d'ouvrir le raw socket (êtes-vous root ?)")
	}

	// 3. Application d'un filtre BPF au niveau du noyau (On n'écoute QUE les SYN-ACK ou RST)
	err = handle.SetBPFFilter("tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack) or tcp[tcpflags] & tcp-rst != 0")
	if err != nil {
		return nil, err
	}

	return &TCPSynProbe{
		localIP:   localIP,
		localPort: layers.TCPPort(54321), // Port source aléatoire fixe pour simplifier le routage
		handle:    handle,
	}, nil
}

func (p *TCPSynProbe) Name() string {
	return "tcp-syn"
}

func (p *TCPSynProbe) Scan(ctx context.Context, target models.Target, dialer network.ContextDialer, timeout time.Duration) *models.ScanResult {
	// Le Ghost Engine (Proxy SOCKS5) NE FONCTIONNE PAS avec les Raw Sockets (niveau 3/4).
	// Un proxy SOCKS5 nécessite une connexion TCP complète. Le SYN Scan expose obligatoirement ton IP.

	targetIP := net.ParseIP(target.IP)
	if targetIP == nil {
		return nil
	}

	// 1. Construction du paquet IP
	ipLayer := &layers.IPv4{
		SrcIP:    p.localIP,
		DstIP:    targetIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	// 2. Construction du paquet TCP Furtif (Flag SYN = true)
	tcpLayer := &layers.TCP{
		SrcPort: p.localPort,
		DstPort: layers.TCPPort(target.Port),
		Seq:     1105024978, // Numéro de séquence factice (devrait être randomisé)
		SYN:     true,
		Window:  14600,
	}
	_ = tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	// 3. Sérialisation (Transformation des structures Go en bits purs)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(buf, opts, ipLayer, tcpLayer); err != nil {
		return nil
	}

	// 4. Frappe : Envoi direct sur le fil de cuivre
	if err := p.handle.WritePacketData(buf.Bytes()); err != nil {
		return nil
	}

	// 5. Attente de la réponse (Listener très simplifié, normalement géré par un thread centralisé)
	// Remarque : Dans une version ultra-optimisée, on ne bloquerait pas ici.
	start := time.Now()
	packetSource := gopacket.NewPacketSource(p.handle, p.handle.LinkType())

	for {
		if time.Since(start) > timeout {
			return nil // Timeout = Filtré ou Fermé
		}

		select {
		case <-ctx.Done():
			return nil
		case packet := <-packetSource.Packets():
			if packet == nil {
				continue
			}
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				// Si le port de destination du paquet correspond à notre port source ET que c'est un SYN-ACK
				if tcp.DstPort == p.localPort && tcp.SrcPort == layers.TCPPort(target.Port) {
					if tcp.SYN && tcp.ACK {
						// PÉPITE : Le port est ouvert !
						return &models.ScanResult{
							IP:        target.IP,
							Port:      target.Port,
							Service:   models.CommonPorts[target.Port],
							State:     "open",
							RiskScore: models.RiskWeights[target.Port],
							Timestamp: time.Now(),
						}
					}
				}
			}
		default:
			time.Sleep(10 * time.Millisecond) // Évite de brûler le CPU
		}
	}
}

// Utilitaire pour trouver l'IP locale (requise pour forger l'en-tête IP)
func getOutboundIP() (net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP, nil
}
