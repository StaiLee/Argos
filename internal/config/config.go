package config

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ParseTargets est le moteur d'intelligence de ciblage.
// Il gère nativement les IP brutes, les sous-réseaux (CIDR) et la résolution DNS (FQDN).
func ParseTargets(input string) ([]string, error) {
	// 1. Détection de Sous-réseau (CIDR)
	if strings.Contains(input, "/") {
		_, ipv4Net, err := net.ParseCIDR(input)
		if err != nil {
			return nil, err
		}
		ip := ipv4Net.IP.To4()
		if ip == nil {
			return nil, fmt.Errorf("IPv6 n'est pas encore supporté par l'engine")
		}
		var ips []string
		start := binary.BigEndian.Uint32(ip)
		mask := binary.BigEndian.Uint32(ipv4Net.Mask)
		end := (start & mask) | (mask ^ 0xffffffff)

		// On ignore la Network Address et le Broadcast Address
		for i := start + 1; i < end; i++ {
			ipBuf := make(net.IP, 4)
			binary.BigEndian.PutUint32(ipBuf, i)
			ips = append(ips, ipBuf.String())
		}
		return ips, nil
	}

	// 2. Détection d'IP pure
	if parsedIP := net.ParseIP(input); parsedIP != nil {
		return []string{input}, nil
	}

	// 3. Résolution DNS (Nom de domaine)
	ips, err := net.LookupIP(input)
	if err != nil {
		return nil, fmt.Errorf("impossible de résoudre la cible DNS: %v", err)
	}

	var resolved []string
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil { // On filtre sur IPv4 pour la stabilité actuelle
			resolved = append(resolved, ipv4.String())
		}
	}

	if len(resolved) == 0 {
		return nil, fmt.Errorf("aucune adresse IPv4 trouvée pour le domaine")
	}

	return resolved, nil
}

// ParsePorts transforme la syntaxe humaine en vecteurs d'attaque.
func ParsePorts(inputStr string) ([]int, error) {
	var p []int
	if inputStr == "all" || inputStr == "-" {
		for i := 1; i <= 65535; i++ {
			p = append(p, i)
		}
		return p, nil
	}

	parts := strings.Split(inputStr, ",")
	for _, v := range parts {
		if strings.Contains(v, "-") {
			sp := strings.Split(v, "-")
			start, _ := strconv.Atoi(sp[0])
			end, _ := strconv.Atoi(sp[1])
			for i := start; i <= end; i++ {
				p = append(p, i)
			}
		} else {
			i, _ := strconv.Atoi(v)
			p = append(p, i)
		}
	}
	return p, nil
}
