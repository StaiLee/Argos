package identity

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"argos/internal/network"
)

// Pré-compilation au démarrage du programme pour l'Escape Analysis
var titleRegex = regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)

// ProbeHTTP extrait l'en-tête Server et la balise Title.
func ProbeHTTP(ctx context.Context, ip string, port int, dialer network.ContextDialer, timeout time.Duration) (string, string) {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}
	targetURL := fmt.Sprintf("%s://%s:%d/", scheme, ip, port)

	// L'Astuce du Maître : Le client HTTP de Go utilise notre propre réseau (Ghost Mode transparent)
	transport := &http.Transport{
		DialContext:       dialer.DialContext,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // On ne suit jamais les redirections (vitesse max)
		},
	}

	ctxTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctxTimeout, http.MethodGet, targetURL, nil)
	if err != nil {
		return "", ""
	}
	// Usurpation d'identité légère
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Argos/5.0")

	resp, err := client.Do(req)
	if err != nil {
		return "", ""
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	srv := resp.Header.Get("Server")
	if srv == "" {
		srv = "Unknown"
	}

	// Prévention contre les "Tarpits" (Serveurs piégés envoyant des flux infinis)
	limitReader := io.LimitReader(resp.Body, 2048)
	bodyBytes, err := io.ReadAll(limitReader)
	if err != nil {
		return "", srv
	}

	title := ""
	if matches := titleRegex.FindSubmatch(bodyBytes); len(matches) > 1 {
		title = strings.TrimSpace(string(matches[1]))
	}

	return title, srv
}
