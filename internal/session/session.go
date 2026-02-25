package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var secret []byte
var trustedProxies []string

func SetSecret(s string) {
	secret = []byte(s)
}

func SetTrustedProxies(proxies string) {
	if proxies == "" {
		trustedProxies = []string{}
		return
	}
	trustedProxies = strings.Split(proxies, ",")
	for i, p := range trustedProxies {
		trustedProxies[i] = strings.TrimSpace(p)
	}
}

func HmacSHA256(data string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

func ConstantTimeCompare(a, b string) bool {
	return hmac.Equal([]byte(a), []byte(b))
}

func IsTrustedRemote(remoteAddr string) bool {
	if len(trustedProxies) == 0 {
		return false
	}

	remoteIP, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		remoteIP = strings.TrimSpace(remoteAddr)
	}

	parsedRemoteIP := net.ParseIP(remoteIP)
	if parsedRemoteIP == nil {
		return false
	}

	for _, proxy := range trustedProxies {
		proxy = strings.TrimSpace(proxy)
		if proxy == "" {
			continue
		}

		if strings.Contains(proxy, "/") {
			_, ipNet, err := net.ParseCIDR(proxy)
			if err != nil {
				continue
			}
			if ipNet.Contains(parsedRemoteIP) {
				return true
			}
			continue
		}

		parsedProxyIP := net.ParseIP(proxy)
		if parsedProxyIP != nil && parsedProxyIP.Equal(parsedRemoteIP) {
			return true
		}
	}

	return false
}

func IsSecureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}

	if strings.EqualFold(r.URL.Scheme, "https") {
		return true
	}

	if !IsTrustedRemote(r.RemoteAddr) {
		return false
	}

	return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}

func GetFromCookie(r *http.Request) (sessionID, userID, username string) {
	cookie, err := r.Cookie("session")
	if err != nil {
		return "", "", ""
	}

	tokenBytes, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return "", "", ""
	}

	parts := strings.Split(string(tokenBytes), ":")
	if len(parts) != 5 {
		return "", "", ""
	}

	sessionID, userID, username, timestampStr, signature := parts[0], parts[1], parts[2], parts[3], parts[4]

	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return "", "", ""
	}

	if time.Now().Unix()-timestamp > 86400 {
		return "", "", ""
	}

	expectedSig := HmacSHA256(sessionID + ":" + userID + ":" + username + ":" + timestampStr)
	if !ConstantTimeCompare(signature, expectedSig) {
		return "", "", ""
	}

	return sessionID, userID, username
}
