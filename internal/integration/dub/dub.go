package dub

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const maxResponseBytes = 1 << 20

var httpClient = &http.Client{Timeout: 10 * time.Second}

type Config struct {
	APIURL    string
	Token     string
	Domain    string
	URLPrefix string
}

type Link struct {
	ShortLink string `json:"shortLink"`
}

type upsertRequest struct {
	URL             string `json:"url"`
	Domain          string `json:"domain"`
	Key             string `json:"key"`
	ExternalID      string `json:"externalId"`
	Password        string `json:"password,omitempty"`
	Title           string `json:"title,omitempty"`
	ExpiresAt       string `json:"expiresAt,omitempty"`
	DoIndex         bool   `json:"doIndex"`
	TrackConversion bool   `json:"trackConversion"`
}

func LoadConfig() (Config, error) {
	apiURL := strings.TrimRight(strings.TrimSpace(os.Getenv("GOKAPI_DUB_API_URL")), "/")
	domain := strings.TrimSpace(os.Getenv("GOKAPI_DUB_DOMAIN"))
	tokenFile := strings.TrimSpace(os.Getenv("GOKAPI_DUB_API_TOKEN_FILE"))
	urlPrefix := strings.TrimSpace(os.Getenv("GOKAPI_DUB_EXTERNAL_ID_PREFIX"))
	if apiURL == "" && domain == "" && tokenFile == "" {
		return Config{}, errors.New("Dub integration is not configured")
	}
	if apiURL == "" || domain == "" || tokenFile == "" {
		return Config{}, errors.New("GOKAPI_DUB_API_URL, GOKAPI_DUB_DOMAIN, and GOKAPI_DUB_API_TOKEN_FILE must all be configured")
	}
	parsed, err := url.Parse(apiURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return Config{}, errors.New("GOKAPI_DUB_API_URL must be an HTTPS origin with an optional path")
	}
	if strings.ContainsAny(domain, "/:@?#") {
		return Config{}, errors.New("GOKAPI_DUB_DOMAIN must be a hostname")
	}
	tokenBytes, err := os.ReadFile(tokenFile)
	if err != nil {
		return Config{}, fmt.Errorf("read Dub API token: %w", err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	if token == "" || strings.ContainsAny(token, "\r\n") {
		return Config{}, errors.New("Dub API token is empty or contains a newline")
	}
	if urlPrefix == "" {
		urlPrefix = "gokapi:file:"
	}
	return Config{APIURL: apiURL, Token: token, Domain: domain, URLPrefix: urlPrefix}, nil
}

func Upsert(ctx context.Context, config Config, fileID, title, password string, expiresAt int64, unlimitedTime bool) (Link, error) {
	key := brokerKey(fileID)
	destination := "https://" + config.Domain + "/" + key + "/_download/" + url.PathEscape(fileID)
	requestBody := upsertRequest{
		URL:             destination,
		Domain:          config.Domain,
		Key:             key,
		ExternalID:      config.URLPrefix + fileID,
		Password:        password,
		Title:           title,
		DoIndex:         false,
		TrackConversion: true,
	}
	if !unlimitedTime && expiresAt > 0 {
		requestBody.ExpiresAt = time.Unix(expiresAt, 0).UTC().Format(time.RFC3339)
	}
	body, err := json.Marshal(requestBody)
	if err != nil {
		return Link{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, config.APIURL+"/links/upsert", bytes.NewReader(body))
	if err != nil {
		return Link{}, err
	}
	req.Header.Set("Authorization", "Bearer "+config.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	response, err := httpClient.Do(req)
	if err != nil {
		return Link{}, fmt.Errorf("call Dub API: %w", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return Link{}, fmt.Errorf("read Dub API response: %w", err)
	}
	if len(responseBody) > maxResponseBytes {
		return Link{}, errors.New("Dub API response exceeded the size limit")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return Link{}, fmt.Errorf("Dub API returned HTTP %d", response.StatusCode)
	}
	var link Link
	if err := json.Unmarshal(responseBody, &link); err != nil {
		return Link{}, fmt.Errorf("decode Dub API response: %w", err)
	}
	shortURL, err := url.Parse(link.ShortLink)
	if err != nil || shortURL.Scheme != "https" || !strings.EqualFold(shortURL.Hostname(), config.Domain) {
		return Link{}, errors.New("Dub API returned an invalid short link")
	}
	return link, nil
}

func brokerKey(fileID string) string {
	sum := sha256.Sum256([]byte(fileID))
	return "g/" + base64.RawURLEncoding.EncodeToString(sum[:9])
}
