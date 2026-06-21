package service

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/websearch"
)

// WebSearchHealthCheckInterval is how often configured custom-endpoint providers
// are health-checked.
const WebSearchHealthCheckInterval = 5 * time.Minute

// webSearchHealthRequestTimeout bounds a single health check HTTP request.
const webSearchHealthRequestTimeout = 5 * time.Second

// ProviderHealth is the read-only health status of a single web search provider.
// It is only populated for providers configured with a custom endpoint; providers
// using the official default endpoint are not checked and report nil.
type ProviderHealth struct {
	Healthy    bool   `json:"healthy"`               // true only when the last check returned a 2xx status
	StatusCode int    `json:"status_code,omitempty"` // HTTP status from the last check (0 if unreachable)
	LatencyMS  int64  `json:"latency_ms,omitempty"`  // round-trip latency of the last check
	CheckedAt  int64  `json:"checked_at"`            // unix seconds of the last check
	Error      string `json:"error,omitempty"`       // error detail when the check failed
}

// WebSearchHealthChecker periodically probes the "/health" endpoint of every
// enabled web search provider that uses a custom API endpoint. The health check
// is considered passing only when the endpoint returns a 2xx status. Requests
// are routed through the provider's configured proxy, matching how real searches
// are dispatched.
type WebSearchHealthChecker struct {
	settingService *SettingService
	interval       time.Duration

	mu      sync.RWMutex
	results map[string]*ProviderHealth // keyed by provider type

	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// NewWebSearchHealthChecker constructs the checker. interval <= 0 falls back to
// WebSearchHealthCheckInterval.
func NewWebSearchHealthChecker(settingService *SettingService, interval time.Duration) *WebSearchHealthChecker {
	if interval <= 0 {
		interval = WebSearchHealthCheckInterval
	}
	return &WebSearchHealthChecker{
		settingService: settingService,
		interval:       interval,
		results:        make(map[string]*ProviderHealth),
		stopCh:         make(chan struct{}),
	}
}

// Start launches the background ticker. The first check runs immediately.
func (c *WebSearchHealthChecker) Start() {
	if c == nil || c.settingService == nil {
		return
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		ticker := time.NewTicker(c.interval)
		defer ticker.Stop()

		c.runOnce()
		for {
			select {
			case <-ticker.C:
				c.runOnce()
			case <-c.stopCh:
				return
			}
		}
	}()
}

// Stop halts the background ticker and waits for the in-flight round to finish.
func (c *WebSearchHealthChecker) Stop() {
	if c == nil {
		return
	}
	c.stopOnce.Do(func() {
		close(c.stopCh)
	})
	c.wg.Wait()
}

// GetHealth returns the last known health status for a provider type, or nil if
// the provider has no custom endpoint (not checked) or has not been checked yet.
func (c *WebSearchHealthChecker) GetHealth(providerType string) *ProviderHealth {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	h, ok := c.results[providerType]
	if !ok {
		return nil
	}
	cp := *h
	return &cp
}

// runOnce checks every enabled provider that has a custom endpoint and updates
// the results map. Providers using the official default endpoint are skipped and
// pruned from the results so stale statuses don't linger after a config change.
func (c *WebSearchHealthChecker) runOnce() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cfg, err := c.settingService.GetWebSearchEmulationConfig(ctx)
	if err != nil {
		slog.Warn("websearch healthcheck: load config failed", "error", err)
		return
	}

	checked := make(map[string]struct{})
	if cfg != nil && cfg.Enabled {
		proxyURLs := c.settingService.resolveProviderProxyURLs(ctx, cfg)
		for _, p := range cfg.Providers {
			if p.Endpoint == "" {
				// Official default endpoint — not health-checked.
				continue
			}
			proxyURL := ""
			if p.ProxyID != nil {
				if u, ok := proxyURLs[*p.ProxyID]; ok {
					proxyURL = u
				}
			}
			c.checkProvider(ctx, p.Type, p.Endpoint, proxyURL)
			checked[p.Type] = struct{}{}
		}
	}

	// Prune statuses for providers no longer checked (removed, disabled, or
	// switched back to the official endpoint).
	c.mu.Lock()
	for k := range c.results {
		if _, ok := checked[k]; !ok {
			delete(c.results, k)
		}
	}
	c.mu.Unlock()
}

// checkProvider performs a single GET against the provider's "/health" URL and
// records the outcome. Only a 2xx response counts as healthy.
func (c *WebSearchHealthChecker) checkProvider(ctx context.Context, providerType, endpoint, proxyURL string) {
	result := &ProviderHealth{CheckedAt: time.Now().Unix()}

	healthURL, err := websearch.HealthCheckURL(endpoint)
	if err != nil {
		result.Error = err.Error()
		c.store(providerType, result)
		return
	}

	client, err := websearch.NewHTTPClient(proxyURL)
	if err != nil {
		result.Error = "proxy config: " + err.Error()
		c.store(providerType, result)
		return
	}

	reqCtx, cancel := context.WithTimeout(ctx, webSearchHealthRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, healthURL, nil)
	if err != nil {
		result.Error = err.Error()
		c.store(providerType, result)
		return
	}

	start := time.Now()
	resp, err := client.Do(req)
	result.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		result.Error = err.Error()
		c.store(providerType, result)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	result.StatusCode = resp.StatusCode
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		result.Healthy = true
	} else {
		result.Error = "unexpected status: " + resp.Status
	}
	c.store(providerType, result)
}

func (c *WebSearchHealthChecker) store(providerType string, h *ProviderHealth) {
	c.mu.Lock()
	c.results[providerType] = h
	c.mu.Unlock()
}

// --- Global accessor (mirrors the websearch.Manager wiring pattern) ---

var webSearchHealthChecker = struct {
	sync.RWMutex
	checker *WebSearchHealthChecker
}{}

// SetWebSearchHealthChecker registers the running checker so handlers can read
// provider health when serializing config.
func SetWebSearchHealthChecker(c *WebSearchHealthChecker) {
	webSearchHealthChecker.Lock()
	webSearchHealthChecker.checker = c
	webSearchHealthChecker.Unlock()
}

func getWebSearchHealthChecker() *WebSearchHealthChecker {
	webSearchHealthChecker.RLock()
	defer webSearchHealthChecker.RUnlock()
	return webSearchHealthChecker.checker
}

// StopWebSearchHealthChecker stops the registered checker, if any.
func StopWebSearchHealthChecker() {
	if c := getWebSearchHealthChecker(); c != nil {
		c.Stop()
	}
}
