package websearch

import (
	"fmt"
	"net/url"
)

// HealthCheckURL derives the health check endpoint for a provider that uses a
// custom API endpoint. The result is "scheme://host/health" — host already
// includes the port when one is specified in the custom endpoint.
//
// Health checks only apply to providers configured with a custom endpoint;
// passing an empty customEndpoint returns an error so callers skip the provider.
func HealthCheckURL(customEndpoint string) (string, error) {
	if customEndpoint == "" {
		return "", fmt.Errorf("websearch: health check requires a custom endpoint")
	}
	u, err := url.Parse(customEndpoint)
	if err != nil {
		return "", fmt.Errorf("websearch: invalid endpoint %q: %w", customEndpoint, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("websearch: endpoint %q missing scheme or host", customEndpoint)
	}
	return fmt.Sprintf("%s://%s/health", u.Scheme, u.Host), nil
}
