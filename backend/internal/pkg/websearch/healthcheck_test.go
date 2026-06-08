package websearch

import "testing"

func TestHealthCheckURL(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     string
		wantErr  bool
	}{
		{
			name:     "https with default port",
			endpoint: "https://search.example.com/res/v1/web/search",
			want:     "https://search.example.com/health",
		},
		{
			name:     "http with explicit port",
			endpoint: "http://10.0.0.5:8080/v1/search",
			want:     "http://10.0.0.5:8080/health",
		},
		{
			name:     "host root only",
			endpoint: "https://api.internal:9000",
			want:     "https://api.internal:9000/health",
		},
		{
			name:     "empty endpoint is an error",
			endpoint: "",
			wantErr:  true,
		},
		{
			name:     "missing scheme is an error",
			endpoint: "search.example.com/search",
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HealthCheckURL(tt.endpoint)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (result %q)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("HealthCheckURL(%q) = %q, want %q", tt.endpoint, got, tt.want)
			}
		})
	}
}
