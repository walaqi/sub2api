package websearch

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTavilyProvider_Name(t *testing.T) {
	p := NewTavilyProvider("key", "", nil)
	require.Equal(t, "tavily", p.Name())
}

func TestTavilyProvider_Search_CustomEndpoint(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))
		resp := tavilyResponse{Results: []tavilyResult{
			{URL: "https://go.dev", Title: "Go", Content: "Go lang", Score: 0.9},
		}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := NewTavilyProvider("test-key", srv.URL+"/custom/search", srv.Client())
	resp, err := p.Search(context.Background(), SearchRequest{Query: "golang", MaxResults: 3})
	require.NoError(t, err)
	require.Equal(t, "/custom/search", gotPath)
	require.Len(t, resp.Results, 1)
	require.Equal(t, "https://go.dev", resp.Results[0].URL)
	require.Equal(t, "Go lang", resp.Results[0].Snippet)
}

func TestTavilyProvider_DefaultEndpoint(t *testing.T) {
	p := NewTavilyProvider("key", "", nil)
	require.Equal(t, tavilySearchEndpoint, p.endpoint)
}

func TestTavilyProvider_Search_RequestConstruction(t *testing.T) {
	// Verify tavilyRequest struct fields map correctly
	req := tavilyRequest{
		APIKey:      "test-key",
		Query:       "golang",
		MaxResults:  3,
		SearchDepth: tavilySearchDepthBasic,
	}
	data, err := json.Marshal(req)
	require.NoError(t, err)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(data, &parsed))
	require.Equal(t, "test-key", parsed["api_key"])
	require.Equal(t, "golang", parsed["query"])
	require.Equal(t, float64(3), parsed["max_results"])
	require.Equal(t, "basic", parsed["search_depth"])
}

func TestTavilyProvider_Search_ResponseParsing(t *testing.T) {
	rawResp := `{"results":[{"url":"https://go.dev","title":"Go","content":"Go programming language","score":0.95}]}`
	var resp tavilyResponse
	require.NoError(t, json.Unmarshal([]byte(rawResp), &resp))
	require.Len(t, resp.Results, 1)
	require.Equal(t, "https://go.dev", resp.Results[0].URL)
	require.Equal(t, "Go programming language", resp.Results[0].Content)
	require.InDelta(t, 0.95, resp.Results[0].Score, 0.001)

	// Verify mapping to SearchResult
	results := make([]SearchResult, 0, len(resp.Results))
	for _, r := range resp.Results {
		results = append(results, SearchResult{
			URL: r.URL, Title: r.Title, Snippet: r.Content,
		})
	}
	require.Equal(t, "Go programming language", results[0].Snippet)
	require.Equal(t, "", results[0].PageAge)
}

func TestTavilyProvider_Search_EmptyResults(t *testing.T) {
	var resp tavilyResponse
	require.NoError(t, json.Unmarshal([]byte(`{"results":[]}`), &resp))
	require.Empty(t, resp.Results)
}

func TestTavilyProvider_Search_InvalidJSON(t *testing.T) {
	var resp tavilyResponse
	require.Error(t, json.Unmarshal([]byte("not json"), &resp))
}
