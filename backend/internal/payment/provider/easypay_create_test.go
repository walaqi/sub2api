package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/payment"
)

// TestEasyPayCreateAPIPaymentHTMLErrorPage covers the original report:
// when the upstream gateway returns an HTML error page (e.g. wrong apiBase
// pointing at a 404 page), the error must surface HTTP status + body summary
// instead of "invalid character '<'".
func TestEasyPayCreateAPIPaymentHTMLErrorPage(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body>404 Not Found</body></html>`))
	}))
	defer server.Close()

	p := newTestEasyPay(t, server.URL)
	_, err := p.CreatePayment(context.Background(), payment.CreatePaymentRequest{
		OrderID:     "order-1",
		PaymentType: string(payment.TypeAlipay),
		Amount:      "1.00",
		Subject:     "test",
	})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	msg := err.Error()
	for _, want := range []string{"easypay create", "HTTP 404", "404 Not Found"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q missing %q", msg, want)
		}
	}
}

func TestEasyPayCreateAPIPaymentBadJSON(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(`not json at all`))
	}))
	defer server.Close()

	p := newTestEasyPay(t, server.URL)
	_, err := p.CreatePayment(context.Background(), payment.CreatePaymentRequest{
		OrderID:     "order-2",
		PaymentType: string(payment.TypeAlipay),
		Amount:      "1.00",
		Subject:     "test",
	})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	msg := err.Error()
	for _, want := range []string{"easypay create", "HTTP 200", "not json at all"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q missing %q", msg, want)
		}
	}
}

func TestEasyPayCreateAPIPaymentSuccess(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":1,"msg":"ok","trade_no":"T1","payurl":"https://pay.example.com/p/T1"}`))
	}))
	defer server.Close()

	p := newTestEasyPay(t, server.URL)
	resp, err := p.CreatePayment(context.Background(), payment.CreatePaymentRequest{
		OrderID:     "order-3",
		PaymentType: string(payment.TypeAlipay),
		Amount:      "1.00",
		Subject:     "test",
	})
	if err != nil {
		t.Fatalf("CreatePayment: %v", err)
	}
	if resp.TradeNo != "T1" || resp.PayURL != "https://pay.example.com/p/T1" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestEasyPayQueryOrderHTMLErrorPage(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`<html>502 bad gateway</html>`))
	}))
	defer server.Close()

	p := newTestEasyPay(t, server.URL)
	_, err := p.QueryOrder(context.Background(), "T1")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	msg := err.Error()
	for _, want := range []string{"easypay query", "HTTP 502"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q missing %q", msg, want)
		}
	}
}
