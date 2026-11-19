// The traffic example runs both SDK entry points against an in-memory fixture.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	"github.com/emhha/netloom"
	"github.com/emhha/netloom/mitm"
	"github.com/emhha/netloom/nethttp"
	"github.com/emhha/netloom/passive"
	"github.com/emhha/netloom/passive/plugins/infoextract"
	"github.com/emhha/netloom/passive/plugins/serialization"
	"github.com/emhha/netloom/traffic"
)

const host = "traffic-demo.example.com"
const target = "https://" + host + "/main.js"

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/main.js" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = io.WriteString(w, `const fixture = "NETLOOM_DEMO_ALPHA";`)
	}))
	defer origin.Close()

	// The fixture proxy maps only the reserved demo hostname to the local TLS
	// listener. Both entry points use it as their upstream proxy.
	upstream := newFixtureProxy(host+":443", origin.Listener.Addr().String())
	defer upstream.Close()
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw})
	trust, err := netloom.ParseTLSOptions(string(cert), "", "")
	if err != nil {
		return err
	}
	engine, err := netloom.New(netloom.Config{Retries: -1})
	if err != nil {
		return err
	}
	defer engine.Close()

	info := infoextract.New()
	if err := info.AddRule(infoextract.Rule{
		Name: "demo_marker", Pattern: `NETLOOM_DEMO_[A-Z]+`, Scope: "body", Triggers: []string{"NETLOOM_DEMO_"},
	}); err != nil {
		return err
	}
	registry, err := passive.New([]passive.Plugin{info, serialization.New()}, 128)
	if err != nil {
		return err
	}
	reports := make(chan traffic.Report, 1)
	flow, err := traffic.New(traffic.Config{
		Engine: engine, Registry: registry,
		Proxies:  traffic.ProxyConfig{Default: &upstream.URL},
		OnReport: func(report traffic.Report) { reports <- report },
	})
	if err != nil {
		return err
	}
	defer flow.Close()

	input, err := nethttp.ParseCurl("curl " + target)
	if err != nil {
		return err
	}
	request, err := nethttp.BuildRequest(input)
	if err != nil {
		return err
	}
	request.TLSConfig, request.VerifyTLS = trust, true
	_, report, err := flow.Send(ctx, request, traffic.RequestOptions{})
	if err != nil {
		return err
	}
	if err := printReport(report); err != nil {
		return err
	}

	return observeMITM(ctx, flow, trust.Roots, reports)
}

func observeMITM(ctx context.Context, flow *traffic.Traffic, roots *x509.CertPool, reports <-chan traffic.Report) error {
	ca, err := mitm.NewAuthority()
	if err != nil {
		return err
	}
	backend, err := flow.NewMITMBackend(func(_ context.Context, u *url.URL) error {
		if u.Scheme != "https" || u.Hostname() != host || (u.Port() != "" && u.Port() != "443") {
			return errors.New("target is outside the demo")
		}
		return nil
	}, &http.Transport{DisableCompression: true, TLSClientConfig: &tls.Config{RootCAs: roots}})
	if err != nil {
		return err
	}
	defer backend.CloseIdleConnections()
	proxy := mitm.New(ca, backend, mitm.Options{})
	listener := httptest.NewServer(proxy)
	defer listener.Close()
	defer proxy.Close()
	proxyURL, err := url.Parse(listener.URL)
	if err != nil {
		return err
	}
	clientTrust := x509.NewCertPool()
	if !clientTrust.AppendCertsFromPEM(ca.CertificatePEM()) {
		return errors.New("cannot trust the demo MITM CA")
	}
	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: clientTrust},
	}}
	defer client.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	_, readErr := io.Copy(io.Discard, response.Body)
	if err := errors.Join(readErr, response.Body.Close()); err != nil {
		return err
	}
	select {
	case report := <-reports:
		return printReport(report)
	case <-ctx.Done():
		return ctx.Err()
	}
}

func printReport(report traffic.Report) error {
	if err := errors.Join(report.TransportError, report.DecodeError, report.AnalysisError); err != nil {
		return err
	}
	if report.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned HTTP %d", report.Source, report.StatusCode)
	}
	fmt.Printf("%s HTTP %d %s\n", report.Source, report.StatusCode, report.URL)
	for _, result := range report.Results {
		if result.Error != "" {
			return fmt.Errorf("%s: %s", result.PluginID, result.Error)
		}
		fmt.Printf("  %s: %d findings\n", result.PluginID, len(result.Artifacts))
		if result.PluginID == "infoextract" {
			fmt.Printf("    %s\n", result.Data)
		}
		for _, artifact := range result.Artifacts {
			fmt.Printf("    %s (%s)\n", artifact.Rule, artifact.Scope)
		}
	}
	return nil
}
