// Package main is the binary application for the CA self-service portal application.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/relvacode/ca-portal/server"
	"github.com/smallstep/certificates/ca"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

const (
	timeoutDiscover       = 30 * time.Second
	timeoutServerShutdown = 5 * time.Second
	timeoutReadHeader     = 5 * time.Second
)

type URLFlag struct {
	url.URL
}

func (f *URLFlag) UnmarshalFlag(value string) error {
	u, err := url.Parse(value)
	if err != nil {
		return err
	}

	f.URL = *u

	return nil
}

type CAOptions struct {
	URL         URLFlag `description:"CA URL"                      env:"URL"         long:"url"         required:"true"`
	Fingerprint string  `description:"CA root certificate SHA256 fingerprint" env:"FINGERPRINT" long:"fingerprint"`
	Provisioner string  `description:"Provisioner name"            env:"PROVISIONER" long:"provisioner" required:"true"`
}

type OIDCOptions struct {
	TLSInsecureSkipVerify bool   `long:"tls-insecure-skip-verify" env:"TLS_INSECURE_SKIP_VERIFY" description:"Skip TLS verification"`
	TLSRootCertFile       string `long:"tls-root-cert-file"       env:"TLS_ROOT_CERT_FILE"       description:"Path to CA root certificate. If disabled, use the system CA certificates"`
}

func (o *OIDCOptions) TLSConfig() (*tls.Config, error) {
	var certPool *x509.CertPool
	if o.TLSRootCertFile != "" {
		certPool = x509.NewCertPool()

		certBytes, err := os.ReadFile(o.TLSRootCertFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA root certificate: %w", err)
		}

		if !certPool.AppendCertsFromPEM(certBytes) {
			return nil, errors.New("failed to append CA root certificate")
		}
	}

	return &tls.Config{
		//nolint:gosec
		InsecureSkipVerify: o.TLSInsecureSkipVerify,
		RootCAs:            certPool,
	}, nil
}

type ServerOptions struct {
	RedirectURL    URLFlag `long:"redirect-url"    env:"REDIRECT_URL"    default:"/callback"                required:"true"              description:"Redirect URL"`
	InsecureCookie bool    `long:"insecure-cookie" env:"INSECURE_COOKIE" description:"Use insecure cookies"`
	ListenHTTPS    string  `long:"listen-https" env:"LISTEN_HTTPS" default:":9443" description:"Listen on this HTTPS address"`
}

type ACMEOptions struct {
	Provisioner string   `long:"provisioner" env:"PROVISIONER" default:"acme" required:"true" description:"The name of your ACME provisioner in step-ca"`
	Domains     []string `long:"domains" env:"DOMAINS" env-delim:"," required:"true" description:"The domains to request certificates for"`
	State       string   `long:"state" env:"STATE" default:"/acme" description:"Where to store certificates generated using ACME"`
	Email       string   `long:"email" env:"EMAIL" required:"true" description:"Email address to use for ACME registration"`
}

func (o *ACMEOptions) TLSConfig(caUrl *url.URL, certPool *x509.CertPool) (*tls.Config, error) {
	caUrlACME := caUrl.ResolveReference(&url.URL{Path: fmt.Sprintf("/acme/%s/directory", o.Provisioner)})

	certManager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Email:      o.Email,
		Cache:      autocert.DirCache(o.State),
		HostPolicy: autocert.HostWhitelist(o.Domains...),
		Client: &acme.Client{
			DirectoryURL: caUrlACME.String(),
			HTTPClient: &http.Client{
				Timeout: timeoutDiscover,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs: certPool,
					},
				},
			},
		},
	}

	return certManager.TLSConfig(), nil
}

type Options struct {
	CA     CAOptions     `group:"CA Options"     env-namespace:"CA"     namespace:"ca"`
	Server ServerOptions `group:"Server Options" env-namespace:"SERVER" namespace:"server"`
	OIDC   OIDCOptions   `group:"OIDC Options"   env-namespace:"OIDC"   namespace:"oidc"`
	ACME   ACMEOptions   `group:"ACME Options"   env-namespace:"ACME"   namespace:"acme"`
}

//nolint:funlen
func Main() error {
	var opts Options

	_, err := flags.NewParser(&opts, flags.HelpFlag).Parse()
	if err != nil {
		return err
	}

	caClient, err := ca.NewClient(opts.CA.URL.String(), ca.WithRootSHA256(opts.CA.Fingerprint))
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	timeoutCtx, timeoutCancel := context.WithTimeout(ctx, timeoutDiscover)
	defer timeoutCancel()

	oidcTLSConfig, err := opts.OIDC.TLSConfig()
	if err != nil {
		return fmt.Errorf("failed to create TLS config for OIDC server: %w", err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: oidcTLSConfig,
		},
	}

	var serverOptions = []server.Option{
		server.WithRedirectURL(&opts.Server.RedirectURL.URL),
	}

	if opts.Server.InsecureCookie {
		serverOptions = append(serverOptions, server.WithInsecureCookie)
	}

	caServer, err := server.Discover(timeoutCtx, caClient, httpClient, opts.CA.Provisioner, serverOptions...)
	if err != nil {
		return err
	}

	httpsServerTlsConfig, err := opts.ACME.TLSConfig(&opts.CA.URL.URL, caClient.GetRootCAs())
	if err != nil {
		return fmt.Errorf("failed to create TLS config for ACME server: %w", err)
	}

	httpServer := &http.Server{
		ReadHeaderTimeout: timeoutReadHeader,
		Handler:           caServer.HTTPHandler(),
		Addr:              opts.Server.ListenHTTPS,
		TLSConfig:         httpsServerTlsConfig,
	}

	ln, err := net.Listen("tcp", opts.Server.ListenHTTPS)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", opts.Server.ListenHTTPS, err)
	}

	defer func() { _ = ln.Close() }()

	tlsListener := tls.NewListener(ln, httpsServerTlsConfig)
	defer func() { _ = tlsListener.Close() }()

	go func() {
		<-ctx.Done()

		timeoutCtx, cancel := context.WithTimeout(context.Background(), timeoutServerShutdown)
		defer cancel()

		//nolint:contextcheck
		_ = httpServer.Shutdown(timeoutCtx)
	}()

	err = httpServer.Serve(tlsListener)
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}

	return err
}

func main() {
	err := Main()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
	}
}
