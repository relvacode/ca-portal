// Package main is the binary application for the CA self-service portal application.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/relvacode/ca-portal/server"
	"github.com/smallstep/certificates/ca"
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
	URL         URLFlag `description:"CA URL"                                 env:"URL"         long:"url"         required:"true"`
	Fingerprint string  `description:"CA root certificate SHA256 fingerprint" env:"FINGERPRINT" long:"fingerprint"`
	Provisioner string  `description:"Provisioner name"                       env:"PROVISIONER" long:"provisioner" required:"true"`
}

type OIDCOptions struct {
	TLSInsecureSkipVerify bool   `long:"tls-insecure-skip-verify" env:"TLS_INSECURE_SKIP_VERIFY" description:"Skip TLS verification"`
	TLSRootCertFile       string `long:"tls-root-cert-file"       env:"TLS_ROOT_CERT_FILE"       description:"Path to CA root certificate. If disabled, use the system CA certificates"`
	TrailingSlash         bool   `long:"trailing-slash"           env:"TRAILING_SLASH"           description:"Does the issuer reported by the OIDC discovery endpoint end in a trailing slash? This option must be set if so as it is not possible for the server to automatically detect this"`
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
	RedirectURL    URLFlag `long:"redirect-url"    env:"REDIRECT_URL"    default:"/callback"                required:"true"                            description:"Redirect URL"`
	InsecureCookie bool    `long:"insecure-cookie" env:"INSECURE_COOKIE" description:"Use insecure cookies"`
	ListenHTTP     string  `long:"listen-http"     env:"LISTEN_HTTP"     default:":8100"                    description:"Listen on this HTTPS address"`
}

type Options struct {
	CA     CAOptions     `group:"CA Options"     env-namespace:"CA"     namespace:"ca"`
	Server ServerOptions `group:"Server Options" env-namespace:"SERVER" namespace:"server"`
	OIDC   OIDCOptions   `group:"OIDC Options"   env-namespace:"OIDC"   namespace:"oidc"`
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

	var discoverOpts = &server.DiscoverOptions{
		HTTPClient:          httpClient,
		IssuerTrailingSlash: opts.OIDC.TrailingSlash,
	}

	caServer, err := server.Discover(timeoutCtx, caClient, opts.CA.Provisioner, discoverOpts, serverOptions...)
	if err != nil {
		return err
	}

	httpServer := &http.Server{
		ReadHeaderTimeout: timeoutReadHeader,
		Handler:           caServer.HTTPHandler(),
		Addr:              opts.Server.ListenHTTP,
	}

	go func() {
		<-ctx.Done()

		timeoutCtx, cancel := context.WithTimeout(context.Background(), timeoutServerShutdown)
		defer cancel()

		//nolint:contextcheck
		_ = httpServer.Shutdown(timeoutCtx)
	}()

	err = httpServer.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}

	return err
}

func main() {
	err := Main()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)

		os.Exit(1)
	}
}
