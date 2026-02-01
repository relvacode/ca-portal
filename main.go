// Package main is the binary application for the CA self service portal application.
package main

import (
	"context"
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

type CAOptions struct {
	URL         string `description:"CA URL"                      env:"URL"         long:"url"         required:"true"`
	RootCert    string `description:"Path to CA root certificate" env:"ROOT_CERT"   long:"root-cert"   required:"true"`
	Provisioner string `description:"Provisioner name"            env:"PROVISIONER" long:"provisioner" required:"true"`
}

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

type ServerOptions struct {
	RedirectURL    URLFlag `default:"/callback"                description:"Redirect URL"   env:"REDIRECT_URL"     long:"redirect-url" required:"true"`
	InsecureCookie bool    `description:"Use insecure cookies" env:"INSECURE_COOKIE"        long:"insecure-cookie"`
	ListenAddr     string  `default:":8080"                    description:"Listen address" env:"LISTEN_ADDR"      long:"listen-addr"`
}

type Options struct {
	CA     CAOptions     `env-namespace:"CA"     group:"CA Options"     namespace:"ca"`
	Server ServerOptions `env-namespace:"SERVER" group:"Server Options" namespace:"server"`
}

func Main() error {
	var opts Options

	_, err := flags.NewParser(&opts, flags.HelpFlag).Parse()
	if err != nil {
		return err
	}

	caClient, err := ca.NewClient(opts.CA.URL, ca.WithRootFile(opts.CA.RootCert))
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	timeoutCtx, timeoutCancel := context.WithTimeout(ctx, timeoutDiscover)
	defer timeoutCancel()

	var serverOptions = []server.Option{
		server.WithRedirectURL(&opts.Server.RedirectURL.URL),
	}

	if opts.Server.InsecureCookie {
		serverOptions = append(serverOptions, server.WithInsecureCookie)
	}

	caServer, err := server.Discover(timeoutCtx, caClient, opts.CA.Provisioner, serverOptions...)
	if err != nil {
		return err
	}

	httpServer := &http.Server{
		ReadHeaderTimeout: timeoutReadHeader,
		Addr:              opts.Server.ListenAddr,
		Handler:           caServer.HTTPHandler(),
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
	}
}
