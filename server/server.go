// Package server handles the HTTP logic for implementing an OAuth2 Authorization Code flow
// and then exchanging the obtained token for a signed certificate from a Step CA server.
package server

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/ca"
	"github.com/uptrace/bunrouter"
	"golang.org/x/oauth2"
	"software.sslmate.com/src/go-pkcs12"
)

const (
	csrfTokenMaxAge = 300
)

// An Option configures optional parameters of the Server.
type Option func(*Server)

// WithInsecureCookie sets the server to use insecure cookies.
func WithInsecureCookie(s *Server) {
	s.insecureCookie = true
}

// WithRedirectURL sets the redirect URL to use for the OAuth flow.
// Defaults to "/callback".
func WithRedirectURL(url *url.URL) Option {
	return func(s *Server) {
		s.redirectURL = url
	}
}

// Server is the CA Portal server.
// It provides an HTTP handler that serves the CA Portal routes.
//
// The redirect URL endpoint is used to handle the OAuth2 callback.
// It exchanges the authorization code for an access token
// and then uses that access token to generate a certificate on behalf of the user.
// Once a certificate is generated, it is returned to the user via a PKCS12 bundle.
//
// The certificate request does not include any SANs as it's expected that that's controlled by the provisioner
// configuration in the Step CA server.
type Server struct {
	ca             *ca.Client
	oauth2         *oauth2.Config
	verifier       *oidc.IDTokenVerifier
	httpClient     *http.Client
	insecureCookie bool
	redirectURL    *url.URL
}

// New returns a new Server using the supplied CA client, OAuth2 configuration, and ID token verifier.
func New(ca *ca.Client, config *oauth2.Config, verifier *oidc.IDTokenVerifier, httpClient *http.Client, options ...Option) *Server {
	server := &Server{
		ca:             ca,
		oauth2:         config,
		verifier:       verifier,
		httpClient:     httpClient,
		insecureCookie: false,
		redirectURL:    &url.URL{Path: "/callback"},
	}

	for _, opt := range options {
		opt(server)
	}

	return server
}

func getOIDCProvisioner(resp *api.ProvisionersResponse, name string) (*provisioner.OIDC, error) {
	for _, p := range resp.Provisioners {
		c, ok := p.(*provisioner.OIDC)
		if ok && c.Name == name {
			return c, nil
		}
	}

	return nil, fmt.Errorf("OIDC provisioner %s not found", name)
}

// Discover returns a new Server by automatically discovering configuration from a named OIDC provisioner in the CA.
func Discover(ctx context.Context, client *ca.Client, httpClient *http.Client, provisionerName string, options ...Option) (*Server, error) {
	provisioners, err := client.ProvisionersWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get provisioners: %w", err)
	}

	caProvisioner, err := getOIDCProvisioner(provisioners, provisionerName)
	if err != nil {
		return nil, err
	}

	providerCtx := context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	provider, err := oidc.NewProvider(providerCtx, strings.TrimSuffix(caProvisioner.ConfigurationEndpoint, ".well-known/openid-configuration"))
	if err != nil {
		return nil, err
	}

	var (
		verifier = provider.Verifier(&oidc.Config{ClientID: caProvisioner.ClientID})
		config   = &oauth2.Config{
			ClientID:     caProvisioner.ClientID,
			ClientSecret: caProvisioner.ClientSecret,
			Scopes:       caProvisioner.Scopes,
			Endpoint:     provider.Endpoint(),
		}
	)

	return New(client, config, verifier, httpClient, options...), nil
}

// resolveRedirectURL returns the redirect URL to use for the OAuth flow made relative to the current request.
func (s *Server) resolveRedirectURL(r *http.Request) *url.URL {
	var u = new(url.URL)

	if s.redirectURL.IsAbs() {
		*u = *s.redirectURL

		return u
	}

	// (implicit) trust X-Forwarded-* headers
	var scheme = "http"
	if r.TLS != nil {
		scheme = "https"
	}

	if xfp := r.Header.Get("X-Forwarded-Proto"); xfp != "" {
		scheme = xfp
	}

	var host = r.Host
	if xff := r.Header.Get("X-Forwarded-Host"); xff != "" {
		host = xff
	}

	base := &url.URL{
		Scheme: scheme,
		Host:   host,
	}

	return base.ResolveReference(s.redirectURL)
}

func (s *Server) csrfCookieName() string {
	base := "ca-portal"
	if !s.insecureCookie {
		base = "__Secure-" + base
	}

	return base
}

func (s *Server) httpServeIndex(w http.ResponseWriter, req bunrouter.Request) error {
	var (
		state        = uuid.New().String()
		pkceVerifier = oauth2.GenerateVerifier()
	)

	authCodeURL := s.oauth2.AuthCodeURL(
		state,
		oauth2.S256ChallengeOption(pkceVerifier),
		oauth2.SetAuthURLParam("redirect_uri", s.resolveRedirectURL(req.Request).String()),
	)

	cookie := http.Cookie{
		Name:     s.csrfCookieName(),
		Value:    fmt.Sprintf("%s|%s", state, pkceVerifier),
		Secure:   !s.insecureCookie,
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
		MaxAge:   csrfTokenMaxAge,
		Path:     "/",
	}

	http.SetCookie(w, &cookie)
	http.Redirect(w, req.Request, authCodeURL, http.StatusFound)

	return nil
}

func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) (string, *oidc.IDToken, error) {
	err := r.ParseForm()
	if err != nil {
		return "", nil, Error(http.StatusBadRequest, err)
	}

	if retError := r.FormValue("error"); retError != "" {
		return "", nil, Error(http.StatusBadRequest, fmt.Errorf("%s: %s", retError, r.FormValue("error_description")))
	}

	csrfCookie, err := r.Cookie(s.csrfCookieName())
	if err != nil {
		return "", nil, Error(http.StatusBadRequest, err)
	}

	// Delete CSRF cookie
	http.SetCookie(w, &http.Cookie{
		Name:   s.csrfCookieName(),
		MaxAge: -1,
	})

	csrfState, csrfVerifier, ok := strings.Cut(csrfCookie.Value, "|")
	if !ok {
		return "", nil, Error(http.StatusBadRequest, errors.New("invalid CSRF cookie value"))
	}

	if csrfState != r.FormValue("state") {
		return "", nil, Error(http.StatusBadRequest, errors.New("invalid CSRF state"))
	}

	ctx := context.WithValue(r.Context(), oauth2.HTTPClient, s.httpClient)

	token, err := s.oauth2.Exchange(
		ctx,
		r.FormValue("code"),
		oauth2.VerifierOption(csrfVerifier),
		oauth2.SetAuthURLParam("redirect_uri", s.resolveRedirectURL(r).String()),
	)
	if err != nil {
		return "", nil, Error(http.StatusBadRequest, err)
	}

	jwt, err := s.verifier.Verify(r.Context(), token.AccessToken)
	if err != nil {
		return "", nil, Error(http.StatusBadRequest, err)
	}

	return token.AccessToken, jwt, nil
}

func (s *Server) httpServeCallback(w http.ResponseWriter, req bunrouter.Request) error {
	jwt, token, err := s.handleOAuthCallback(w, req.Request)
	if err != nil {
		return err
	}

	csr, privateKey, err := ca.CreateCertificateRequest(token.Subject)
	if err != nil {
		return err
	}

	resp, err := s.ca.SignWithContext(req.Context(), &api.SignRequest{
		CsrPEM: *csr,
		OTT:    jwt,
	})
	if err != nil {
		return err
	}

	if len(resp.CertChainPEM) == 0 {
		return errors.New("no certificate chain returned")
	}

	leaf := resp.CertChainPEM[0]

	var chain = make([]*x509.Certificate, 0, len(resp.CertChainPEM)-1)
	for _, cert := range resp.CertChainPEM[1:] {
		chain = append(chain, cert.Certificate)
	}

	pfxData, err := pkcs12.Legacy.Encode(privateKey, leaf.Certificate, chain, pkcs12.DefaultPassword)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/x-pkcs12")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.pfx", leaf.Subject.CommonName))
	w.Header().Set("Content-Length", strconv.Itoa(len(pfxData)))
	w.Header().Set("Cache-Control", "private, no-store")
	w.WriteHeader(http.StatusOK)

	_, _ = w.Write(pfxData)

	return nil
}

// Bind registers the CA Portal routes with the given router group.
func (s *Server) Bind(g *bunrouter.Group) {
	g.GET("/", s.httpServeIndex)
	g.GET(s.redirectURL.Path, s.httpServeCallback)
}

// HTTPHandler returns an HTTP handler that serves the CA Portal routes.
func (s *Server) HTTPHandler() http.Handler {
	router := bunrouter.New()
	s.Bind(&router.Group)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := router.ServeHTTPError(w, r)
		if err == nil {
			return
		}

		var he HTTPError
		if !errors.As(err, &he) {
			he = HTTPError{Code: http.StatusInternalServerError, Err: err}
		}

		http.Error(w, he.Error(), he.Code)
	})
}
