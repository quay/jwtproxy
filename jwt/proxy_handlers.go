// Copyright 2016 CoreOS, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package jwt

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos/goproxy"
	log "github.com/sirupsen/logrus"

	"github.com/quay/jwtproxy/config"
	"github.com/quay/jwtproxy/jwt/claims"
	"github.com/quay/jwtproxy/jwt/keyserver"
	"github.com/quay/jwtproxy/jwt/noncestorage"
	"github.com/quay/jwtproxy/jwt/privatekey"
	"github.com/quay/jwtproxy/proxy"
	"github.com/quay/jwtproxy/stop"
)

type StoppableProxyHandler struct {
	proxy.Handler
	stopFunc func() <-chan struct{}
}

func NewJWTSignerHandler(cfg config.SignerConfig) (*StoppableProxyHandler, error) {
	// Verify config (required keys that have no defaults).
	if cfg.PrivateKey.Type == "" {
		return nil, errors.New("no private key provider specified")
	}

	// Get the private key that will be used for signing.
	privateKeyProvider, err := privatekey.New(cfg.PrivateKey, cfg.SignerParams)
	if err != nil {
		return nil, err
	}

	// Create a proxy.Handler that will add a JWT to http.Requests.
	handler := func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		privateKey, err := privateKeyProvider.GetPrivateKey()
		if err != nil {
			return r, errorResponse(r, err)
		}

		if err := Sign(r, privateKey, cfg.SignerParams); err != nil {
			return r, errorResponse(r, err)
		}
		return r, nil
	}

	return &StoppableProxyHandler{
		Handler:  handler,
		stopFunc: privateKeyProvider.Stop,
	}, nil
}

func NewJWTVerifierHandler(cfg config.VerifierConfig) (*StoppableProxyHandler, error) {
	// Verify config (required keys that have no defaults).
	if cfg.Upstream.URL == nil {
		return nil, errors.New("no upstream specified")
	}
	if cfg.Audience.URL == nil {
		return nil, errors.New("no audience specified")
	}
	if cfg.KeyServer.Type == "" {
		return nil, errors.New("no key server specified")
	}

	stopper := stop.NewGroup()

	// Create a KeyServer that will provide public keys for signature verification.
	keyServer, err := keyserver.NewReader(cfg.KeyServer)
	if err != nil {
		return nil, err
	}
	stopper.Add(keyServer)

	// Create a NonceStorage that will create nonces for signing.
	nonceStorage, err := noncestorage.New(cfg.NonceStorage)
	if err != nil {
		return nil, err
	}
	stopper.Add(nonceStorage)

	// Create an appropriate routing policy.
	route := newRouter(cfg.Upstream.URL)

	// Create the required list of claims.Verifier.
	var claimsVerifiers []claims.Verifier
	if cfg.ClaimsVerifiers != nil {
		claimsVerifiers = make([]claims.Verifier, 0, len(cfg.ClaimsVerifiers))

		for _, verifierConfig := range cfg.ClaimsVerifiers {
			verifier, err := claims.New(verifierConfig)
			if err != nil {
				return nil, fmt.Errorf("could not instantiate claim verifier: %s", err)
			}

			stopper.Add(verifier)
			claimsVerifiers = append(claimsVerifiers, verifier)
		}
	} else {
		log.Info("No claims verifiers specified, upstream should be configured to verify authorization")
	}

	// Create a reverse proxy.Handler that will verify JWT from http.Requests.
	handler := func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		signedClaims, err := Verify(r, keyServer, nonceStorage, cfg.Audience.URL, cfg.MaxSkew, cfg.MaxTTL)
		if err != nil {
			return r, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusForbidden, fmt.Sprintf("jwtproxy: unable to verify request: %s", err))
		}

		// Run through the claims verifiers.
		for _, verifier := range claimsVerifiers {
			err := verifier.Handle(r, signedClaims)
			if err != nil {
				return r, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusForbidden, fmt.Sprintf("Error verifying claims: %s", err))
			}
		}

		// Route the request to upstream.
		route(r, ctx)

		return r, nil
	}

	return &StoppableProxyHandler{
		Handler:  handler,
		stopFunc: stopper.Stop,
	}, nil
}

func (sph *StoppableProxyHandler) Stop() <-chan struct{} {
	return sph.stopFunc()
}

func errorResponse(r *http.Request, err error) *http.Response {
	return goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusBadGateway, fmt.Sprintf("jwtproxy: unable to sign request: %s", err))
}

type router func(r *http.Request, ctx *goproxy.ProxyCtx)

func newRouter(upstream *url.URL) router {
	if strings.HasPrefix(upstream.String(), "unix:") {
		// Upstream is an UNIX socket.
		// - Use a goproxy.RoundTripper that has an "unix" net.Dial.
		// - Rewrite the request's scheme to be "http" and the host to be the encoded path to the
		//   socket.
		sockPath := strings.TrimPrefix(upstream.String(), "unix:")
		roundTripper := newUnixRoundTripper(sockPath)
		return func(r *http.Request, ctx *goproxy.ProxyCtx) {
			ctx.RoundTripper = roundTripper
			r.URL.Scheme = "http"
			r.URL.Host = sockPath
		}
	}

	// Upstream is an HTTP or HTTPS endpoint.
	// - Set the request's scheme and host to the upstream ones.
	// - Prepend the request's path with the upstream path.
	// - Merge query values from request and upstream.
	return func(r *http.Request, ctx *goproxy.ProxyCtx) {
		r.URL.Scheme = upstream.Scheme
		r.URL.Host = upstream.Host
		r.URL.Path = singleJoiningSlash(upstream.Path, r.URL.Path)

		upstreamQuery := upstream.RawQuery
		if upstreamQuery == "" || r.URL.RawQuery == "" {
			r.URL.RawQuery = upstreamQuery + r.URL.RawQuery
		} else {
			r.URL.RawQuery = upstreamQuery + "&" + r.URL.RawQuery
		}
	}
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

type unixRoundTripper struct {
	*http.Transport
}

func newUnixRoundTripper(sockPath string) *unixRoundTripper {
	dialer := func(network, addr string) (net.Conn, error) {
		return net.Dial("unix", sockPath)
	}

	return &unixRoundTripper{
		Transport: &http.Transport{Dial: dialer},
	}
}

func (urt *unixRoundTripper) RoundTrip(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Response, error) {
	return urt.Transport.RoundTrip(req)
}
