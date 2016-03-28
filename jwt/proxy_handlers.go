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
	"net/http"
	"net/url"
	"strings"

	"github.com/quentin-m/goproxy"

	"github.com/coreos-inc/jwtproxy/config"
	"github.com/coreos-inc/jwtproxy/jwt/keyserver"
	"github.com/coreos-inc/jwtproxy/jwt/noncestorage"
	"github.com/coreos-inc/jwtproxy/jwt/privatekey"
	"github.com/coreos-inc/jwtproxy/proxy"
)

func NewJWTSignerHandler(cfg config.SignerConfig) (proxy.ProxyHandler, error) {
	// Verify config (required keys that have no defaults).
	if cfg.PrivateKey.Type == "" {
		return nil, errors.New("no private key provider specified")
	}

	// Get the private key that will be used for signing.
	privateKeyProvider, err := privatekey.New(cfg.PrivateKey, cfg.SignerParams)
	if err != nil {
		return nil, err
	}

	// Create a ProxyHandler that will add a JWT to http.Requests.
	return func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		privateKey, err := privateKeyProvider.GetPrivateKey()
		if err != nil {
			return r, errorResponse(r, err)
		}

		if err := Sign(r, privateKey, cfg.SignerParams); err != nil {
			return r, errorResponse(r, err)
		}
		return r, nil
	}, nil
}

func NewJWTVerifierHandler(cfg config.VerifierConfig) (proxy.ProxyHandler, error) {
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

	// Create a KeyServer that will provide public keys for signature verification.
	keyServer, err := keyserver.NewReader(cfg.KeyServer)
	if err != nil {
		return nil, err
	}

	// Create a NonceStorage that will create nonces for signing.
	nonceStorage, err := noncestorage.New(cfg.NonceStorage)
	if err != nil {
		return nil, err
	}

	if cfg.Upstream.URL == nil {
		return nil, errors.New("could not start verifier handler: no upstream set")
	}

	// Create a reverse ProxyHandler that will verify JWT from http.Requests.
	return func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		if err = Verify(r, keyServer, nonceStorage, cfg.Audience.URL, cfg.MaxTTL); err != nil {
			return r, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusForbidden, fmt.Sprintf("jwtproxy: unable to verify request: %s", err))
		}

		// Route the request to upstream.
		rerouteRequest(r, cfg.Upstream.URL)

		return r, nil
	}, nil
}

func errorResponse(r *http.Request, err error) *http.Response {
	return goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusBadGateway, fmt.Sprintf("jwtproxy: unable to sign request: %s", err))
}

func rerouteRequest(r *http.Request, upstream *url.URL) {
	upstreamQuery := upstream.RawQuery

	r.URL.Scheme = upstream.Scheme
	r.URL.Host = upstream.Host

	r.URL.Path = singleJoiningSlash(upstream.Path, r.URL.Path)
	if upstreamQuery == "" || r.URL.RawQuery == "" {
		r.URL.RawQuery = upstreamQuery + r.URL.RawQuery
	} else {
		r.URL.RawQuery = upstreamQuery + "&" + r.URL.RawQuery
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
