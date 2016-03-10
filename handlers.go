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

package hmacproxy

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/coreos-inc/hmacproxy/credential"
	"github.com/elazarl/goproxy"
)

// NewSigningProxy instantiates a new signing proxy with the static credential specified.
func NewSigningProxy(cred credential.Credential) (*goproxy.ProxyHttpServer, error) {
	proxy := goproxy.NewProxyHttpServer()

	proxy.OnRequest().DoFunc(
		func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			if err := Sign4(r, cred); err != nil {
				response := goproxy.NewResponse(
					r,
					goproxy.ContentTypeText,
					http.StatusBadRequest,
					fmt.Sprintf("Could not sign request: %v", err),
				)

				log.Errorf("Could not sign request: %#v (%v)", r, err)

				return r, response
			}

			log.Debugf("Proxying signed request: %#v", r)

			return r, nil
		})

	return proxy, nil
}

// NewVerifyingProxy instantiates a new verifying proxy with the specified
// upstream URL and credential store, which will be used to verify incoming
// requests.
// TODO: Implement TLS.
func NewVerifyingProxy(upstream *url.URL, cs credential.Store, maxSkew time.Duration) (*httputil.ReverseProxy, error) {
	upstreamQuery := upstream.RawQuery
	director := func(r *http.Request) {

		// Verify request.
		cred, err := Verify4(r, cs, maxSkew)
		if err != nil || cred == nil {
			// Invalid or non-existent signature, reject request.
			log.Warningf("Dropping request: %#v (%v)", r, err)

			// TODO: Find a better way to do it.
			panic("Dropping request")
		}

		// Do minimal reverse proxy logic.
		r.URL.Scheme = upstream.Scheme
		r.URL.Host = upstream.Host
		r.URL.Path = singleJoiningSlash(upstream.Path, r.URL.Path)
		if upstreamQuery == "" || r.URL.RawQuery == "" {
			r.URL.RawQuery = upstreamQuery + r.URL.RawQuery
		} else {
			r.URL.RawQuery = upstreamQuery + "&" + r.URL.RawQuery
		}

		// Add headers indicating the validated credential.
		r.Header.Add("X-HMAC-KeyID", cred.ID)
		r.Header.Add("X-HMAC-Region", cred.Region)
		r.Header.Add("X-HMAC-Service", cred.Service)

		log.Debugf("Proxying verified request: %#v", r)
	}

	return &httputil.ReverseProxy{Director: director}, nil
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
