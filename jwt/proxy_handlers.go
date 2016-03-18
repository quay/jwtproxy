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
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos-inc/jwtproxy/proxy"
	"github.com/elazarl/goproxy"
)

func NewJWTSignerHandler() proxy.ProxyHandler {
	return func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		// TODO JWT.
		fmt.Println("Signing request")
		r.Header.Set("X-Jwt-Token", "yxorPoG-X")

		return r, nil
	}
}

func NewJWTVerifierHandler(upstream *url.URL) proxy.ProxyHandler {
	return func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		// TODO JWT.
		fmt.Println("Detected JWT Token:" + r.Header.Get("X-Jwt-Token"))

		// Route the request to upstream.
		rerouteRequest(r, upstream)

		return r, nil
	}
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
