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
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/coreos-inc/hmacproxy/credential"
)

// NewSigningProxy instantiates a new signing proxy with the target url and the
// statc credential specified.
func NewSigningProxy(target *url.URL, cred credential.Credential) (*httputil.ReverseProxy, error) {
	director := func(req *http.Request) {
		log.Printf("Proxying request %v", req)
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
	}
	return &httputil.ReverseProxy{Director: director}, nil
}

// NewVerifyingProxy instantiates a new verifying proxy with the specified
// upstream URL and credential store, which will be used to verify incoming
// requests.
func NewVerifyingProxy(upstream *url.URL, cs credential.Store) (*httputil.ReverseProxy, error) {
	director := func(req *http.Request) {
		log.Printf("Proxying request %v", req)
		req.URL.Scheme = upstream.Scheme
		req.URL.Host = upstream.Host
	}
	return &httputil.ReverseProxy{Director: director}, nil
}
