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

func CreateSigningProxy(target *url.URL, cred credential.Credential) (*httputil.ReverseProxy, error) {
	director := func(req *http.Request) {
		log.Printf("Proxying request %v", req)
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
	}
	return &httputil.ReverseProxy{Director: director}, nil
}

func CreateVerifyingProxy(target *url.URL, cs credential.CredentialStore) (*httputil.ReverseProxy, error) {
	director := func(req *http.Request) {
		log.Printf("Proxying request %v", req)
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
	}
	return &httputil.ReverseProxy{Director: director}, nil
}
