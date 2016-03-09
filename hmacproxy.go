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
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/coreos-inc/hmacproxy/credential"
	"github.com/coreos-inc/hmacproxy/hmac"
	"github.com/elazarl/goproxy"
)

func CreateSigningProxy(credential credential.Credential) (*goproxy.ProxyHttpServer, error) {
	proxy := goproxy.NewProxyHttpServer()

	proxy.OnRequest().DoFunc(
		func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			if err := hmac.Sign4(r, credential); err != nil {
				response := goproxy.NewResponse(
					r,
					goproxy.ContentTypeText,
					http.StatusBadRequest,
					fmt.Sprintf("Could not sign request: %v", err),
				)
				return r, response
			}
			return r, nil
		})

	return proxy, nil
}

func CreateVerifyingProxy(target *url.URL, credStore credential.CredentialStore) (*httputil.ReverseProxy, error) {
	director := func(req *http.Request) {
		log.Printf("Proxying request %v", req)
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
	}
	return &httputil.ReverseProxy{Director: director}, nil
}
