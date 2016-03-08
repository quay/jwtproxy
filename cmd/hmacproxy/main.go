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

package main

import (
	"github.com/coreos-inc/hmacproxy"
	"log"
	"net/http/httptest"
	"net/url"
)

func main() {
	tmpCred := hmacproxy.SingleAccessKey{"123", "456"}

	signingDest, err := url.Parse("https://www.google.com")
	if err != nil {
		log.Fatal(err)
	}
	signingProxy, err := hmacproxy.CreateSigningProxy(signingDest, tmpCred)
	if err != nil {
		log.Fatal(err)
	}
	signingServer := httptest.NewServer(signingProxy)
	defer signingServer.Close()

	upstream, err := url.Parse("http://localhost:6060")
	if err != nil {
		log.Fatal(err)
	}
	verificationProxy, err := hmacproxy.CreateVerifyingProxy(upstream, tmpCred)
	if err != nil {
		log.Fatal(err)
	}
	verificationServer := httptest.NewServer(verificationProxy)
	defer verificationServer.Close()
}
