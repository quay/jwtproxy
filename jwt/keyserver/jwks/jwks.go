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

package jwks

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sync"

	"github.com/coreos/go-oidc/key"
	"github.com/gregjones/httpcache"
	"gopkg.in/yaml.v2"

	"github.com/coreos/jwtproxy/config"
	"github.com/coreos/jwtproxy/jwt/keyserver"
	"github.com/coreos/jwtproxy/jwt/keyserver/jwks/keycache"
)

func init() {
	keyserver.RegisterReader("jwks", constructReader)
}

type client struct {
	cache        keycache.Cache
	jwks         *url.URL
	signerParams config.SignerParams
	stopping     chan struct{}
	inFlight     *sync.WaitGroup
	httpClient   *http.Client
}

type Config struct {
	Jwks config.URL `yaml:"jwks"`
}

type ReaderConfig struct {
	Config `yaml:",inline"'`
	Cache  *config.RegistrableComponentConfig `yaml:"cache"`
}

func (krc *client) GetPublicKey(issuer string, keyID string) (*key.PublicKey, error) {
	// Query java web key set for a public key matching the given issuer and key ID.
	pubkeyURL := krc.absURL(keyID)
	pubkeyReq, err := krc.prepareRequest("GET", pubkeyURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := krc.httpClient.Do(pubkeyReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		switch resp.StatusCode {
		case http.StatusNotFound:
			return nil, keyserver.ErrPublicKeyNotFound
		case http.StatusForbidden:
			return nil, keyserver.ErrPublicKeyExpired
		default:
			return nil, keyserver.ErrUnkownResponse
		}
	}

	// Decode the public key we received as a JSON-encoded JWK.
	var pk key.PublicKey
	jsonDecoder := json.NewDecoder(resp.Body)
	err = jsonDecoder.Decode(&pk)
	if err != nil {
		return nil, err
	}

	return &pk, nil
}

func (krc *client) Stop() <-chan struct{} {
	finished := make(chan struct{})
	// Stop the in flight requests
	close(krc.stopping)
	go func() {
		krc.inFlight.Wait()

		// Now stop the cache
		if krc.cache != nil {
			<-krc.cache.Stop()
		}

		close(finished)
	}()
	return finished
}

func (krc *client) prepareRequest(method string, url *url.URL, body io.Reader) (*http.Request, error) {
	// Create an HTTP request to the key server to publish a new key.
	req, err := http.NewRequest(method, url.String(), body)
	if err != nil {
		return nil, err
	}

	if method == "PUT" || method == "POST" {
		req.Header.Add("Content-Type", "application/json")
	}

	// Add our user agent.
	req.Header.Set("User-Agent", "JWTProxy/0.1.0")

	return req, nil
}

func (krc *client) absURL(pathParams ...string) *url.URL {
	escaped := make([]string, 0, len(pathParams)+1)
	escaped = append(escaped, krc.jwks.Path)
	for _, pathParam := range pathParams {
		escaped = append(escaped, url.QueryEscape(pathParam))
	}

	absPath := path.Join(escaped...)
	relurl, err := url.Parse(absPath)
	if err != nil {
		panic(err)
	}
	return krc.jwks.ResolveReference(relurl)
}

func constructReader(registrableComponentConfig config.RegistrableComponentConfig) (keyserver.Reader, error) {
	bytes, err := yaml.Marshal(registrableComponentConfig.Options)
	if err != nil {
		return nil, err
	}
	var cfg ReaderConfig
	err = yaml.Unmarshal(bytes, &cfg)
	if err != nil {
		return nil, err
	}

	// Construct the public key cache.
	cacheConfig := config.RegistrableComponentConfig{
		Type: "memory",
	}
	if cfg.Cache != nil {
		cacheConfig = *cfg.Cache
	}

	cache, err := keycache.NewCache(cacheConfig)
	if err != nil {
		return nil, fmt.Errorf("Unable to construct cache: %s", err)
	}

	httpClient := &http.Client{
		Transport: httpcache.NewTransport(cache),
	}

	return &client{
		jwks:       cfg.Jwks.URL,
		inFlight:   &sync.WaitGroup{},
		stopping:   make(chan struct{}),
		cache:      cache,
		httpClient: httpClient,
	}, nil
}
