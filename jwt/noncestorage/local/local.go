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

package local

import (
	"time"

	"gopkg.in/yaml.v2"

	"github.com/quay/jwtproxy/config"
	"github.com/quay/jwtproxy/jwt/noncestorage"
	"github.com/quay/jwtproxy/stop"
	"github.com/patrickmn/go-cache"
)

func init() {
	noncestorage.Register("local", constructor)
}

type Local struct {
	*cache.Cache
}

type Config struct {
	PurgeInterval time.Duration `yaml:"purge_interval"`
}

func constructor(registrableComponentConfig config.RegistrableComponentConfig) (noncestorage.NonceStorage, error) {
	var cfg Config
	bytes, err := yaml.Marshal(registrableComponentConfig.Options)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(bytes, &cfg)
	if err != nil {
		return nil, err
	}

	return &Local{
		Cache: cache.New(cache.NoExpiration, cfg.PurgeInterval),
	}, nil
}

func (ln *Local) Verify(nonce string, expiration time.Time) bool {
	if _, found := ln.Get(nonce); found {
		return false
	}
	ln.Set(nonce, struct{}{}, expiration.Sub(time.Now()))
	return true
}

func (ln *Local) Stop() <-chan struct{} {
	return stop.AlreadyDone
}
