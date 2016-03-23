// Copyright 2015 CoreOS, Inc
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
	"encoding/json"
	"math/rand"
	"time"

	"github.com/coreos-inc/jwtproxy/config"
	"github.com/coreos-inc/jwtproxy/jwt/noncestorage"
	"github.com/patrickmn/go-cache"
)

const (
	letterBytes   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

func init() {
	noncestorage.Register("local", constructor)
}

type Local struct {
	*cache.Cache
	Length     int
	randSource rand.Source
}

type Config struct {
	Length        int
	PurgeInterval time.Duration
}

func constructor(registrableComponentConfig config.RegistrableComponentConfig) (noncestorage.NonceStorage, error) {
	var cfg Config
	bytes, err := json.Marshal(registrableComponentConfig.Options)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(bytes, &cfg)
	if err != nil {
		return nil, err
	}

	return &Local{
		Cache:      cache.New(cache.NoExpiration, cfg.PurgeInterval),
		Length:     cfg.Length,
		randSource: rand.NewSource(time.Now().UnixNano()),
	}, nil
}

func (ln *Local) Verify(nonce string, expiration time.Time) bool {
	if _, found := ln.Get(nonce); found {
		return false
	}
	ln.Set(nonce, struct{}{}, expiration.Sub(time.Now()))
	return true
}

func (ln *Local) Generate() (string, error) {
	for {
		n := randStringBytesMask(ln.randSource, ln.Length)
		if _, found := ln.Get(n); !found {
			return n, nil
		}
	}
}

func randStringBytesMask(randSource rand.Source, n int) string {
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, randSource.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = randSource.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}
	return string(b)
}
