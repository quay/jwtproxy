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

package noncestorage

import (
	"fmt"
	"time"

	"github.com/quay/jwtproxy/config"
	"github.com/quay/jwtproxy/stop"
)

type Constructor func(config.RegistrableComponentConfig) (NonceStorage, error)

type NonceStorage interface {
	stop.Stoppable
	Verify(nonce string, expiration time.Time) bool
}

var storages = make(map[string]Constructor)

func Register(name string, nsc Constructor) {
	if nsc == nil {
		panic("server: could not register nil NonceStorage")
	}
	if _, dup := storages[name]; dup {
		panic("server: could not register duplicate NonceStorage: " + name)
	}
	storages[name] = nsc
}

func New(cfg config.RegistrableComponentConfig) (NonceStorage, error) {
	nsc, ok := storages[cfg.Type]
	if !ok {
		return nil, fmt.Errorf("server: unknown NonceStorage %q (forgotten import?)", cfg.Type)
	}
	return nsc(cfg)
}
