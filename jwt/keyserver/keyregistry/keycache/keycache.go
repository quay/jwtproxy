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

package keycache

import (
	"fmt"

	"github.com/gregjones/httpcache"

	"github.com/quay/jwtproxy/config"
	"github.com/quay/jwtproxy/stop"
)

type Constructor func(config.RegistrableComponentConfig) (Cache, error)

type Cache interface {
	stop.Stoppable
	httpcache.Cache
}

var keycaches = make(map[string]Constructor)

func RegisterCache(name string, c Constructor) {
	if c == nil {
		panic("server: could not register nil ReaderConstructor")
	}
	if _, dup := keycaches[name]; dup {
		panic("server: could not register duplicate ReaderConstructor: " + name)
	}
	keycaches[name] = c
}

func NewCache(cfg config.RegistrableComponentConfig) (Cache, error) {
	c, ok := keycaches[cfg.Type]
	if !ok {
		return nil, fmt.Errorf("server: unknown Cache type %q (forgotten import?)", cfg.Type)
	}
	return c(cfg)
}
