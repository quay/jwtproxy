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

package credential

import (
	"fmt"

	"github.com/coreos-inc/hmacproxy/config"
)

// StoreConstructor is a function which is capable of instantiating a Store.
type StoreConstructor func(*config.CredentialSourceConfig) (Store, error)

var storeFactories = make(map[string]StoreConstructor)

// RegisterStoreConstructor allows one to register a new type of Store.
func RegisterStoreConstructor(name string, csf func(*config.CredentialSourceConfig) (Store, error)) {
	if name == "" {
		panic("credentials: could not register a Store with an empty name")
	}

	if csf == nil {
		panic("credentials: could not register a nil Store")
	}

	if _, dup := storeFactories[name]; dup {
		panic("credentials: RegisterStore called twice for " + name)
	}

	storeFactories[name] = csf
}

// NewStore instantiates and configures a new Store object using the specified
// configuration.
func NewStore(cfg *config.CredentialSourceConfig) (cs Store, err error) {
	constructor, found := storeFactories[cfg.Type]
	if !found {
		err = fmt.Errorf("credentials: Unable to find credential store constructor for %s", cfg.Type)
		return
	}

	cs, err = constructor(cfg)
	return
}

// Store is an interface for loading a Credential from a configurable data
// source.
type Store interface {
	LoadCredential(keyID, serviceName, regionName string) (*Credential, error)
}
