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

package singlekey

import (
	"fmt"

	"gopkg.in/yaml.v2"

	"github.com/coreos-inc/hmacproxy/config"
	"github.com/coreos-inc/hmacproxy/credential"
)

type singleAccessKey struct {
	credential.Credential
}

func (s singleAccessKey) LoadCredential(keyID, serviceName, regionName string) (*credential.Credential, error) {
	if keyID != s.ID || serviceName != s.Service || regionName != s.Region {
		return nil, fmt.Errorf("Unknown key with key id: %s", keyID)
	}
	return &s.Credential, nil
}

func constructor(cfg *config.CredentialSourceConfig) (credential.Store, error) {
	reserialized, err := yaml.Marshal(cfg.Options)
	if err != nil {
		return nil, fmt.Errorf("unable to marshall configuration: %v", cfg.Options)
	}
	var parsed singleAccessKey
	err = yaml.Unmarshal(reserialized, &parsed)
	if err != nil {
		return nil, fmt.Errorf("unable to parse configuration: %v", reserialized)
	}
	return parsed, nil
}

func init() {
	credential.RegisterStoreConstructor("SingleCredential", constructor)
}
