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
)

type Credential interface {
	ID() string
	Secret() string
	Service() string
	Region() string
}

type CredentialStore interface {
	LoadCredential(keyID, serviceName, regionName string) (Credential, error)
}

type SingleAccessKey struct {
	KeyID      string
	KeySecret  string
	KeyService string
	KeyRegion  string
}

func (s SingleAccessKey) ID() string {
	return s.KeyID
}

func (s SingleAccessKey) Secret() string {
	return s.KeySecret
}

func (s SingleAccessKey) Service() string {
	return s.KeyService
}

func (s SingleAccessKey) Region() string {
	return s.KeyRegion
}

func (s SingleAccessKey) LoadCredential(keyID, serviceName, regionName string) (Credential, error) {
	if keyID != s.ID() || serviceName != s.Service() || regionName != s.Region() {
		return nil, fmt.Errorf("Unknown key with key id: %s", keyID)
	}
	return s, nil
}
