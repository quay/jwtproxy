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

package config

import (
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"time"

	"gopkg.in/yaml.v2"
)

// URL is a custom URL type that allows validation at configuration load time.
type URL struct {
	*url.URL
}

// UnmarshalYAML implements the yaml.Unmarshaler interface for URLs.
func (u *URL) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}

	urlp, err := url.Parse(s)
	if err != nil {
		return err
	}
	u.URL = urlp
	return nil
}

// MarshalYAML implements the yaml.Marshaler interface for URLs.
func (u URL) MarshalYAML() (interface{}, error) {
	if u.URL != nil {
		return u.String(), nil
	}
	return nil, nil
}

// Represents a config file, which may have configuration for other programs
// as a top level key.
type configFile struct {
	JWTProxy *Config
}

// Config is the global configuration
type Config struct {
	SignerProxy   SignerProxyConfig   `yaml:"signer_proxy"`
	VerifierProxy VerifierProxyConfig `yaml:"verifier_proxy"`
}

type VerifierProxyConfig struct {
	ListenAddr string         `yaml:"listen_addr"`
	CrtFile    string         `yaml:"crt_file"`
	KeyFile    string         `yaml:"key_file"`
	Verifier   VerifierConfig `yaml:"verifier"`
}

type SignerProxyConfig struct {
	ListenAddr string       `yaml:"listen_addr"`
	CAKeyFile  string       `yaml:"ca_key_file"`
	CACrtFile  string       `yaml:"ca_crt_file"`
	Signer     SignerConfig `yaml:"signer"`
}

type VerifierConfig struct {
	Upstream     URL                        `yaml:"upstream"`
	Audience     URL                        `yaml:"audience"`
	MaxTTL       time.Duration              `yaml:"max_ttl"`
	KeyServer    RegistrableComponentConfig `yaml:"key_server"`
	NonceStorage RegistrableComponentConfig `yaml:"nonce_storage"`
}

type SignerConfig struct {
	Issuer       string                     `yaml:"issuer"`
	MaxSkew      time.Duration              `yaml:"max_skew"`
	PrivateKey   RegistrableComponentConfig `yaml:"private_key"`
	NonceStorage RegistrableComponentConfig `yaml:"nonce_storage"`
}

type RegistrableComponentConfig struct {
	Type    string                 `yaml:"type"`
	Options map[string]interface{} `yaml:"options"`
}

// DefaultConfig is a configuration that can be used as a fallback value.
var DefaultConfig = configFile{
	JWTProxy: &Config{
	//TODO
	},
}

// Load is a shortcut to open a file, read it, and generate a Config.
// It supports relative and absolute paths.
func Load(path string) (config *Config, err error) {
	cFile := &DefaultConfig
	if path == "" {
		err = fmt.Errorf("A configuration file is required")
		return
	}

	f, err := os.Open(os.ExpandEnv(path))
	if err != nil {
		return
	}
	defer f.Close()

	d, err := ioutil.ReadAll(f)
	if err != nil {
		return
	}

	err = yaml.Unmarshal(d, cFile)
	if err != nil {
		return
	}

	config = cFile.JWTProxy
	return
}

type RegistrableComponentConfig struct {
	Type    string                 `yaml:"type"`
	Options map[string]interface{} `yaml:"options"`
}
