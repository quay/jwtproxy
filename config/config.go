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

package config

import (
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

type DefaultVerifierProxyConfig VerifierProxyConfig

// UnmarshalYAML implements the yaml.Unmarshaler interface for URLs.
func (cfg *VerifierProxyConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	tempCfg := DefaultVerifierProxyConfig{
		Enabled:         true,
		ListenAddr:      ":8082",
		SocketPermission: 0755,
		ShutdownTimeout: 5 * time.Second,
		Verifier: VerifierConfig{
			MaxSkew: 5 * time.Minute,
			MaxTTL:  5 * time.Minute,
			NonceStorage: RegistrableComponentConfig{
				Type: "local",
				Options: map[string]interface{}{
					"PurgeInterval": 1 * time.Minute,
				},
			},
		},
	}

	if err := unmarshal(&tempCfg); err != nil {
		return err
	}

	*cfg = VerifierProxyConfig(tempCfg)

	return nil
}

// Represents a config file, which may have configuration for other programs
// as a top level key.
type configFile struct {
	JWTProxy Config
}

// Config is the global configuration
type Config struct {
	SignerProxy     SignerProxyConfig     `yaml:"signer_proxy"`
	VerifierProxies []VerifierProxyConfig `yaml:"verifier_proxies"`
}

type VerifierProxyConfig struct {
	Enabled         bool           `yaml:"enabled"`
	ListenAddr      string         `yaml:"listen_addr"`
	SocketPermission os.FileMode   `yaml:"socket_permission"`
	ShutdownTimeout time.Duration  `yaml:"shutdown_timeout"`
	CrtFile         string         `yaml:"crt_file"`
	KeyFile         string         `yaml:"key_file"`
	Verifier        VerifierConfig `yaml:"verifier"`
}

type SignerProxyConfig struct {
	Enabled             bool          `yaml:"enabled"`
	ListenAddr          string        `yaml:"listen_addr"`
	SocketPermission    os.FileMode   `yaml:"socket_permission"`
	ShutdownTimeout     time.Duration `yaml:"shutdown_timeout"`
	CAKeyFile           string        `yaml:"ca_key_file"`
	CACrtFile           string        `yaml:"ca_crt_file"`
	TrustedCertificates []string      `yaml:"trusted_certificates"`
	InsecureSkipVerify  bool          `yaml:"insecure_skip_verify"`
	Signer              SignerConfig  `yaml:"signer"`
}

type VerifierConfig struct {
	Upstream        URL                          `yaml:"upstream"`
	Audience        URL                          `yaml:"audience"`
	MaxSkew         time.Duration                `yaml:"max_skew"`
	MaxTTL          time.Duration                `yaml:"max_ttl"`
	KeyServer       RegistrableComponentConfig   `yaml:"key_server"`
	NonceStorage    RegistrableComponentConfig   `yaml:"nonce_storage"`
	ClaimsVerifiers []RegistrableComponentConfig `yaml:"claims_verifiers"`
}

type SignerParams struct {
	Issuer         string        `yaml:"issuer"`
	ExpirationTime time.Duration `yaml:"expiration_time"`
	MaxSkew        time.Duration `yaml:"max_skew"`
	NonceLength    int           `yaml:"nonce_length"`
}

type SignerConfig struct {
	SignerParams `yaml:",inline"`
	PrivateKey   RegistrableComponentConfig `yaml:"private_key"`
}

type RegistrableComponentConfig struct {
	Type    string                 `yaml:"type"`
	Options map[string]interface{} `yaml:"options"`
}

// DefaultConfig is a configuration that can be used as a fallback value.
func DefaultConfig() Config {
	return Config{
		SignerProxy: SignerProxyConfig{
			Enabled:         true,
			ListenAddr:      ":8080",
			SocketPermission: 0755,
			ShutdownTimeout: 5 * time.Second,
			Signer: SignerConfig{
				SignerParams: SignerParams{
					Issuer:         "jwtproxy",
					ExpirationTime: 5 * time.Minute,
					MaxSkew:        1 * time.Minute,
					NonceLength:    32,
				},
			},
		},
	}
}

// Load is a shortcut to open a file, read it, and generate a Config.
// It supports relative and absolute paths. Given "", it returns DefaultConfig.
func Load(path string) (config *Config, err error) {
	var cfgFile configFile
	cfgFile.JWTProxy = DefaultConfig()
	if path == "" {
		return &cfgFile.JWTProxy, nil
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

	err = yaml.Unmarshal(d, &cfgFile)
	if err != nil {
		return
	}
	config = &cfgFile.JWTProxy

	return
}
