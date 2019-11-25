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

package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coreos/goproxy"
	"github.com/quay/jwtproxy/stop"
	log "github.com/sirupsen/logrus"
	"github.com/tylerb/graceful"
)

// This tls.Config is borrowed from the CockroachDB project.
var defaultTLSConfig = tls.Config{
	// This is Go's default list of cipher suites (as of go 1.8.3),
	// with the following differences:
	//
	// - 3DES-based cipher suites have been removed. This cipher is
	//   vulnerable to the Sweet32 attack and is sometimes reported by
	//   security scanners. (This is arguably a false positive since
	//   it will never be selected: Any TLS1.2 implementation MUST
	//   include at least one cipher higher in the priority list, but
	//   there's also no reason to keep it around)
	// - AES is always prioritized over ChaCha20. Go makes this decision
	//   by default based on the presence or absence of hardware AES
	//   acceleration.
	//   TODO(bdarnell): do the same detection here. See
	//   https://github.com/golang/go/issues/21167
	//
	// Note that some TLS cipher suite guidance (such as Mozilla's[1])
	// recommend replacing the CBC_SHA suites below with CBC_SHA384 or
	// CBC_SHA256 variants. We do not do this because Go does not
	// currerntly implement the CBC_SHA384 suites, and its CBC_SHA256
	// implementation is vulnerable to the Lucky13 attack and is disabled
	// by default.[2]
	//
	// [1]: https://wiki.mozilla.org/Security/Server_Side_TLS#Modern_compatibility
	// [2]: https://github.com/golang/go/commit/48d8edb5b21db190f717e035b4d9ab61a077f9d7
	PreferServerCipherSuites: true,
	CipherSuites: []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	},

	MinVersion: tls.VersionTLS12,
}

type Handler func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response)

type Proxy struct {
	*goproxy.ProxyHttpServer
	grace           *graceful.Server
	shutdownTimeout time.Duration
	started         bool
}

func (proxy *Proxy) Serve(listenAddr, crtFile, keyFile string, shutdownTimeout time.Duration, socketPermission os.FileMode) error {
	tlsConfig := defaultTLSConfig

	// Create a graceful server.
	proxy.grace = &graceful.Server{
		NoSignalHandling: true,
		Server: &http.Server{
			Addr:      listenAddr,
			Handler:   proxy.ProxyHttpServer,
			TLSConfig: &tlsConfig,
		},
	}
	proxy.shutdownTimeout = shutdownTimeout

	// Create an appropriate net.Listener.
	var err error
	var listener net.Listener

	if strings.HasPrefix(listenAddr, "unix:") {
		if crtFile != "" && keyFile != "" {
			return errors.New("Proxy is configured to terminate TLS but proxy listens on an UNIX socket.")
		}

		unixFile := strings.TrimPrefix(listenAddr, "unix:")

		listener, err = net.Listen("unix", unixFile)
		if err != nil {
			return err
		}

		os.Chmod(unixFile, socketPermission)

		defer os.Remove(unixFile)
	} else {
		if crtFile != "" && keyFile != "" {
			listener, err = proxy.grace.ListenTLS(crtFile, keyFile)
			if err != nil {
				return err
			}
		} else {
			listener, err = net.Listen("tcp", listenAddr)
			if err != nil {
				return err
			}
		}
	}

	// Serve traffic.
	proxy.started = true
	defer func() { proxy.started = false }()

	if err = proxy.grace.Serve(listener); err != nil {
		if opErr, ok := err.(*net.OpError); !ok || (ok && opErr.Op != "accept") {
			return err
		}
	}

	return nil
}

func (proxy *Proxy) Stop() <-chan struct{} {
	if proxy.started {
		proxy.grace.Stop(proxy.shutdownTimeout)
		return proxy.grace.StopChan()
	}
	return stop.AlreadyDone
}

func NewProxy(proxyHandler Handler, caKeyPath, caCertPath string, insecureSkipVerify bool, trustedCertificatePaths []string) (*Proxy, error) {
	var err error

	// Initialize the forward proxy's MITM handler using the specified CA key pair.
	var mitmHandler goproxy.FuncHttpsHandler
	if caKeyPath == "" || caCertPath == "" {
		mitmHandler = rejectMITMHandler()
		log.Warning("No CA keypair specified, the proxy will not be able to forward requests to TLS endpoints.")
	} else {
		mitmHandler, err = setupMITMHandler(caKeyPath, caCertPath)
		if err != nil {
			return nil, err
		}
	}

	// Create a forward proxy.
	proxy := goproxy.NewProxyHttpServer()
	proxy.Tr, err = setupClientTransport(insecureSkipVerify, trustedCertificatePaths)
	if err != nil {
		return nil, err
	}
	proxy.Verbose = log.GetLevel() == log.DebugLevel

	// Handle HTTPs requests with MITM and the specified handler.
	proxy.OnRequest().DoFunc(proxyHandler)
	proxy.OnRequest().HandleConnect(mitmHandler)

	return &Proxy{ProxyHttpServer: proxy}, nil
}

func NewReverseProxy(proxyHandler Handler) (*Proxy, error) {
	// Create a reverse proxy.
	reverseProxy := goproxy.NewReverseProxyHttpServer()
	reverseProxy.Tr = http.DefaultTransport.(*http.Transport)
	reverseProxy.Verbose = log.GetLevel() == log.DebugLevel

	// Handle requests with the specified handler.
	reverseProxy.OnRequest().DoFunc(proxyHandler)

	return &Proxy{ProxyHttpServer: reverseProxy}, nil
}

func setupMITMHandler(caKeyPath, caCertPath string) (goproxy.FuncHttpsHandler, error) {
	ca, err := readCA(caKeyPath, caCertPath)
	if err != nil {
		return nil, err
	}

	return func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		return &goproxy.ConnectAction{
			Action:    goproxy.ConnectMitm,
			TLSConfig: goproxy.TLSConfigFromCA(ca),
		}, host
	}, nil
}

func rejectMITMHandler() goproxy.FuncHttpsHandler {
	return func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		return &goproxy.ConnectAction{
			Action: goproxy.ConnectReject,
		}, host
	}
}

func setupClientTransport(insecureSkipVerify bool, certificatePaths []string) (*http.Transport, error) {
	tlsConfig := defaultTLSConfig
	tlsConfig.InsecureSkipVerify = insecureSkipVerify

	// If any certificates are specified, load them. Otherwise, system-wide certificates are to be
	// used.
	if len(certificatePaths) > 0 {
		// TODO: Instead of creating an empty certificate pool, thus overriding entirely the system
		// pool, we should start from a pool populated by the system roots. This will be possible
		// in Go 1.7 using x509.SystemCertPool().
		// See https://go-review.googlesource.com/#/c/21293/
		tlsConfig.RootCAs = x509.NewCertPool()

		for _, certificatePath := range certificatePaths {
			if certificate, err := ioutil.ReadFile(certificatePath); err == nil {
				tlsConfig.RootCAs.AppendCertsFromPEM(certificate)
			} else {
				return nil, fmt.Errorf("Could not load certificate '%s': %s", certificatePath, err)
			}
		}
	}

	return &http.Transport{
		TLSClientConfig: &tlsConfig,
	}, nil
}

func readCA(caKeyPath, caCertPath string) (*tls.Certificate, error) {
	caCert, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		return nil, err
	}

	caKey, err := ioutil.ReadFile(caKeyPath)
	if err != nil {
		return nil, err
	}

	ca, err := tls.X509KeyPair(caCert, caKey)
	if err != nil {
		return nil, err
	}

	ca.Leaf, err = x509.ParseCertificate(ca.Certificate[0])
	return &ca, err
}
