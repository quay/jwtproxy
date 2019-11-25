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

package jwtproxy

import (
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/quay/jwtproxy/config"
	"github.com/quay/jwtproxy/jwt"
	"github.com/quay/jwtproxy/proxy"
	"github.com/quay/jwtproxy/stop"
)

// RunProxies is an utility function that starts both the JWT verifier and signer proxies
// in their own goroutines and returns a stop.Group intance that give the caller the ability to
// stop them gracefully.
// Potential startup errors are sent to the abort chan.
func RunProxies(config *config.Config) (*stop.Group, chan error) {
	stopper := stop.NewGroup()
	abort := make(chan error)

	if config.SignerProxy.Enabled {
		go StartForwardProxy(config.SignerProxy, stopper, abort)
	}

	for _, verifierConfig := range config.VerifierProxies {
		if verifierConfig.Enabled {
			go StartReverseProxy(verifierConfig, stopper, abort)
		}
	}

	return stopper, abort
}

// StartForwardProxy starts a new signer proxy in its own goroutine.
// Also adds a graceful stop function to the specified stop.Group.
// Potential startup errors are sent to the abort chan.
func StartForwardProxy(fpConfig config.SignerProxyConfig, stopper *stop.Group, abort chan<- error) {
	// Create signer.
	signer, err := jwt.NewJWTSignerHandler(fpConfig.Signer)
	if err != nil {
		abort <- fmt.Errorf("Failed to create JWT signer: %s", err)
		return
	}

	// Create forward proxy.
	forwardProxy, err := proxy.NewProxy(signer.Handler, fpConfig.CAKeyFile, fpConfig.CACrtFile, fpConfig.InsecureSkipVerify, fpConfig.TrustedCertificates)
	if err != nil {
		stopper.Add(signer)
		abort <- fmt.Errorf("Failed to create forward proxy: %s", err)
		return
	}

	startProxy(
		abort,
		fpConfig.ListenAddr,
		"",
		"",
		fpConfig.ShutdownTimeout,
		"forward",
		forwardProxy,
		fpConfig.SocketPermission,
	)

	forwardStopper := func() <-chan struct{} {
		done := make(chan struct{})
		go func() {
			<-forwardProxy.Stop()
			<-signer.Stop()
			close(done)
		}()
		return done
	}
	stopper.AddFunc(forwardStopper)
}

// StartReverseProxy starts a new verifier proxy in its own goroutine.
// Also adds a graceful stop function to the specified stop.Group.
// Potential startup errors will be sent to the abort chan.
func StartReverseProxy(rpConfig config.VerifierProxyConfig, stopper *stop.Group, abort chan<- error) {
	// Create verifier.
	verifier, err := jwt.NewJWTVerifierHandler(rpConfig.Verifier)
	if err != nil {
		abort <- fmt.Errorf("Failed to create JWT verifier: %s", err)
		return
	}

	// Create reverse proxy.
	reverseProxy, err := proxy.NewReverseProxy(verifier.Handler)
	if err != nil {
		stopper.Add(verifier)
		abort <- fmt.Errorf("Failed to create reverse proxy: %s", err)
		return
	}

	startProxy(
		abort,
		rpConfig.ListenAddr,
		rpConfig.CrtFile,
		rpConfig.KeyFile,
		rpConfig.ShutdownTimeout,
		"reverse",
		reverseProxy,
		rpConfig.SocketPermission,
	)

	reverseStopper := func() <-chan struct{} {
		done := make(chan struct{})
		go func() {
			<-reverseProxy.Stop()
			<-verifier.Stop()
			close(done)
		}()
		return done
	}
	stopper.AddFunc(reverseStopper)
}

func startProxy(abort chan<- error, listenAddr, crtFile, keyFile string, shutdownTimeout time.Duration, proxyName string, proxy *proxy.Proxy, socketPermission os.FileMode) {
	go func() {
		log.Infof("Starting %s proxy (Listening on '%s')", proxyName, listenAddr)
		if err := proxy.Serve(listenAddr, crtFile, keyFile, shutdownTimeout, socketPermission); err != nil {
			failedToStart := fmt.Errorf("Failed to start %s proxy: %s", proxyName, err)
			abort <- failedToStart
		}
	}()
}
