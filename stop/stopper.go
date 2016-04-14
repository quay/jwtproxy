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

package stop

import (
	"sync"
)

var AlreadyDone <-chan struct{}

func init() {
	closeMe := make(chan struct{})
	close(closeMe)
	AlreadyDone = closeMe
}

type Stoppable interface {
	Stop() <-chan struct{}
}

type Group struct {
	stoppables     []StopperFunc
	stoppablesLock sync.Mutex
}

type StopperFunc func() <-chan struct{}

func NewGroup() *Group {
	return &Group{
		stoppables: make([]StopperFunc, 0),
	}
}

func (cg *Group) Add(toAdd Stoppable) {
	cg.stoppablesLock.Lock()
	defer cg.stoppablesLock.Unlock()

	cg.stoppables = append(cg.stoppables, toAdd.Stop)
}

func (cg *Group) AddFunc(toAddFunc StopperFunc) {
	cg.stoppablesLock.Lock()
	defer cg.stoppablesLock.Unlock()

	cg.stoppables = append(cg.stoppables, toAddFunc)
}

func (cg *Group) Stop() <-chan struct{} {
	cg.stoppablesLock.Lock()
	defer cg.stoppablesLock.Unlock()

	whenDone := make(chan struct{})

	waitChannels := make([]<-chan struct{}, 0, len(cg.stoppables))
	for _, toStop := range cg.stoppables {
		waitFor := toStop()
		if waitFor == nil {
			panic("Someone returned a nil chan from Stop")
		}
		waitChannels = append(waitChannels, waitFor)
	}

	cg.stoppables = make([]StopperFunc, 0)

	go func() {
		for _, waitForMe := range waitChannels {
			<-waitForMe
		}
		close(whenDone)
	}()
	return whenDone
}
