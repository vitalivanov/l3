//
//Copyright [2016] [SnapRoute Inc]
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//	 Unless required by applicable law or agreed to in writing, software
//	 distributed under the License is distributed on an "AS IS" BASIS,
//	 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//	 See the License for the specific language governing permissions and
//	 limitations under the License.
//
// _______  __       __________   ___      _______.____    __    ____  __  .___________.  ______  __    __
// |   ____||  |     |   ____\  \ /  /     /       |\   \  /  \  /   / |  | |           | /      ||  |  |  |
// |  |__   |  |     |  |__   \  V  /     |   (----` \   \/    \/   /  |  | `---|  |----`|  ,----'|  |__|  |
// |   __|  |  |     |   __|   >   <       \   \      \            /   |  |     |  |     |  |     |   __   |
// |  |     |  `----.|  |____ /  .  \  .----)   |      \    /\    /    |  |     |  |     |  `----.|  |  |  |
// |__|     |_______||_______/__/ \__\ |_______/        \__/  \__/     |__|     |__|      \______||__|  |__|
//

// path_test.go
package rib

import (
	_ "l3/bgp/baseobjects"
	_ "l3/bgp/packet"
	_ "net"
	"testing"
)

func TestLocRib(t *testing.T) {
	logger := getLogger(t)
	gConf, _ := getConfObjects("192.168.0.100", uint32(1234), uint32(4321))
	//nConf := base.NewNeighborConf(logger, gConf, nil, *pConf)
	//pathAttrs := constructPathAttrs(pConf.NeighborAddress, pConf.PeerAS, pConf.PeerAS+1)
	locRib := NewLocRib(logger, nil, nil, gConf)
	if locRib != nil {
		t.Log("LocRib successfully created")
	}
}
