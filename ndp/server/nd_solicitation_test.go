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
package server

import (
	"l3/ndp/packet"
	"testing"
)

const (
	testMulticastSolicitationAddr = "ff02::1:ff7c:ca9f"
	testUnspecifiecSrcIp          = "::"
)

func TestProcessNS(t *testing.T) {
	intf := &Interface{}
	ndInfo := &packet.NDInfo{
		DstIp: testMulticastSolicitationAddr,
	}
	nbrInfo, operType := intf.processNS(ndInfo)
	if nbrInfo != nil {
		t.Error("for testMulticastSolicitationAddr nbrInfo should be nil")
		return
	}
	if operType != IGNORE {
		t.Error("for testMulticastSolicitationAddr operation should be IGNORE, but got:", operType)
		return
	}
	ndInfo.SrcIp = testUnspecifiecSrcIp
	ndInfo.DstIp = ""
	nbrInfo, operType = intf.processNS(ndInfo)
	if nbrInfo != nil {
		t.Error("for testUnspecifiecSrcIp nbrInfo should be nil")
		return
	}
	if operType != IGNORE {
		t.Error("for testUnspecifiecSrcIp  operation should be IGNORE, but got:", operType)
		return
	}
}
