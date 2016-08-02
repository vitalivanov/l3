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
package packet

import (
	"net"
	"testing"
)

func dumpLinkInfo(t *testing.T) {
	t.Log(testPktObj.LinkInfo)
}

func TestLinkFlushNeighbor(t *testing.T) {
	initTestPacket()
	ipAddr := "2002::1/64"
	nbrIp := "2002::2"
	testPktObj.InitLink(100, ipAddr, "00:e0:ec:26:a7:ee")
	ip, _, _ := net.ParseCIDR(ipAddr)
	addTestNbrEntry(ip.String(), nbrIp)
	err := testPktObj.FlushNeighbors(ipAddr)
	if err != nil {
		t.Error("Failed to flush neighbor cache from packet LinkInfo, error:", err)
	}
	if len(testPktObj.LinkInfo) > 0 {
		t.Error("failed to delete links from packet linkInfo", testPktObj.LinkInfo)
	}
	err = testPktObj.FlushNeighbors(ipAddr)
	if err == nil {
		t.Error("There is no entry in Neighbor Cache and we still didn't receive error message")
	}
}
