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
	"github.com/google/gopacket/pcap"
	"testing"
)

var testPcapHdl *pcap.Handle
var testPktObj *Packet

const (
	TEST_PORT = "lo"
)

func initPcapHandlerForTest(t *testing.T) {
	var err error
	testPcapHdl, err = pcap.OpenLive(TEST_PORT, 1024, false, 1)
	if err != nil {
		t.Error("Opening Pcap handler on", TEST_PORT, "failed with error:", err)
		return
	}
}

func initTestPacket() {
	testPktObj = Init()
}

func addTestNbrEntry(ipAddr string) {
	cache := NeighborCache{
		Timer:            120,
		State:            REACHABLE,
		LinkLayerAddress: "00:e0:ec:26:a7:ee",
	}
	testPktObj.NbrCache[ipAddr] = cache
}

func TestSendNDPacket(t *testing.T) {
	err := sendNDPkt(ndsTest, testPcapHdl)
	if err == nil {
		t.Error(err)
	}
	initPcapHandlerForTest(t)
	err = sendNDPkt(ndsTest, testPcapHdl)
	if err != nil {
		t.Error(err)
	}
}

func TestNDSMsgSend(t *testing.T) {
	ipAddr := "2002::1/64"
	initTestPacket()
	addTestNbrEntry(ipAddr)
	initPcapHandlerForTest(t)
	err := testPktObj.SendNSMsgIfRequired(ipAddr, testPcapHdl)
	if err != nil {
		t.Error(err)
	}
}
