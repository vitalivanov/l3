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
	"l3/ndp/config"
	"l3/ndp/debug"
	"testing"
)

var testPcapHdl *pcap.Handle
var testPktObj *Packet
var testPktDataCh chan config.PacketData

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
	t := &testing.T{}
	testPktDataCh = make(chan config.PacketData)
	testPktObj = Init(testPktDataCh)
	logger, err := NDPTestNewLogger("ndpd", "NDPTEST", true)
	if err != nil {
		t.Error("creating logger failed")
	}
	debug.NDPSetLogger(logger)
}

func addTestNbrEntry(ipAddr string) {
	cache := NeighborCache{
		Timer:            120,
		State:            REACHABLE,
		LinkLayerAddress: "00:e0:ec:26:a7:ee",
	}
	link, _ := testPktObj.GetLink(ipAddr)
	link.NbrCache[ipAddr] = cache
	testPktObj.SetLink(ipAddr, link)
}

func TestSendNDPacket(t *testing.T) {
	initTestPacket()
	err := testPktObj.SendNDPkt(ndsTest, testPcapHdl)
	if err == nil {
		t.Error(err)
	}
	initPcapHandlerForTest(t)
	err = testPktObj.SendNDPkt(ndsTest, testPcapHdl)
	if err != nil {
		t.Error(err)
	}
}

func TestNDSMsgSend(t *testing.T) {
	ipAddr := "2002::1"
	initTestPacket()
	testPktObj.InitLink(100, "2024::1", "aa:bb:cc:dd:ee:ff")
	addTestNbrEntry(ipAddr)
	initPcapHandlerForTest(t)
	var err error
	/*
		@TODO: add below check again
			err := testPktObj.SendNSMsgIfRequired(ipAddr, testPcapHdl)
			if err == nil {
				t.Error(err)
			}
	*/
	err = testPktObj.SendNSMsgIfRequired(ipAddr+"/64", testPcapHdl)
	if err != nil {
		t.Error(err)
	}
}
