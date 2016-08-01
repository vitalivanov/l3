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
	_ "fmt"
	"github.com/google/gopacket/pcap"
	"l3/ndp/config"
	"l3/ndp/debug"
	"net"
	"reflect"
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

func addTestNbrEntry(ipAddr string, peerIP string) {
	cache := NeighborCache{
		State:            REACHABLE,
		LinkLayerAddress: "aa:bb:cc:dd:ee:ff",
	}
	link, exists := testPktObj.GetLink(ipAddr)
	if !exists {
		return
	}
	link.NbrCache[peerIP] = cache
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

func dumpLinkInfo(t *testing.T) {
	t.Log(testPktObj.LinkInfo)
}

func TestNDSMsgSend(t *testing.T) {
	ipAddr := "2002::1"
	initTestPacket()
	testPktObj.InitLink(100, "2002::1/64", "00:e0:ec:26:a7:ee")
	//dumpLinkInfo(t)
	addTestNbrEntry(ipAddr, "2002::2")
	initPcapHandlerForTest(t)
	var err error
	err = testPktObj.SendNSMsgIfRequired(ipAddr, testPcapHdl)
	if err == nil {
		t.Error(err)
	}
	err = testPktObj.SendNSMsgIfRequired(ipAddr+"/64", testPcapHdl)
	if err != nil {
		t.Error(err)
	}
	dstIP := "2002::2"
	err = testPktObj.SendUnicastNeighborSolicitation(ipAddr, dstIP, testPcapHdl)
	if err != nil {
		t.Error(err)
	}
}

func TestNeighborCacheReTransmitTimer(t *testing.T) {
	sip := "2002::1/64"
	dip := "2002::2/64"
	ipD, _, _ := net.ParseCIDR(dip)
	ipS, _, _ := net.ParseCIDR(sip)
	srcMac := "00:e0:ec:26:a7:ee"
	initTestPacket()
	testPktObj.InitLink(100, sip, srcMac)
	addTestNbrEntry(ipS.String(), ipD.String())
	pktCh := make(chan config.PacketData, 3)
	link, _ := testPktObj.GetLink(ipS.String())
	cache, exists := link.NbrCache[ipD.String()]
	if !exists {
		t.Error("Initializing failure")
	} else {
		go func() {
			cache.Timer(link.PortIfIndex, ipS.String(), ipD.String(), link.RetransTimer, pktCh)
		}()
	}

	var pktData config.PacketData
	for {
		select {
		case pktData = <-pktCh:
			break
		}
		break
	}

	if !reflect.DeepEqual(pktData.IpAddr, ipS.String()) {
		t.Error("mismatch in src ip", pktData.IpAddr, "!=", ipS.String())
	}
	if !reflect.DeepEqual(pktData.NeighborIp, ipD.String()) {
		t.Error("mismatch in dst ip", pktData.NeighborIp, "!=", ipD.String())
	}
	if pktData.IfIndex != int32(100) {
		t.Error("invalid ifIndex received on packet channel", pktData.IfIndex)
	}
}
