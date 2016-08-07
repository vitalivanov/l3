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
	"fmt"
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
	testPktDataCh = make(chan config.PacketData, 3)
	testPktObj = Init(testPktDataCh)
	logger, err := NDPTestNewLogger("ndpd", "NDPTEST", true)
	if err != nil {
		t.Error("creating logger failed")
	}
	debug.NDPSetLogger(logger)
}

func addTestNbrEntryWithMac(ipAddr string, peerIP string, macAddr string) {
	cache := NeighborCache{
		State:            REACHABLE,
		LinkLayerAddress: macAddr,
		IpAddr:           peerIP,
	}
	link, exists := testPktObj.GetLink(ipAddr)
	if !exists {
		return
	}
	cache.InitCache(link.ReachableTime, link.RetransTimer, cache.IpAddr, ipAddr, link.PortIfIndex, testPktDataCh)
	link.NbrCache[peerIP] = cache
	testPktObj.SetLink(ipAddr, link)
}

func addTestNbrEntry(ipAddr string, peerIP string) {
	cache := NeighborCache{
		State:            REACHABLE,
		LinkLayerAddress: "aa:bb:cc:dd:ee:ff",
		IpAddr:           peerIP,
	}
	link, exists := testPktObj.GetLink(ipAddr)
	if !exists {
		fmt.Println("ERROR: link should exists", ipAddr, "peerIP:", peerIP)
		return
	}
	cache.InitCache(link.ReachableTime, link.RetransTimer, cache.IpAddr, ipAddr, link.PortIfIndex, testPktDataCh)
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

func cacheInitHelper() NeighborCache {
	cache := NeighborCache{}
	cache.InitCache(30000, 1000, "2002::3", "2002::1", 123, testPktDataCh)
	return cache
}

func TestReTransmitTimer(t *testing.T) {
	cache := cacheInitHelper()
	if cache.RetransTimer != nil {
		t.Error("Re-Transmit timer should not be started until reachable timer fires")
	}
	cache.Timer()
	cache.StopReTransmitTimer()
	if cache.RetransTimer != nil {
		t.Error("Failed to stop re-transmit timer")
	}
}

func TestReachableTimer(t *testing.T) {
	cache := cacheInitHelper()
	if cache.ReachableTimer == nil {
		t.Error("Failed to start reachable timer")
	}
	cache.RchTimer()
	cache.StopReachableTimer()
	if cache.ReachableTimer != nil {
		t.Error("Failed to stop Reachable timer")
	}
}

func TestReComputerTimer(t *testing.T) {
	cache := cacheInitHelper()
	if cache.RecomputeBaseTimer == nil {
		t.Error("Failed to start re-compute base timer")
	}
	cache.ReComputeBaseReachableTimer()
	cache.StopReComputeBaseTimer()
	if cache.RetransTimer != nil {
		t.Error("Failed to stop recompute base timer")
	}
}

func TestNeighborCacheInitDeInit(t *testing.T) {
	cache := cacheInitHelper()
	wantCache := NeighborCache{
		ReachableTimeConfig: 30000,
		RetransTimerConfig:  1000,
		IpAddr:              "2002::3",
	}
	wantCache.MyLinkInfo = &ParentLinkInfo{
		IpAddr:   "2002::1",
		IfIndex:  123,
		ReturnCh: testPktDataCh,
	}

	if !reflect.DeepEqual(cache.MyLinkInfo, wantCache.MyLinkInfo) {
		t.Error("Failed populating parent link information")
	}

	if !cache.ReachableTimer.Stop() {
		t.Error("failed stopping reachable timer")
	}

	if !cache.RecomputeBaseTimer.Stop() {
		t.Error("failed to stop recompute timer")
	}

	cache.DeInitCache()

	if cache.RetransTimer != nil {
		t.Error("Failed to stop retranst timer")
	}
	if cache.RecomputeBaseTimer != nil {
		t.Error("Failed to delete recompute timer")
	}
	if cache.ReachableTimer != nil {
		t.Error("Failed to delete reachable timer")
	}
	if cache.MyLinkInfo != nil {
		t.Error("failed to delete neighbor -> parent link information")
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
	link, _ := testPktObj.GetLink(ipS.String())
	cache, exists := link.NbrCache[ipD.String()]
	if !exists {
		t.Error("Initializing failure")
	} else {
		go func() {
			cache.Timer()
		}()
	}

	var pktData config.PacketData
	for {
		select {
		case pktData = <-testPktDataCh:
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
