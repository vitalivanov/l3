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
	t := &testing.T{}
	cache := NeighborCache{
		LinkLayerAddress: "aa:bb:cc:dd:ee:ff",
		IpAddr:           peerIP,
	}
	link, exists := testPktObj.GetLink(ipAddr)
	if !exists {
		t.Error("ERROR: link should exists", ipAddr, "peerIP:", peerIP)
		return
	}
	// Init cache will set the STATE to be In-complete
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
	// add neighbors
	helperForAddingNbr(ipAddr)
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

func TestDelayFirstTimer(t *testing.T) {
	initTestPacket()
	cache := cacheInitHelper()
	cache.DelayProbe()
	if cache.DelayFirstProbeTimer == nil {
		t.Error("Failed to start delay probe timer")
	}
	cache.DelayProbe()
	if cache.DelayFirstProbeTimer == nil {
		t.Error("Failed to reset delay probe timer")
	}

	cache.StopDelayProbeTimer()
	if cache.DelayFirstProbeTimer != nil {
		t.Error("Failed to stop delay probe timer")
	}
	// delete the cache and then restart the proble
	cache.DeInitCache()
	if cache.DelayFirstProbeTimer != nil {
		t.Error("Failed to stop delay probe timer")
	}

	cache = cacheInitHelper()
	cache.DelayProbe()
	if cache.DelayFirstProbeTimer == nil {
		t.Error("Failed to start delay probe timer")
	}
	// delete the cache and make sure delay probe is stopped in that
	cache.DeInitCache()
	if cache.DelayFirstProbeTimer != nil {
		t.Error("Failed to stop delay probe timer")
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

func helperForLinkNbr() (string, string) {
	sip := "2002::1/64"
	dip := "2002::2/64"
	ipD, _, _ := net.ParseCIDR(dip)
	ipS, _, _ := net.ParseCIDR(sip)
	srcMac := "00:e0:ec:26:a7:ee"
	testPktObj.InitLink(100, sip, srcMac)
	addTestNbrEntry(ipS.String(), ipD.String())
	return ipS.String(), ipD.String()
}

func ValidateRcvdPktData(pktData config.PacketData, ipS, ipD string) {
	t := &testing.T{}
	if !reflect.DeepEqual(pktData.IpAddr, ipS) {
		t.Error("mismatch in src ip", pktData.IpAddr, "!=", ipS)
	}
	if !reflect.DeepEqual(pktData.NeighborIp, ipD) {
		t.Error("mismatch in dst ip", pktData.NeighborIp, "!=", ipD)
	}
	if pktData.IfIndex != int32(100) {
		t.Error("invalid ifIndex received on packet channel", pktData.IfIndex)
	}
}

func helperFoValidatingChannelInfo(ipS, ipD string) (pktData config.PacketData) {
	//t := &testing.T{}
	for {
		select {
		case pktData = <-testPktDataCh:
			break
		}
		break
	}
	ValidateRcvdPktData(pktData, ipS, ipD)
	return pktData
}

func ValidateRetryUnicastSoliciation(pktData config.PacketData) (deleteEntries []string) {
	t := &testing.T{}
	// Send a packet on delay retry
	retry := testPktObj.RetryUnicastSolicitation(pktData.IpAddr, pktData.NeighborIp, testPcapHdl)
	if !retry {
		// delete single Neighbor entry from Neighbor Cache
		deleteEntries, err := testPktObj.DeleteNeighbor(pktData.IpAddr, pktData.NeighborIp)
		if len(deleteEntries) > 0 && err == nil {
			return deleteEntries
		} else {
			t.Error("We should have got delete request for Nbr", pktData.NeighborIp)
		}
	}
	return deleteEntries
}

func ValidateProbes(ipS, ipD string, quit chan bool, t *testing.T) {
	link, _ := testPktObj.GetLink(ipS)
	exit := false
	for {
		select {
		case pktData := <-testPktDataCh:
			ValidateRcvdPktData(pktData, ipS, ipD)
			deleteEntries := ValidateRetryUnicastSoliciation(pktData)
			if len(deleteEntries) == 0 { // then you validate neighbor information
				cache, exists := link.NbrCache[ipD]
				if !exists {
					t.Error("Initializing failure")
					exit = true
				}

				if cache.ProbesSent == 0 {
					continue
				} else {
					if cache.State != PROBE {
						t.Error("Updating State from DELAY to PROBE failed on Delay Timer Expiry")
						exit = true
						//break
					} else {
						if cache.RetransTimer == nil {
							t.Error("Failer to restart re-transmit timer even when state is PROBE")
							exit = true
						}
					}
				}
			} else {
				exit = true
			}
		}
		if exit {
			quit <- true
			return
		}
	}
}

func TestNeighborCacheDelayTransmitTimer(t *testing.T) {
	initTestPacket()
	initPcapHandlerForTest(t)
	ipS, ipD := helperForLinkNbr()
	link, _ := testPktObj.GetLink(ipS)
	cache, exists := link.NbrCache[ipD]
	if !exists {
		t.Error("Initializing failure")
		return
	}
	// set state to be reachable for testing purpose
	cache.State = REACHABLE
	link.NbrCache[ipD] = cache
	testPktObj.SetLink(ipS, link)

	//start delay timer and test functionality of only delay timer
	go func() {
		cache.DelayProbe()
	}()

	//wait for delay timer expiry
	pktData := helperFoValidatingChannelInfo(ipS, ipD)
	ValidateRetryUnicastSoliciation(pktData)
	cache, exists = link.NbrCache[ipD]
	if !exists {
		t.Error("Initializing failure")
	}

	if cache.State != DELAY {
		t.Error("Update Stating from REACHABLE to DELAY failed on Reachable Timer Expiry")
		return
	}

	// re-start delay time and test functionality of delay timer triggering re-transmit timer
	cache.StopReTransmitTimer() // just making sure that re-transmit is stopped
	cache.State = REACHABLE
	cache.ProbesSent = 0
	link.NbrCache[ipD] = cache
	testPktObj.SetLink(ipS, link)
	quit := make(chan bool)
	go ValidateProbes(ipS, ipD, quit, t)
	cache, exists = link.NbrCache[ipD]
	if !exists {
		t.Error("Initializing failure")
	}
	go func() {
		cache.DelayProbe()
	}()

	<-quit
}

func TestNeighborCacheReTransmitTimer(t *testing.T) {
	initTestPacket()
	ipS, ipD := helperForLinkNbr()
	link, _ := testPktObj.GetLink(ipS)
	cache, exists := link.NbrCache[ipD]
	if !exists {
		t.Error("Initializing failure")
	} else {
		go func() {
			cache.Timer()
		}()
	}
	_ = helperFoValidatingChannelInfo(ipS, ipD)
}
