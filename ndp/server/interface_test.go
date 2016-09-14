//
//Copyright [2016] [SnapRoute Inc]
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//       Unless required by applicable law or agreed to in writing, software
//       distributed under the License is distributed on an "AS IS" BASIS,
//       WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//       See the License for the specific language governing permissions and
//       limitations under the License.
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
	"testing"
)

var testIntf *Interface

func initTestInterface() {
	initServerBasic()
	testIntf = &Interface{}
}

func deinitTestInterface() []string {
	return testIntf.DeInitIntf()
}

func TestAddIp(t *testing.T) {
	initTestInterface()
	testIntf.addIP(testMyLinkScopeIP)
	if testIntf.linkScope != testMyAbsLinkScopeIP {
		t.Error("Failure converting CIDR to Absoulte Address for", testMyLinkScopeIP)
		return
	}

	testIntf.UpdateIntf(testMyGSIp)
	if testIntf.globalScope != testMyAbsGSIP {
		t.Error("Failure converting CIDR to Abs Address for", testMyGSIp)
		return
	}

	deleteEntries := deinitTestInterface()

	if len(deleteEntries) > 0 {
		t.Error("There should not have any NeighborInfo and we received deleteEntries:", deleteEntries)
		return
	}

	if testIntf.linkScope != "" || testIntf.LinkLocalIp != "" {
		t.Error("Falied to remove ip address", testMyLinkScopeIP)
		return
	}
	if testIntf.globalScope != "" || testIntf.IpAddr != "" {
		t.Error("Falied to remove ip address", testMyGSIp)
		return
	}
	testIntf = nil
}

func validateTimerUpdate(t *testing.T, gCfg NdpConfig, intf Interface) {
	if intf.reachableTime != gCfg.ReachableTime {
		t.Error("Failure in updating reachableTime")
		return
	}

	if intf.retransTime != gCfg.RetransTime {
		t.Error("Failure in updating retransmit timer")
		return
	}

	if intf.raRestransmitTime != gCfg.RaRestransmitTime {
		t.Error("Failure in updating router advertisement timer")
		return
	}
}

func TestTimerUpdate(t *testing.T) {
	intf := Interface{}
	if intf.retransTime != 0 || intf.raRestransmitTime != 0 || intf.reachableTime != 0 {
		t.Error("Initializing interface object failed")
		return
	}
	gCfg := NdpConfig{"default", 200, 100, 245}
	intf.UpdateTimer(gCfg)
	validateTimerUpdate(t, gCfg, intf)
}

func TestInvalidReceiveNdpPkt(t *testing.T) {
	intf := Interface{}
	err := intf.ReceiveNdpPkts(nil)
	if err == nil {
		t.Error("no pcap handler and starting rx for ndp packet should fail")
		return
	}
}

func TestDeleteOneIntf(t *testing.T) {
	TestIPv6IntfCreate(t)
	teststateUpHelperFunc(t)
	l3Port, exists := testNdpServer.L3Port[testIfIndex]
	if !exists {
		t.Error("Failed to get L3 Port for ifIndex:", testIfIndex)
		return
	}
	l3Port.DeleteIntf(testMyGSIp)
	if l3Port.PcapBase.PcapUsers != 1 {
		t.Error("Failed Deleting Interface")
		return
	}
}
