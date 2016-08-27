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
	"fmt"
	_ "github.com/google/gopacket/pcap"
	"infra/sysd/sysdCommonDefs"
	"l3/ndp/config"
	"l3/ndp/debug"
	"log/syslog"
	"testing"
	asicdmock "utils/asicdClient/mock"
	"utils/logging"
)

const (
	TEST_NBR_ENTRIES     = 5
	testIfIndex          = 100
	testIntfRef          = "lo"
	testSwitchMac        = "c8:1f:66:ea:ae:fc"
	testMyGSIp           = "2192::168:1:1/64"
	testMyLinkScopeIP    = "fe80::77:9cf8:fcff:fe4a:1615/16"
	testMyAbsGSIP        = "2192::168:1:1"
	testMyAbsLinkScopeIP = "fe80::77:9cf8:fcff:fe4a:1615"
	testSrcMac           = "88:1d:fc:cf:15:fc"

	testReachableTimerValue = 30000
	estReTransmitTimerValue = 1000
)

var testNdpServer *NDPServer
var testIpv6GSNotifyObj *config.IPIntfNotification
var testIpv6LSNotifyObj *config.IPIntfNotification
var testServerInitdone chan bool
var testServerQuit chan bool

var testPorts []config.PortInfo

func NDPTestNewLogger(name string, tag string, listenToConfig bool) (*logging.Writer, error) {
	var err error
	srLogger := new(logging.Writer)
	srLogger.MyComponentName = name

	srLogger.SysLogger, err = syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, tag)
	if err != nil {
		fmt.Println("Failed to initialize syslog - ", err)
		return srLogger, err
	}

	srLogger.GlobalLogging = true
	srLogger.MyLogLevel = sysdCommonDefs.INFO
	return srLogger, err
}

func initServerBasic() {
	t := &testing.T{}
	logger, err := NDPTestNewLogger("ndpd", "NDPTEST", true)
	if err != nil {
		t.Error("creating logger failed")
	}
	debug.NDPSetLogger(logger)
}

func initPhysicalPorts() {
	port := config.PortInfo{
		IntfRef:   "lo",
		IfIndex:   testIfIndex,
		Name:      "Loopback0",
		OperState: "UP",
		MacAddr:   "aa:bb:cc:dd:ee:ff",
	}
	testNdpServer.PhyPort[port.IfIndex] = port
	port = config.PortInfo{
		IntfRef:   "lo1",
		IfIndex:   96,
		Name:      "Loopback1",
		OperState: "UP",
		MacAddr:   "aa:bb:cc:dd:ee:ff",
	}
	testNdpServer.PhyPort[port.IfIndex] = port
	port = config.PortInfo{
		IntfRef:   "lo2",
		IfIndex:   97,
		Name:      "Loopback2",
		OperState: "UP",
		MacAddr:   "aa:bb:cc:dd:ee:ff",
	}
	testNdpServer.PhyPort[port.IfIndex] = port
	port = config.PortInfo{
		IntfRef:   "lo3",
		IfIndex:   98,
		Name:      "Loopback3",
		OperState: "UP",
		MacAddr:   "aa:bb:cc:dd:ee:ff",
	}
	testNdpServer.PhyPort[port.IfIndex] = port
	port = config.PortInfo{
		IntfRef:   "lo4",
		IfIndex:   99,
		Name:      "Loopback4",
		OperState: "UP",
		MacAddr:   "aa:bb:cc:dd:ee:ff",
	}
	testNdpServer.PhyPort[port.IfIndex] = port
	port = config.PortInfo{
		IntfRef:   "lo5",
		IfIndex:   95,
		Name:      "Loopback5",
		OperState: "UP",
		MacAddr:   "aa:bb:cc:dd:ee:ff",
	}
	testNdpServer.PhyPort[port.IfIndex] = port
}

func InitNDPTestServer() {
	initServerBasic()
	testServerInitdone = make(chan bool)
	testServerQuit = make(chan bool)
	testNdpServer = NDPNewServer(&asicdmock.MockAsicdClientMgr{})
	testNdpServer.NDPStartServer()
	initPhysicalPorts()
	testIpv6GSNotifyObj = &config.IPIntfNotification{
		IfIndex: testIfIndex,
		IpAddr:  testMyGSIp,
	}

	testIpv6LSNotifyObj = &config.IPIntfNotification{
		IfIndex: testIfIndex,
		IpAddr:  testMyLinkScopeIP,
	}
	testNdpServer.SwitchMac = testSwitchMac
}

func TestNDPStartServer(t *testing.T) {
	InitNDPTestServer()
}

func TestIPv6IntfCreate(t *testing.T) {
	InitNDPTestServer() // event listener channel is already running

	ipv6Obj := &config.IPIntfNotification{
		IfIndex:   testIfIndex,
		IpAddr:    testMyGSIp,
		Operation: config.CONFIG_CREATE,
		IntfRef:   testIntfRef,
	}
	t.Log("Ports Created are:", testNdpServer.PhyPort)
	testNdpServer.HandleIPIntfCreateDelete(ipv6Obj)
	ipv6Obj.IpAddr = testMyLinkScopeIP
	testNdpServer.HandleIPIntfCreateDelete(ipv6Obj)

	t.Log(testNdpServer.L3Port)
	l3Port, exists := testNdpServer.L3Port[testIfIndex]
	if !exists {
		t.Error("failed to init interface")
		return
	}

	if l3Port.IpAddr != testMyGSIp {
		t.Error("failed to set l3 port global scope ip address. wanted:", testMyGSIp, "got:", l3Port.IpAddr)
		return
	}

	if l3Port.globalScope != testMyAbsGSIP {
		t.Error("failed to set l3 port global scope ip address. wanted:", testMyAbsGSIP, "got:", l3Port.globalScope)
		return
	}

	if l3Port.LinkLocalIp != testMyLinkScopeIP {
		t.Error("failed to set l3 port global scope ip address. wanted:", testMyLinkScopeIP, "got:", l3Port.LinkLocalIp)
		return
	}

	if l3Port.linkScope != testMyAbsLinkScopeIP {
		t.Error("failed to set l3 port link scope ip address. wanted:", testMyAbsLinkScopeIP, "got:", l3Port.linkScope)
		return
	}

	if l3Port.PcapBase.PcapUsers != 0 {
		t.Error("pcap users added even when we did not received STATE UP Notification", l3Port.PcapBase.PcapUsers)
		return
	}
}

func TestIPv6IntfDelete(t *testing.T) {
	TestIPv6IntfCreate(t)
	ipv6Obj := &config.IPIntfNotification{
		IfIndex:   testIfIndex,
		IpAddr:    testMyGSIp,
		Operation: config.CONFIG_DELETE,
	}
	testNdpServer.HandleIPIntfCreateDelete(ipv6Obj)

	l3Port, exists := testNdpServer.L3Port[testIfIndex]
	if !exists {
		t.Error("Failed to get L3 Port for ifIndex:", testIfIndex)
		return
	}

	if l3Port.IpAddr != "" {
		t.Error("Failed to delete global scope IP Address:", l3Port.IpAddr)
		return
	}

	if l3Port.globalScope != "" {
		t.Error("Failed to delete global scope IP Address:", l3Port.globalScope)
	}

	ipv6Obj.IpAddr = testMyLinkScopeIP

	testNdpServer.HandleIPIntfCreateDelete(ipv6Obj)

	l3Port, exists = testNdpServer.L3Port[testIfIndex]
	if !exists {
		t.Error("Failed to get L3 Port for ifIndex:", testIfIndex)
		return
	}

	if l3Port.LinkLocalIp != "" {
		t.Error("Failed to delete Link Scope Ip Address:", l3Port.LinkLocalIp)
		return
	}

	if l3Port.linkScope != "" {
		t.Error("Failed to delete link scope iP address:", l3Port.linkScope)
		return
	}
}

func TestIPv6IntfStateUpDown(t *testing.T) {
	TestIPv6IntfCreate(t)
	stateObj := config.StateNotification{
		IfIndex: testIfIndex,
		State:   config.STATE_UP,
		IpAddr:  testMyLinkScopeIP,
	}
	t.Log(stateObj)
	testNdpServer.HandleStateNotification(&stateObj)

	l3Port, _ := testNdpServer.L3Port[testIfIndex]
	if l3Port.PcapBase.PcapHandle == nil {
		t.Error("Failed to initialize pcap handler")
		return
	}

	if l3Port.PcapBase.PcapCtrl == nil {
		t.Error("failed to initialize pcap ctrl")
		return
	}

	if l3Port.PcapBase.PcapUsers != 1 {
		t.Error("Failed to add first pcap user")
		return
	}

	stateObj.State = config.STATE_UP
	stateObj.IpAddr = testMyGSIp

	t.Log(stateObj)

	testNdpServer.HandleStateNotification(&stateObj)
	l3Port, _ = testNdpServer.L3Port[testIfIndex]
	if l3Port.PcapBase.PcapHandle == nil {
		t.Error("Failed to initialize pcap handler")
		return
	}

	if l3Port.PcapBase.PcapCtrl == nil {
		t.Error("failed to initialize pcap ctrl")
		return
	}

	if l3Port.PcapBase.PcapUsers != 2 {
		t.Error("Failed to add second pcap user")
		return
	}

}
