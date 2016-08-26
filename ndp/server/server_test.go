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
	"strconv"
	"testing"
	asicdmock "utils/asicdClient/mock"
	"utils/logging"
)

const (
	TEST_NBR_ENTRIES     = 5
	testIfIndex          = 100
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
		IntfRef:   "lo0",
		IfIndex:   95,
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
		IfIndex:   100,
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

// _Test ND Solicitation message Decoder
func _TestInvalidInitPortInfo(t *testing.T) {
	svr := &NDPServer{}
	svr.InitGlobalDS()

	if len(svr.PhyPort) > 0 {
		t.Error("There should not be any elements in the system port map", len(svr.PhyPort))
	}
	svr.DeInitGlobalDS()

	if svr.PhyPort != nil {
		t.Error("De-Init for ndp port info didn't happen")
	}
}

// _Test ND Solicitation message Decoder
func _TestInvalidInitL3Info(t *testing.T) {
	svr := &NDPServer{}
	svr.InitGlobalDS()
	/*
		svr.InitSystemIPIntf(nil, nil)

		if len(svr.L3Port) > 0 {
			t.Error("There should not be any elements in the system ip map", len(svr.L3Port))
		}
	*/
	svr.DeInitGlobalDS()

	if svr.L3Port != nil {
		t.Error("De-Init for ndp l3 info didn't happen")
	}
}

// _Test Pcap Create
func _TestPcapCreate(t *testing.T) {
	/*
		var err error
		var pcapHdl *pcap.Handle
		logger, err := NDPTestNewLogger("ndpd", "NDPTEST", true)
		if err != nil {
			t.Error("creating logger failed")
		}
		debug.NDPSetLogger(logger)
		svr := NDPNewServer(nil)
		svr.InitGlobalDS()
		pcapHdl, err = svr.CreatePcapHandler("lo")
		if err != nil {
			t.Error("Pcap Create Failed", err)
		}
		svr.DeletePcapHandler(&pcapHdl)
		if pcapHdl != nil {
			t.Error("Failed to set nil")
		}
	*/
}

// test src mac
func _TestCheckSrcMac(t *testing.T) {
	svr := &NDPServer{}
	svr.InitGlobalDS()
	i := int(0)
	for i = 0; i < TEST_NBR_ENTRIES; i++ {
		macStr := "aa:bb:cc:dd:ee:0" + strconv.Itoa(i)
		var temp struct{}
		svr.SwitchMacMapEntries[macStr] = temp
	}
	if !svr.CheckSrcMac("aa:bb:cc:dd:ee:01") {
		t.Error("failed checking src mac 01")
	}

	if svr.CheckSrcMac("aa:bb:cc:dd:ee:ff") {
		t.Error("ff src mac entry should not exists")
	}
	svr.DeInitGlobalDS()
}

// test populate vlan
func _TestPopulateVlanIfIndexInfo(t *testing.T) {
	svr := &NDPServer{}
	svr.InitGlobalDS()
	nbrInfo := &config.NeighborConfig{}
	svr.PopulateVlanInfo(nbrInfo, 1)
	if nbrInfo.VlanId != -1 {
		t.Error("Vlan Id", nbrInfo.VlanId, "should not be present")
	}
	svr.DeInitGlobalDS()
}

func _TestIpV6Addr(t *testing.T) {
	svr := &NDPServer{}
	if svr.IsIPv6Addr("192.168.1.1/31") {
		t.Error("Failed check for ipv6 adddress when ipv4 is passed as arg")
	}
	if !svr.IsIPv6Addr("2002::1/64") {
		t.Error("failed check for ipv6 addr when ipv6 is passed as arg")
	}
}

func _TestLinkLocalAddr(t *testing.T) {
	/*
		svr := &NDPServer{}
		if svr.IsLinkLocal("192.168.1.1/31") {
			t.Error("ipv6 adddress is not link local ip address")
		}
		if svr.IsLinkLocal("2002::1/64") {
			t.Error("ipv6 adddress is not link local ip address")
		}
		if !svr.IsLinkLocal("fe80::c000:54ff:fef5:0/64") {
			t.Error("ipv6 address is link local ip address")
		}
	*/
}
