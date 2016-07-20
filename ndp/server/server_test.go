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
	"github.com/google/gopacket/pcap"
	"infra/sysd/sysdCommonDefs"
	"l3/ndp/config"
	"l3/ndp/debug"
	"log/syslog"
	"reflect"
	"strconv"
	"testing"
	"utils/logging"
)

const (
	TEST_NBR_ENTRIES = 5
)

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

// Test ND Solicitation message Decoder
func TestInvalidInitPortInfo(t *testing.T) {
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

// Test ND Solicitation message Decoder
func TestInvalidInitL3Info(t *testing.T) {
	svr := &NDPServer{}
	svr.InitGlobalDS()
	svr.InitSystemIPIntf(nil, nil)

	if len(svr.L3Port) > 0 {
		t.Error("There should not be any elements in the system ip map", len(svr.L3Port))
	}
	svr.DeInitGlobalDS()

	if svr.L3Port != nil {
		t.Error("De-Init for ndp l3 info didn't happen")
	}
}

// Test Pcap Create
func TestPcapCreate(t *testing.T) {
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
}

// test src mac
func TestCheckSrcMac(t *testing.T) {
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
func TestPopulateVlanIfIndexInfo(t *testing.T) {
	svr := &NDPServer{}
	svr.InitGlobalDS()
	nbrInfo := &config.NeighborInfo{}
	svr.PopulateVlanInfo(nbrInfo, 1)
	if nbrInfo.VlanId != -1 {
		t.Error("Vlan Id", nbrInfo.VlanId, "should not be present")
	}
	if nbrInfo.IfIndex != 1 {
		t.Error("IfIndex is not copied properly need 1 but got", nbrInfo.IfIndex)
	}
	svr.DeInitGlobalDS()
}

func TestIpV6Addr(t *testing.T) {
	svr := &NDPServer{}
	if svr.IsIPv6Addr("192.168.1.1/31") {
		t.Error("Failed check for ipv6 adddress when ipv4 is passed as arg")
	}
	if !svr.IsIPv6Addr("2002::1/64") {
		t.Error("failed check for ipv6 addr when ipv6 is passed as arg")
	}
}

func TestLinkLocalAddr(t *testing.T) {
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
}

var nbr []config.NeighborInfo

func populateNbrInfoTest(svr *NDPServer) {
	nbr1 := config.NeighborInfo{
		IpAddr:      "2002::1/64",
		VlanId:      100,
		IfIndex:     1234,
		LinkLocalIp: "fe80::1/64",
		MacAddr:     "aa:bb:cc:dd:ee:01",
	}
	nbr2 := config.NeighborInfo{
		IpAddr:      "2003::1/64",
		VlanId:      100,
		IfIndex:     1234,
		LinkLocalIp: "fe80::2/64",
		MacAddr:     "aa:bb:cc:dd:ee:02",
	}
	nbr3 := config.NeighborInfo{
		IpAddr:      "2004::1/64",
		VlanId:      100,
		IfIndex:     1234,
		LinkLocalIp: "fe80::3/64",
		MacAddr:     "aa:bb:cc:dd:ee:03",
	}
	nbr4 := config.NeighborInfo{
		IpAddr:      "2005::1/64",
		VlanId:      100,
		IfIndex:     1234,
		LinkLocalIp: "fe80::4/64",
		MacAddr:     "aa:bb:cc:dd:ee:04",
	}
	nbr5 := config.NeighborInfo{
		IpAddr:      "2006::1/64",
		VlanId:      100,
		IfIndex:     1234,
		LinkLocalIp: "fe80::5/64",
		MacAddr:     "aa:bb:cc:dd:ee:05",
	}
	nbr = append(nbr, nbr1)
	nbr = append(nbr, nbr2)
	nbr = append(nbr, nbr3)
	nbr = append(nbr, nbr4)
	nbr = append(nbr, nbr5)
	for i := 0; i < TEST_NBR_ENTRIES; i++ {
		svr.insertNeigborInfo(&nbr[i])
	}
}

func TestGetAllNbrEntries(t *testing.T) {
	svr := &NDPServer{}
	svr.InitGlobalDS()
	populateNbrInfoTest(svr)
	if len(svr.NeighborInfo) < TEST_NBR_ENTRIES || len(svr.neighborKey) < TEST_NBR_ENTRIES {
		t.Error("Inserting neighbor entries failed")
	}
	nextIdx, count, runTimeEntries := svr.GetNeighborEntries(0, TEST_NBR_ENTRIES)
	if nextIdx != 0 {
		t.Error("Not All Entries are fetched, nextIdx is", nextIdx)
	}
	if count != TEST_NBR_ENTRIES {
		t.Error("Not all entries are found from runtime, count is", count)
	}
	if !reflect.DeepEqual(nbr, runTimeEntries) {
		t.Error("Get All Entries Failed, nbr Info Stored:", nbr, "Runtime Entries fetched:", runTimeEntries)
	}
	svr.DeInitGlobalDS()
}

func TestGet3NbrEntries(t *testing.T) {
	svr := &NDPServer{}
	svr.InitGlobalDS()
	populateNbrInfoTest(svr)
	if len(svr.NeighborInfo) < TEST_NBR_ENTRIES || len(svr.neighborKey) < TEST_NBR_ENTRIES {
		t.Error("Inserting neighbor entries failed")
	}
	nextIdx, count, runTimeEntries := svr.GetNeighborEntries(2, TEST_NBR_ENTRIES)
	if nextIdx != 0 {
		t.Error("Not All Entries are fetched, nextIdx is", nextIdx)
	}
	if count != TEST_NBR_ENTRIES-2 {
		t.Error("Not all entries are found from runtime, count is", count)
	}

	if len(runTimeEntries) == TEST_NBR_ENTRIES {
		t.Error("Len of fetched entries should be", count, " but got", len(runTimeEntries))
	}
	for i := 2; i < count; i++ {
		if !reflect.DeepEqual(nbr[i], runTimeEntries[i-2]) {
			t.Error("Get All Entries Failed, nbr Info Stored:", nbr[i], "Runtime Entries fetched:", runTimeEntries[i-2])
		}
	}
	svr.DeInitGlobalDS()
}
