// _vtep_test.go
package vxlan

import (
	"asicd/pluginManager/pluginCommon"
	"fmt"
	"net"
	"os/exec"
	"sync"
	"testing"
	"time"
	"utils/commonDefs"
	"utils/logging"
)

var vtepcreatedone chan bool
var vxlancreatedone chan bool
var vtepdeletedone chan bool
var vxlandeletedone chan bool

type mockintf struct {
	//BaseClientIntf
	// triggers for test to fail various interface functions to test behavior
	failCreateVtep           bool
	failCreateVxlan          bool
	failDeleteVtep           bool
	failDeleteVxlan          bool
	failGetIntfInfo          bool
	failCreateAccessPortVlan bool
	failDeleteAccessPortVlan bool
	failGetAccessPorts       bool
	failGetNextHop           bool
	failResolveNexHop        bool
}

func (b mockintf) SetServerChannels(s *VxLanConfigChannels) {

}

func (b mockintf) ConnectToClients(path string) {

}
func (b mockintf) ConstructPortConfigMap() {

}
func (b mockintf) GetIntfInfo(name string, intfchan chan<- VxlanIntfInfo) {

	logger.Info("MOCK: Calling GetIntfInfo")
	if !b.failGetIntfInfo {
		mac, _ := net.ParseMAC("00:01:02:03:04:05")
		ip := net.ParseIP("100.1.1.1")
		intfchan <- VxlanIntfInfo{
			IntfName: "eth0",
			IfIndex:  pluginCommon.GetIfIndexFromIdType(1, commonDefs.IfTypePort),
			Mac:      mac,
			Ip:       ip,
		}
	}
}
func (b mockintf) CreateVtep(vtep *VtepDbEntry, vtepname chan<- string) {
	if !b.failCreateVtep {
		logger.Info(fmt.Sprintf("Create vtep %#v", vtep))
		vtepcreatedone <- true
	}
}
func (b mockintf) DeleteVtep(vtep *VtepDbEntry) {
	if !b.failDeleteVtep {
		vtepdeletedone <- true
	}
}
func (b mockintf) CreateVxlan(vxlan *VxlanConfig) {
	if !b.failCreateVxlan {
		logger.Info("MOCK: Calling Vxlan Create done")
		vxlancreatedone <- true
	}
}
func (b mockintf) DeleteVxlan(vxlan *VxlanConfig) {
	if !b.failDeleteVxlan {
		vxlandeletedone <- true
	}
}
func (b mockintf) GetAccessPorts(vlan uint16) {
	if !b.failGetAccessPorts {

	}
}
func (b mockintf) UpdateAccessPorts() {

}
func (b mockintf) CreateAccessPortVlan(vlan uint16, intfList []int) {
	if !b.failCreateAccessPortVlan {

	}
}
func (b mockintf) DeleteAccessPortVlan(vlan uint16, intfList []int) {
	if !b.failDeleteAccessPortVlan {

	}
}
func (b mockintf) GetNextHopInfo(ip net.IP, nexthopchan chan<- VtepNextHopInfo) {
	logger.Info("MOCK: Calling GetNextHopInfo")
	nexthopip := net.ParseIP("100.1.1.2")
	if !b.failGetNextHop {
		nexthopchan <- VtepNextHopInfo{
			Ip:      nexthopip,
			IfIndex: 1,
			IfName:  "eth0",
		}
	} else {
		logger.Info("MOCK: force fail")
	}
}
func (b mockintf) ResolveNextHopMac(nextHopIp net.IP, nexthopmacchan chan<- net.HardwareAddr) {
	logger.Info("MOCK: Calling ResolveNextHopMac")
	mac, _ := net.ParseMAC("00:55:44:33:22:11")
	if !b.failResolveNexHop {
		nexthopmacchan <- mac
	} else {
		logger.Info("MOCK: force fail")
	}
}

func MockFuncRxTx(vtep *VtepDbEntry) {
	logger.Info(fmt.Sprintf("MOCK: going to listen on interface %s", vtep.VtepName))
}

func setup() {
	setVxlanTestLogger()
	vtepcreatedone = make(chan bool, 1)
	vtepdeletedone = make(chan bool, 1)
	vxlancreatedone = make(chan bool, 1)
	vxlandeletedone = make(chan bool, 1)
}

func teardown() {
	logger.Close()
	logger = nil
	close(vtepcreatedone)
	close(vxlancreatedone)
	close(vtepdeletedone)
	close(vxlandeletedone)
	exec.Command("/bin/rm", "UsrConfDb.db")
	DeRegisterClients()
	SetLogger(nil)
}

func setVxlanTestLogger() {

	logger, _ := logging.NewLogger("vxland", "TEST", true)
	SetLogger(logger)
}

func TimerTest(v *VtepDbEntry, exitchan chan<- bool) {
	cnt := 0
	for {
		time.Sleep(time.Millisecond * 10)
		if v.ticksTillConfig > 2 {
			exitchan <- true
			return
		}
		if cnt > 10 {
			exitchan <- true
			return
		}
		cnt++
	}
}

// TestFSMValidVxlanVtepCreate:
// Test creation of vxlan before vtep
func TestFSMValidVxlanVtepCreate(t *testing.T) {

	// setup common test info
	setup()
	defer teardown()

	oldRxTx := VxlanVtepRxTx
	VxlanVtepRxTx = MockFuncRxTx

	defer func() {
		VxlanVtepRxTx = oldRxTx
	}()

	// all apis are set to not fail
	RegisterClients(mockintf{})

	vxlanConfig := &VxlanConfig{
		VNI:    100,
		VlanId: 200,
	}

	vtepConfig := &VtepConfig{
		Vni:         100,
		VtepName:    "vtep100",
		SrcIfName:   "eth0",
		TunnelDstIp: net.ParseIP("100.1.1.2"),
		VlanId:      200,
	}

	// create the vxlan
	CreateVxLAN(vxlanConfig)

	<-vxlancreatedone

	CreateVtep(vtepConfig)

	// need to wait for test to hwcreate to be called
	<-vtepcreatedone

	key := &VtepDbKey{
		name: vtepConfig.VtepName,
	}

	vtep := GetVtepDBEntry(key)
	if vtep.Status != VtepStatusUp {
		t.Errorf("State not as expected expected[%s] actual[%s]", VtepStatusUp, vtep.Status)
	}

	DeleteVtep(vtepConfig)

	<-vtepdeletedone

	DeleteVxLAN(vxlanConfig)

	<-vxlandeletedone

	if len(GetVxlanDB()) != 0 {
		t.Errorf("Vxlan db not empty as expected")
	}

	if len(GetVtepDB()) != 0 {
		t.Errorf("Vtep db not empty as expected")
	}

	VxlanVtepRxTx = oldRxTx
}

// TestFSMValidVtepVxlanCreate:
// Test creation of vtep before vxlan
func TestFSMValidVtepVxlanCreate(t *testing.T) {

	// setup common test info
	setup()
	defer teardown()

	oldRxTx := VxlanVtepRxTx
	VxlanVtepRxTx = MockFuncRxTx

	defer func() {
		VxlanVtepRxTx = oldRxTx
	}()

	// all apis are set to not fail
	RegisterClients(mockintf{})

	vxlanConfig := &VxlanConfig{
		VNI:    100,
		VlanId: 200,
	}

	vtepConfig := &VtepConfig{
		Vni:         100,
		VtepName:    "vtep100",
		SrcIfName:   "eth0",
		TunnelDstIp: net.ParseIP("100.1.1.2"),
		VlanId:      200,
	}

	CreateVtep(vtepConfig)

	// need to wait for test to hwcreate to be called
	CreateVxLAN(vxlanConfig)

	<-vxlancreatedone
	<-vtepcreatedone

	key := &VtepDbKey{
		name: vtepConfig.VtepName,
	}

	vtep := GetVtepDBEntry(key)
	if vtep.Status != VtepStatusUp {
		t.Errorf("State not as expected expected[%s] actual[%s]", VtepStatusUp, vtep.Status)
	}

	DeleteVtep(vtepConfig)

	<-vtepdeletedone

	DeleteVxLAN(vxlanConfig)

	<-vxlandeletedone

	if len(GetVxlanDB()) != 0 {
		t.Errorf("Vxlan db not empty as expected")
	}

	if len(GetVtepDB()) != 0 {
		t.Errorf("Vtep db not empty as expected")
	}

}

// TestFSMCreateVtepNoVxlan
// Test that FSM is not running when vxlan is not configured
func TestFSMCreateVtepNoVxlan(t *testing.T) {

	// setup common test info
	setup()
	defer teardown()

	oldRxTx := VxlanVtepRxTx
	VxlanVtepRxTx = MockFuncRxTx

	defer func() {
		VxlanVtepRxTx = oldRxTx
	}()

	// all apis are set to not fail
	RegisterClients(mockintf{})

	vtepConfig := &VtepConfig{
		Vni:         100,
		VtepName:    "vtep100",
		SrcIfName:   "eth0",
		TunnelDstIp: net.ParseIP("100.1.1.2"),
		VlanId:      200,
	}

	CreateVtep(vtepConfig)

	// should only be one entry
	key := &VtepDbKey{
		name: vtepConfig.VtepName,
	}

	vtep := GetVtepDBEntry(key)
	exitchan := make(chan bool, 1)
	go TimerTest(vtep, exitchan)

	<-exitchan

	// test timer mechanism
	if vtep.ticksTillConfig > 0 ||
		vtep.retrytimer != nil {
		t.Errorf("Why was FSM started")
	}

	if vtep.Status != VtepStatusDetached {
		t.Errorf("State not as expected expected[%s] actual[%s]", VtepStatusDetached, vtep.Status)
	}
	DeleteVtep(vtepConfig)
}

// TestFSMIntfFailVtepVxlanCreate:
// Test creation of vtep and the src interface does not exist
// basically provisioning incomplete
func TestFSMIntfFailVtepVxlanCreate(t *testing.T) {

	// setup common test info
	setup()
	defer teardown()

	oldRxTx := VxlanVtepRxTx
	VxlanVtepRxTx = MockFuncRxTx

	defer func() {
		VxlanVtepRxTx = oldRxTx
	}()

	// all apis are set to not fail
	RegisterClients(mockintf{
		failGetIntfInfo: true,
	})

	vxlanConfig := &VxlanConfig{
		VNI:    100,
		VlanId: 200,
	}

	vtepConfig := &VtepConfig{
		Vni:         100,
		VtepName:    "vtep100",
		SrcIfName:   "eth0",
		TunnelDstIp: net.ParseIP("100.1.1.2"),
		VlanId:      200,
	}

	// create vxlan
	CreateVxLAN(vxlanConfig)
	<-vxlancreatedone

	// create vtep
	CreateVtep(vtepConfig)

	// should only be one entry
	key := &VtepDbKey{
		name: vtepConfig.VtepName,
	}
	vtep := GetVtepDBEntry(key)

	exitchan := make(chan bool, 1)
	go TimerTest(vtep, exitchan)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case done := <-vtepcreatedone:
				if done {
					t.Errorf("Vtep should not have been created the interface did not exist")
				}
				return
			case <-exitchan:
				return
			}
		}
	}()

	wg.Wait()

	if vtep.Status != VtepStatusIncomplete {
		t.Errorf("State not as expected expected[%s] actual[%s]", VtepStatusIncomplete, vtep.Status)
	}

	DeleteVtep(vtepConfig)

	DeleteVxLAN(vxlanConfig)

	if len(GetVxlanDB()) != 0 {
		t.Errorf("Vxlan db not empty as expected")
	}

	if len(GetVtepDB()) != 0 {
		t.Errorf("Vtep db not empty as expected")
	}
}

// TestFSMIntfFailThenSendIntfSuccessVtepVxlanCreate:
// Test creation of vtep and the src interface does not exist
// basically provisioning incomplete, then once interface exists
// notify state machine
func TestFSMIntfFailThenSendIntfSuccessVtepVxlanCreate(t *testing.T) {

	// setup common test info
	setup()
	defer teardown()

	oldRxTx := VxlanVtepRxTx
	VxlanVtepRxTx = MockFuncRxTx

	defer func() {
		VxlanVtepRxTx = oldRxTx
	}()

	x := mockintf{
		failGetIntfInfo: true,
	}
	// all apis are set to not fail
	RegisterClients(x)

	vxlanConfig := &VxlanConfig{
		VNI:    100,
		VlanId: 200,
	}

	vtepConfig := &VtepConfig{
		Vni:         100,
		VtepName:    "vtep100",
		SrcIfName:   "eth0",
		TunnelDstIp: net.ParseIP("100.1.1.2"),
		VlanId:      200,
	}

	// create vxlan
	CreateVxLAN(vxlanConfig)
	<-vxlancreatedone

	// create vtep
	CreateVtep(vtepConfig)

	// should only be one entry
	key := &VtepDbKey{
		name: vtepConfig.VtepName,
	}
	vtep := GetVtepDBEntry(key)

	exitchan := make(chan bool, 1)
	go TimerTest(vtep, exitchan)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case done := <-vtepcreatedone:
				if done {
					t.Errorf("Vtep should not have been created the interface did not exist")
				}
				return
			case <-exitchan:
				return
			}
		}
	}()

	wg.Wait()

	if vtep.Status != VtepStatusIncomplete {
		t.Errorf("State not as expected expected[%s] actual[%s]", VtepStatusIncomplete, vtep.Status)
	}

	// allow this to proceed in order to process
	x.failGetIntfInfo = false

	// lets get the info necessary info, this is "sort of" simulating
	// a notification from the client to the server
	mac, _ := net.ParseMAC("00:01:02:03:04:05")
	ip := net.ParseIP("100.1.1.1")
	vtep.intfinfochan <- VxlanIntfInfo{
		IntfName: "eth0",
		IfIndex:  pluginCommon.GetIfIndexFromIdType(1, commonDefs.IfTypePort),
		Mac:      mac,
		Ip:       ip,
	}

	<-vtepcreatedone

	if vtep.Status != VtepStatusUp {
		t.Errorf("State not as expected expected[%s] actual[%s]", VtepStatusUp, vtep.Status)
	}

	DeleteVtep(vtepConfig)

	<-vtepdeletedone

	DeleteVxLAN(vxlanConfig)

	<-vxlandeletedone

	if len(GetVxlanDB()) != 0 {
		t.Errorf("Vxlan db not empty as expected")
	}

	if len(GetVtepDB()) != 0 {
		t.Errorf("Vtep db not empty as expected")
	}
}

// TestFSMNextHopFailVtepVxlanCreate:
// Test next hop ip has not been discovered yet thus verify state
func TestFSMNextHopFailVtepVxlanCreate(t *testing.T) {

	// setup common test info
	setup()
	defer teardown()

	oldRxTx := VxlanVtepRxTx
	VxlanVtepRxTx = MockFuncRxTx

	defer func() {
		VxlanVtepRxTx = oldRxTx
	}()

	// all apis are set to not fail
	RegisterClients(mockintf{
		failGetNextHop: true,
	})

	vxlanConfig := &VxlanConfig{
		VNI:    100,
		VlanId: 200,
	}

	vtepConfig := &VtepConfig{
		Vni:         100,
		VtepName:    "vtep100",
		SrcIfName:   "eth0",
		TunnelDstIp: net.ParseIP("100.1.1.2"),
		VlanId:      200,
	}

	// create vxlan
	CreateVxLAN(vxlanConfig)
	<-vxlancreatedone

	// create vtep
	CreateVtep(vtepConfig)

	// should only be one entry
	key := &VtepDbKey{
		name: vtepConfig.VtepName,
	}
	vtep := GetVtepDBEntry(key)

	exitchan := make(chan bool, 1)
	go TimerTest(vtep, exitchan)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case done := <-vtepcreatedone:
				if done {
					t.Errorf("Vtep should not have been created the interface did not exist")
				}
				return
			case <-exitchan:
				return
			}
		}
	}()

	wg.Wait()

	if vtep.Status != VtepStatusNextHopUnknown {
		t.Errorf("State not as expected expected[%s] actual[%s]", VtepStatusNextHopUnknown, vtep.Status)
	}

	if vtep.NextHop.Ip.String() != "0.0.0.0" &&
		vtep.NextHop.Ip.String() != "" &&
		vtep.NextHop.Ip != nil {
		t.Errorf("Why was the next hop IP address[%s] found for interface [%s]", vtep.NextHop.Ip, vtep.SrcIfName)
	}

	DeleteVtep(vtepConfig)

	DeleteVxLAN(vxlanConfig)

	if len(GetVxlanDB()) != 0 {
		t.Errorf("Vxlan db not empty as expected")
	}

	if len(GetVtepDB()) != 0 {
		t.Errorf("Vtep db not empty as expected")
	}
}

// TestFSMNextHopFailThenSucceedVtepVxlanCreate:
// Test next hop ip has not been discovered yet thus verify state
// then notify state machine when next hop has been found
func TestFSMNextHopFailThenSucceedVtepVxlanCreate(t *testing.T) {

	// setup common test info
	setup()
	defer teardown()

	oldRxTx := VxlanVtepRxTx
	VxlanVtepRxTx = MockFuncRxTx

	defer func() {
		VxlanVtepRxTx = oldRxTx
	}()

	x := mockintf{
		failGetNextHop: true,
	}
	// all apis are set to not fail
	RegisterClients(x)

	vxlanConfig := &VxlanConfig{
		VNI:    100,
		VlanId: 200,
	}

	vtepConfig := &VtepConfig{
		Vni:         100,
		VtepName:    "vtep100",
		SrcIfName:   "eth0",
		TunnelDstIp: net.ParseIP("100.1.1.2"),
		VlanId:      200,
	}

	// create vxlan
	CreateVxLAN(vxlanConfig)
	<-vxlancreatedone

	// create vtep
	CreateVtep(vtepConfig)

	// should only be one entry
	key := &VtepDbKey{
		name: vtepConfig.VtepName,
	}
	vtep := GetVtepDBEntry(key)

	exitchan := make(chan bool, 1)
	go TimerTest(vtep, exitchan)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case done := <-vtepcreatedone:
				if done {
					t.Errorf("Vtep should not have been created the interface did not exist")
				}
				return
			case <-exitchan:
				return
			}
		}
	}()

	wg.Wait()

	if vtep.Status != VtepStatusNextHopUnknown {
		t.Errorf("State not as expected expected[%s] actual[%s]", VtepStatusNextHopUnknown, vtep.Status)
	}

	if vtep.NextHop.Ip.String() != "0.0.0.0" &&
		vtep.NextHop.Ip.String() != "" &&
		vtep.NextHop.Ip != nil {
		t.Errorf("Why was the next hop IP address[%s] found for interface [%s]", vtep.NextHop.Ip, vtep.SrcIfName)
	}

	// notify that next hop found
	x.failGetNextHop = false

	// notify next hop has been found
	nexthopip := net.ParseIP("100.1.1.100")
	vtep.nexthopchan <- VtepNextHopInfo{
		Ip:      nexthopip,
		IfIndex: 1,
		IfName:  "eth0",
	}

	<-vtepcreatedone

	if vtep.Status != VtepStatusUp {
		t.Errorf("State not as expected expected[%s] actual[%s]", VtepStatusUp, vtep.Status)
	}

	DeleteVtep(vtepConfig)

	DeleteVxLAN(vxlanConfig)

	if len(GetVxlanDB()) != 0 {
		t.Errorf("Vxlan db not empty as expected")
	}

	if len(GetVtepDB()) != 0 {
		t.Errorf("Vtep db not empty as expected")
	}
}

// TestFSMResolveNextHopFailVtepVxlanCreate:
// Test that next hop ip mac address does not exist yet
func TestFSMResolveNextHopFailVtepVxlanCreate(t *testing.T) {

	// setup common test info
	setup()
	defer teardown()

	oldRxTx := VxlanVtepRxTx
	VxlanVtepRxTx = MockFuncRxTx

	defer func() {
		VxlanVtepRxTx = oldRxTx
	}()

	// all apis are set to not fail
	RegisterClients(mockintf{
		failResolveNexHop: true,
	})

	vxlanConfig := &VxlanConfig{
		VNI:    100,
		VlanId: 200,
	}

	vtepConfig := &VtepConfig{
		Vni:         100,
		VtepName:    "vtep100",
		SrcIfName:   "eth0",
		TunnelDstIp: net.ParseIP("100.1.1.2"),
		VlanId:      200,
	}

	// create vxlan
	CreateVxLAN(vxlanConfig)
	<-vxlancreatedone

	// create vtep
	CreateVtep(vtepConfig)

	// should only be one entry
	key := &VtepDbKey{
		name: vtepConfig.VtepName,
	}
	vtep := GetVtepDBEntry(key)

	exitchan := make(chan bool, 1)
	go TimerTest(vtep, exitchan)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case done := <-vtepcreatedone:
				if done {
					t.Errorf("Vtep should not have been created the interface did not exist")
				}
				return
			case <-exitchan:
				return
			}
		}
	}()

	wg.Wait()

	if vtep.Status != VtepStatusArpUnresolved {
		t.Errorf("State not as expected expected[%s] actual[%s]", VtepStatusArpUnresolved, vtep.Status)
	}

	if vtep.SrcIp.String() == "0.0.0.0" ||
		vtep.SrcIp.String() == "" ||
		vtep.SrcIp == nil {
		t.Errorf("Why was the IP address[%s] not found for interface [%s]", VtepStatusNextHopUnknown, vtep.SrcIp, vtep.SrcIfName)
	}

	if vtep.NextHop.Ip.String() == "0.0.0.0" ||
		vtep.NextHop.Ip.String() == "" ||
		vtep.NextHop.Ip == nil {
		t.Errorf("Why was the next hop IP address[%s] not found for interface [%s]", VtepStatusNextHopUnknown, vtep.NextHop.Ip, vtep.SrcIfName)
	}

	if vtep.DstMac.String() != "00:00:00:00:00:00" &&
		vtep.DstMac != nil {
		t.Errorf("Why was the Dst MAC address[%s] found for interface [%s]", vtep.DstMac, vtep.SrcIfName)
	}

	DeleteVtep(vtepConfig)

	DeleteVxLAN(vxlanConfig)

	if len(GetVxlanDB()) != 0 {
		t.Errorf("Vxlan db not empty as expected")
	}

	if len(GetVtepDB()) != 0 {
		t.Errorf("Vtep db not empty as expected")
	}
}
