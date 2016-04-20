// _vtep_test.go
package vxlan

import (
	//"fmt"
	"flag"
	"net"
	"testing"
	"utils/logging"
)

var vtepcreatedone chan bool

func mock_hwCreateVxlan(vxlan *VxlanConfig) {
	// do nothing
}
func mock_hwDeleteVxlan(vxlan *VxlanConfig) {
	// do nothing
}
func mock_hwCreateVtep(vtep *VtepDbEntry) {
	// do nothing
	vtepcreatedone <- true
}
func mock_hwDeleteVtep(vtep *VtepDbEntry) {
	// do nothing
}
func mock_hwGetNextHopInfo(ip net.IP, nexthopchan chan net.IP) {
	// do nothing
}
func mock_hwResolveNextHopMac(nexthopip net.IP, macchan chan net.HardwareAddr) {
	// do nothing
}
func mock_VxlanPortRxTx(ifname string, udpport uint16) {
	// do nothing
}
func mock_VxlanVtepRxTx(vtep *VtepDbEntry) {
	// do nothing
}

func setVxlanTestLogger() {
	paramsDir := flag.String("params", "./params", "Params directory")
	flag.Parse()
	path := *paramsDir
	if path[len(path)-1] != '/' {
		path = path + "/"
	}
	logger, _ := logging.NewLogger(path, "vxland", "TEST")
	SetLogger(logger)
}

func TestDmacSetFsm(t *testing.T) {

	vtepcreatedone = make(chan bool)
	setVxlanTestLogger()

	origHwCreateVxlan := hwCreateVxlan
	origHwDeleteVxlan := hwDeleteVxlan
	origHwCreateVtep := hwCreateVtep
	origHwDeleteVtep := hwDeleteVtep
	origVxlanPortRxTx := VxlanPortRxTx
	origVxlanVtepRxTx := VxlanVtepRxTx

	// mock the function calls now
	hwCreateVxlan = mock_hwCreateVxlan
	hwDeleteVxlan = mock_hwDeleteVxlan
	hwCreateVtep = mock_hwCreateVtep
	hwDeleteVtep = mock_hwDeleteVtep
	VxlanPortRxTx = mock_VxlanPortRxTx
	VxlanVtepRxTx = mock_VxlanVtepRxTx

	vxlanConfig := &VxlanConfig{
		VNI:    100,
		VlanId: 200,
		MTU:    1550,
	}

	srcMac, _ := net.ParseMAC("00:11:11:11:11:11")
	dstMac, _ := net.ParseMAC("00:22:22:22:22:22")

	vtepConfig := &VtepConfig{
		VtepId:       100,
		VxlanId:      1,
		VtepName:     "vtep100",
		SrcIfName:    "eth0",
		TunnelSrcIp:  net.ParseIP("100.1.1.1"),
		TunnelDstIp:  net.ParseIP("100.1.1.2"),
		VlanId:       200,
		TunnelSrcMac: srcMac,
		TunnelDstMac: dstMac,
	}
	CreateVxLAN(vxlanConfig)

	CreateVtep(vtepConfig)

	// need to wait for test to hwcreate to be called
	<-vtepcreatedone

	key := &VtepDbKey{
		VtepId: vtepConfig.VtepId,
	}

	vtep := GetVtepDBEntry(key)
	if vtep.Status != VtepStatusUp {
		t.Errorf("State not as expected expected[%d] got[%d", VtepStatusUp, vtep.Status)
	}

	DeleteVtep(vtepConfig)

	DeleteVxLAN(vxlanConfig)

	hwCreateVxlan = origHwCreateVxlan
	hwDeleteVxlan = origHwDeleteVxlan
	hwCreateVtep = origHwCreateVtep
	hwDeleteVtep = origHwDeleteVtep
	VxlanPortRxTx = origVxlanPortRxTx
	VxlanVtepRxTx = origVxlanVtepRxTx
}
