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
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"l3/ndp/config"
	"reflect"
	"testing"
)

var icmpRATestPkt = []byte{
	0x86, 0x00, 0xf2, 0x66, 0x40, 0x00, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x01, 0x88, 0x1d, 0xfc, 0xcf, 0x15, 0xfc, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0xdc,
}

var raTestPkt = []byte{
	0x33, 0x33, 0x00, 0x00, 0x00, 0x01, 0x88, 0x1d, 0xfc, 0xcf, 0x15, 0xfc, 0x86, 0xdd, 0x6e, 0x00,
	0x00, 0x00, 0x00, 0x20, 0x3a, 0xff, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x1d,
	0xfc, 0xff, 0xfe, 0xcf, 0x15, 0xfc, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x86, 0x00, 0xf2, 0x66, 0x40, 0x00, 0x07, 0x08, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x88, 0x1d, 0xfc, 0xcf, 0x15, 0xfc, 0x05, 0x01,
	0x00, 0x00, 0x00, 0x00, 0x05, 0xdc,
}
var nbrIp = "fe80::8a1d:fcff:fecf:15fc"
var macAddr = "88:1d:fc:cf:15:fc"

const (
	testIfIndex int32 = 100
)

func constructBaseNDInfo() *NDInfo {
	wantBaseNDInfo := &NDInfo{
		CurHopLimit:    64,
		ReservedFlags:  0,
		RouterLifetime: 1800,
		ReachableTime:  0,
		RetransTime:    0,
	}

	sourcendOpt := &NDOption{
		Type:   NDOptionTypeSourceLinkLayerAddress,
		Length: 1,
	}
	sourcendOpt.Value = make([]byte, 6)
	//t.Log(icmpRATestPkt[19:25])
	/*
		sourcendOpt.Value[0] = 0x88
		sourcendOpt.Value[1] = 0x1d
		sourcendOpt.Value[2] = 0xfc
		sourcendOpt.Value[3] = 0xcf
		sourcendOpt.Value[4] = 0x15
		sourcendOpt.Value[5] = 0xfc
	*/
	copy(sourcendOpt.Value, icmpRATestPkt[18:24])
	mtuOpt := &NDOption{
		Type:   NDOptionTypeMTU,
		Length: 1,
	}
	for i := 0; i < 4; i++ {
		mtuOpt.Value = append(mtuOpt.Value, 0)
	}
	mtuOpt.Value = append(mtuOpt.Value, 0x05)
	mtuOpt.Value = append(mtuOpt.Value, 0xdc)
	wantBaseNDInfo.Options = append(wantBaseNDInfo.Options, sourcendOpt)
	wantBaseNDInfo.Options = append(wantBaseNDInfo.Options, mtuOpt)
	return wantBaseNDInfo
}

func helperForVerifyingICMPv6DecodedPayload(ndInfo *NDInfo, t *testing.T) {
	wantBaseNDInfo := constructBaseNDInfo()
	if !reflect.DeepEqual(ndInfo, wantBaseNDInfo) {
		t.Error("mismatch in received ndInfo:", ndInfo, "wantBaseNDInfo:", wantBaseNDInfo)
		/*
			t.Error(ndInfo.Options[1].Value, wantBaseNDInfo.Options[1].Value)
			t.Error(ndInfo.Options[0], ndInfo.Options[1])
			t.Error(wantBaseNDInfo.Options[0], wantBaseNDInfo.Options[1])
		*/
		return
	}
}

func TestDecodeRAInfo(t *testing.T) {
	ndInfo := &NDInfo{}
	// icmp ra packets has icmpv6 4 bytes also and hence ignoring those 4 bytes
	ndInfo.DecodeRAInfo(icmpRATestPkt[4:8], icmpRATestPkt[8:])
	helperForVerifyingICMPv6DecodedPayload(ndInfo, t)

	// validate decoded RA information from packet
	err := ndInfo.ValidateRAInfo()
	if err != nil {
		t.Error("Validation for RA information should be successful, rather we got error:", err)
		return
	}
}

func TestInvalidRAInfo(t *testing.T) {
	wantBaseNDInfo := constructBaseNDInfo()
	wantBaseNDInfo.Options[0].Length = 0 // set length to zero so that it fails
	err := wantBaseNDInfo.ValidateRAInfo()
	if err == nil {
		t.Error("Negative test case for ValidateRAInfo should fail for", wantBaseNDInfo.Options[0],
			"but it didn't")
		return
	}

	wantBaseNDInfo.Options[0].Length = 1
	err = wantBaseNDInfo.ValidateRAInfo()
	if err != nil {
		t.Error("Validation for RA information should be successful, rather we got error:", err)
		return
	}

	wantBaseNDInfo.Options[1].Length = 0 // set length to zero for mtu so that it fails
	err = wantBaseNDInfo.ValidateRAInfo()
	if err == nil {
		t.Error("Negative test case for ValidateRAInfo should fail for", wantBaseNDInfo.Options[1],
			"but it didn't")
		return
	}
}

func createGoPacketForRATesting() gopacket.Packet {
	t := &testing.T{}
	p := gopacket.NewPacket(raTestPkt, layers.LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to create go-packet:", p.ErrorLayer().Error())
		return nil
	}
	return p
}

func createPrefixLinkTest() {
	myIp := "2003::1"
	myMac := "33:33:00:00:00:01"
	initTestPacket()
	// Init Link needs CIDR Format
	testPktObj.InitLink(testIfIndex, myIp+"/64", myMac)
}

func TestCreatePrefixLink(t *testing.T) {
	routerLifeTime := uint16(1800)
	prefix := PrefixInfo{}
	prefix.InitPrefix(nbrIp, macAddr, routerLifeTime)
	if prefix.IpAddr != nbrIp {
		t.Error("Prefix Init failed for ip address")
		return
	}

	if prefix.MacAddr != macAddr {
		t.Error("Prefex Init failed for mac address")
		return
	}
}

func validatePrefix(ifIndex int32) {
	t := &testing.T{}
	wantPrefix := PrefixInfo{
		IpAddr:  nbrIp,
		MacAddr: macAddr,
	}
	prefixLink, exists := testPktObj.GetLinkPrefix(ifIndex)
	if !exists {
		t.Error("Creating Prefix Link failed for IfIndex:", ifIndex)
		return
	}
	if len(prefixLink.PrefixList) == 0 {
		t.Error("No prefix is created when a prefix with entry", wantPrefix, "is expected")
		return
	}
	for _, prefix := range prefixLink.PrefixList {
		if wantPrefix.IpAddr == prefix.IpAddr {
			if !reflect.DeepEqual(prefix, wantPrefix) {
				t.Error("Populating Prefix Link Information failed, wantPrefix:", wantPrefix,
					"rcvd Prefix", prefix)
				return
			}
		}
	}
}

func validateNbrInfo(nbrInfo config.NeighborInfo) {
	t := &testing.T{}
	wantNbrInfo := config.NeighborInfo{
		IpAddr:  nbrIp,
		MacAddr: macAddr,
		State:   REACHABLE,
	}

	if !reflect.DeepEqual(wantNbrInfo, nbrInfo) {
		t.Error("Mismatch in nbr info, wantNbrInfo:", wantNbrInfo, "rcvd NbrInfo:", nbrInfo)
		return
	}
}

func TestHandleRAMsg(t *testing.T) {
	var err error
	createPrefixLinkTest()
	pkt := createGoPacketForRATesting()
	if pkt == nil {
		t.Error("Failed to create gopacket and hence aborting test case")
		return
	}
	icmpv6Hdr := &layers.ICMPv6{}
	ipv6Hdr := &layers.IPv6{}
	eth := &layers.Ethernet{}
	err = getEthLayer(pkt, eth)
	if err != nil {
		t.Error("Failed to get ethernet layer during, error:", err)
		return
	}
	err = getIpAndICMPv6Hdr(pkt, ipv6Hdr, icmpv6Hdr)
	if err != nil {
		t.Error("Decoding ipv6 and icmpv6 header failed", err)
	}

	ndInfo, err1 := testPktObj.HandleRAMsg(icmpv6Hdr, ipv6Hdr.SrcIP, ipv6Hdr.DstIP, testIfIndex)
	if err1 != nil {
		t.Error("Failed to HandleRAMsg, error:", err1)
		return
	}

	nbrInfo := testPktObj.GetNbrInfoUsingRAPkt(eth, ipv6Hdr, ndInfo)

	validateNbrInfo(nbrInfo)
}
