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
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"infra/sysd/sysdCommonDefs"
	"l3/ndp/config"
	"l3/ndp/debug"
	"log/syslog"
	"net"
	"reflect"
	"testing"
	"utils/logging"
)

var ndTestPkt = []byte{
	0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x54, 0xff, 0xfe, 0xf5, 0x00, 0x01,
}

func NDSTestNewLogger(name string, tag string, listenToConfig bool) (*logging.Writer, error) {
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

var OptionRawByteWithTarget = []byte{
	0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x54, 0xff, 0xfe, 0xf5, 0x00, 0x01,
	0x02, 0x01, 0xc2, 0x00, 0x54, 0xf5, 0x00, 0x00,
}

// Test ND Solicitation message Decoder
func TestNDInfoDecoder(t *testing.T) {
	var err error
	logger, err := NDSTestNewLogger("ndpd", "NDPTEST", true)
	if err != nil {
		t.Error("creating logger failed")
	}
	debug.NDPSetLogger(logger)
	nds := &NDInfo{}
	nds.DecodeNDInfo(ndTestPkt)
	ndWant := &NDInfo{
		TargetAddress: net.IP{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0,
			0x00, 0x54, 0xff, 0xfe, 0xf5, 0x00, 0x01},
	}
	if !reflect.DeepEqual(nds, ndWant) {
		t.Error("Decoding NDS Failed")
	}
}

// Test ND Options
func TestNDOptionDecoder(t *testing.T) {
	nds := &NDInfo{}
	nds.DecodeNDInfo(OptionRawByteWithTarget)
	ndWant := &NDInfo{
		TargetAddress: net.IP{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00,
			0x54, 0xff, 0xfe, 0xf5, 0x00, 0x01},
	}
	if !reflect.DeepEqual(nds.TargetAddress, ndWant.TargetAddress) {
		t.Error("Decoding NDInfo Target Address Failed")
	}
	optionWant := &NDOption{
		Type:   2,
		Length: 1,
		Value:  []byte{0xc2, 0x00, 0x54, 0xf5, 0x00, 0x00},
	}
	ndWant.Options = append(ndWant.Options, optionWant)
	if !reflect.DeepEqual(nds, ndWant) {
		t.Error("NDInfo is not correct")
	}
	/*
		option := nds.Options[0]
		macAddr := option.Value
		fmt.Printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
			macAddr[0], macAddr[1], macAddr[2],
			macAddr[3], macAddr[4], macAddr[5])
	*/
}

// Test ND Solicitation multicast Address Validation
func TestNDSMulticast(t *testing.T) {
	nd := &NDInfo{
		TargetAddress: net.IP{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x54,
			0xff, 0xfe, 0xf5, 0x00, 0x01},
	}
	if nd.IsTargetMulticast() {
		// b is not multicast address, fail the test case if true is returned
		//if IsTargetMulticast(b) {
		t.Error("byte is not ipv6 muticast address", nd.TargetAddress)
	}
	b := net.IP{0xff, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x54, 0xff, 0xfe, 0xf5, 0x00, 0x01}
	nd.TargetAddress = b
	// b is multicast address, fail the test case if false is returned
	if !nd.IsTargetMulticast() {
		t.Error("byte is ipv6 muticast address", b)
	}
}

// Test ND Solicitation src ip Address Validation
func TestNDSInformation(t *testing.T) {
	srcIP := net.IP{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00}
	dstIP := net.IP{0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0xff, 0x10, 0x78, 0x2e}
	//t.Log("SrcIP->", srcIP.String(), "DstIP->", dstIP.String())
	nd := &NDInfo{}
	err := nd.ValidateNDSInfo(srcIP, dstIP)
	if err != nil {
		t.Error("Validation of ip address failed with error", err)
	}
	optionWant := &NDOption{
		Type:   2,
		Length: 1,
		Value:  []byte{0xc2, 0x00, 0x54, 0xf5, 0x00, 0x00},
	}
	ndInfo := &NDInfo{}
	ndInfo.Options = append(ndInfo.Options, optionWant)

	err = ndInfo.ValidateNDSInfo(srcIP, dstIP)
	if err != nil {
		t.Error("Neigbor solicitation should fail for any option other than Source Link Layer Address", err)
	}
	optionWant1 := &NDOption{
		Type:   1,
		Length: 1,
		Value:  []byte{0xc2, 0x00, 0x54, 0xf5, 0x00, 0x00},
	}
	ndInfo1 := &NDInfo{}
	ndInfo1.Options = append(ndInfo1.Options, optionWant1)
	err = ndInfo1.ValidateNDSInfo(srcIP, dstIP)
	if err == nil {
		t.Error("Neigbor solicitation should fail for any option other than Source Link Layer Address")
	}
	srcIP = net.IP{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	//t.Log("SrcIP->", srcIP.String(), "DstIP->", dstIP.String())
	err = nd.ValidateNDSInfo(srcIP, dstIP)
	if err != nil {
		t.Error("Validation of ip address", srcIP, "failed with error", err)
	}
	dstIP = net.IP{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x54, 0xff, 0xfe, 0xf5, 0x00, 0x01}
	//t.Log("SrcIP->", srcIP.String(), "DstIP->", dstIP.String())
	err = nd.ValidateNDSInfo(srcIP, dstIP)
	if err != nil {
		t.Error("Validation of ip address", srcIP, "dst Ip", dstIP, "failed with error", err)
	}
}

// Test ND Advertisement check
func TestValidateNDAInfo(t *testing.T) {
	dstIp := net.IP{0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01}
	flags := []byte{0xa0, 00, 00, 00}
	nd := &NDInfo{}
	err := nd.ValidateNDAInfo(flags, dstIp)
	if err != nil {
		t.Error("Validation of nda failed, error:", err)
	}
	flags1 := []byte{0x40, 00, 00, 00, 00}
	err = nd.ValidateNDAInfo(flags1, dstIp)
	if err == nil {
		t.Error("Validation of nda didn't failed, error:", err)
	}
	dstIp = net.IP{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x54, 0xff,
		0xfe, 0xf5, 0x00, 0x01}
	err = nd.ValidateNDAInfo(flags1, dstIp)
	if err != nil {
		t.Error("Validation of nda failed, error:", err)
	}
}

type testIPv6 struct {
	Version      uint8
	TrafficClass uint8
	FlowLabel    uint32
	Length       uint16
	NextHeader   layers.IPProtocol
	HopLimit     uint8
	SrcIP        net.IP
	DstIP        net.IP
}

type testICMPv6 struct {
	TypeCode      layers.ICMPv6TypeCode
	Checksum      uint16
	Reserved      []byte
	TargetAddress net.IP
	Options       []*NDOption
}

func checkEthLayer(encodedEthLayer *layers.Ethernet, wantSrcMac, wantDstMac net.HardwareAddr,
	wantEthType layers.EthernetType, t *testing.T) {
	//t.Log("========VALIDATING ETH HEADER (ENCODEDETH == WANTETH)=========")
	if !reflect.DeepEqual(encodedEthLayer.SrcMAC, wantSrcMac) {
		t.Error("SrcMAC is invalid got", encodedEthLayer.SrcMAC, "but wanted", wantSrcMac)
	}
	if !reflect.DeepEqual(encodedEthLayer.DstMAC, wantDstMac) {
		t.Error("DstMAC is invalid got", encodedEthLayer.DstMAC, "but wanted", wantDstMac)
	}
	if !reflect.DeepEqual(encodedEthLayer.EthernetType, wantEthType) {
		t.Error("Ethernet Type is set incorrectly got", encodedEthLayer.EthernetType, "but wanted",
			wantEthType)
	}
	//t.Log("")
	//t.Log("======== VALIDATING ETH HEADER SUCCESS =========")
}

func checkIPv6Layer(ipv6Hdr *layers.IPv6, wantIPv6Hdr *testIPv6, t *testing.T) {
	//t.Log("========VALIDATING IPV6 HEADER (WANTIPV6 == ENCODEDIPV6)=========")
	if !reflect.DeepEqual(ipv6Hdr.Version, wantIPv6Hdr.Version) {
		t.Error("Version is incorrect", wantIPv6Hdr.Version, "!=", ipv6Hdr.Version)
	}
	if !reflect.DeepEqual(ipv6Hdr.Length, wantIPv6Hdr.Length) {
		t.Error("Length is incorrect", wantIPv6Hdr.Length, "!=", ipv6Hdr.Length)
	}
	if !reflect.DeepEqual(ipv6Hdr.NextHeader, wantIPv6Hdr.NextHeader) {
		t.Error("Next Header is incorrect", wantIPv6Hdr.NextHeader, "!=", ipv6Hdr.NextHeader)
	}
	if !reflect.DeepEqual(ipv6Hdr.HopLimit, wantIPv6Hdr.HopLimit) {
		t.Error("Hop Limit is incorrect", wantIPv6Hdr.HopLimit, "!=", ipv6Hdr.HopLimit)
	}

	if !reflect.DeepEqual(ipv6Hdr.SrcIP, wantIPv6Hdr.SrcIP) {
		t.Error("Src IP is incorrect", wantIPv6Hdr.SrcIP, "!=", ipv6Hdr.SrcIP)
	}
	if !reflect.DeepEqual(ipv6Hdr.DstIP, wantIPv6Hdr.DstIP) {
		t.Error("Dst IP is incorrect", wantIPv6Hdr.DstIP, "!=", ipv6Hdr.DstIP)
	}
	//t.Log("")
	//t.Log("======== VALIDATING IPV6 HEADER SUCCESS =========")
}

func checkICMPv6Layer(hdr *layers.ICMPv6, wantICMPv6Hdr *testICMPv6, t *testing.T) {
	ndsInfo := &NDInfo{}
	ndsInfo.DecodeNDInfo(hdr.LayerPayload())

	if !reflect.DeepEqual(hdr.TypeCode, wantICMPv6Hdr.TypeCode) {
		t.Error("TypeCode mismatch", wantICMPv6Hdr.TypeCode, "!=", hdr.TypeCode)
	}

	if !reflect.DeepEqual(hdr.Checksum, wantICMPv6Hdr.Checksum) {
		t.Errorf("Checksum mismatch 0x%x != 0x%x", wantICMPv6Hdr.Checksum, hdr.Checksum)
	}

	if !reflect.DeepEqual(hdr.TypeBytes, wantICMPv6Hdr.Reserved) {
		t.Error("Reserved bits mismatch", wantICMPv6Hdr.Reserved, "!=", hdr.TypeBytes)
	}
	if !reflect.DeepEqual(ndsInfo.TargetAddress, wantICMPv6Hdr.TargetAddress) {
		t.Error("TargetAddress mismatch", wantICMPv6Hdr.TargetAddress, "!=", ndsInfo.TargetAddress)
	}
	if !reflect.DeepEqual(ndsInfo.Options, wantICMPv6Hdr.Options) {
		t.Error("Options mismatch", wantICMPv6Hdr.Options, "!=", ndsInfo.Options)
	}
}

func TestValidateNDSPktForEncode(t *testing.T) {
	initTestPacket()
	pkt := testPktObj
	p := gopacket.NewPacket(ndsTest, layers.LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	nbrInfo := &config.NeighborInfo{}
	err := pkt.ValidateAndParse(nbrInfo, p)
	if err != nil {
		t.Error("Failed to Validate Packet, Error:", err)
	}
	if nbrInfo.MacAddr != "00:e0:ec:26:a7:ee" {
		t.Error("Src Mac copy to NeighborInfo failed")
	}

	if nbrInfo.IpAddr != "::" {
		t.Error("src ip address copy failed")
	}
}

func TestConstructMulticastNSPacket(t *testing.T) {
	initTestPacket()
	targetAddr := "2002::1"
	srcMac := "00:e0:ec:26:a7:ee"
	dstMac := "33:33:ff:00:00:01"
	rcvdBytes := ConstructNSPacket(srcMac, dstMac, targetAddr, SOLICITATED_NODE_ADDRESS)
	encodedEthLayer := &layers.Ethernet{}
	p := gopacket.NewPacket(rcvdBytes, layers.LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	err := getEthLayer(p, encodedEthLayer)
	if err != nil {
		t.Error(err)
	}
	wantSrcMac := net.HardwareAddr{0x00, 0xe0, 0xec, 0x26, 0xa7, 0xee}
	wantDstMac := net.HardwareAddr{0x33, 0x33, 0xff, 0x00, 0x00, 0x01}
	wantEthType := layers.EthernetTypeIPv6
	checkEthLayer(encodedEthLayer, wantSrcMac, wantDstMac, wantEthType, t)
	icmpv6Hdr := &layers.ICMPv6{}
	ipv6Hdr := &layers.IPv6{}
	err = getIpAndICMPv6Hdr(p, ipv6Hdr, icmpv6Hdr)
	if err != nil {
		t.Error("Decoding ipv6 and icmpv6 header failed", err)
	}

	// Validate that constructed ipv6 header has correct information
	wantIPv6Hdr := &testIPv6{
		Version:      6,
		TrafficClass: 0,
		FlowLabel:    0,
		Length:       ICMPV6_MIN_LENGTH + ICMPV6_SOURCE_LINK_LAYER_LENGTH,
		NextHeader:   layers.IPProtocolICMPv6,
		HopLimit:     HOP_LIMIT,
		SrcIP:        net.ParseIP("::"),
		DstIP:        net.ParseIP("ff02::1:ff00:1"),
	}
	checkIPv6Layer(ipv6Hdr, wantIPv6Hdr, t)
	// Validate That construct icmpv6 header has correct information
	wantICMPv6Hdr := &testICMPv6{
		TypeCode:      layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborSolicitation, 0),
		Checksum:      icmpv6Hdr.Checksum,
		Reserved:      []byte{0, 0, 0, 0},
		TargetAddress: net.ParseIP("ff02::1:ff00:1"),
	}
	optionWant := &NDOption{
		Type:   1,
		Length: 1,
		Value:  []byte{0x00, 0xe0, 0xec, 0x26, 0xa7, 0xee},
	}
	wantICMPv6Hdr.Options = append(wantICMPv6Hdr.Options, optionWant)
	checkICMPv6Layer(icmpv6Hdr, wantICMPv6Hdr, t)
}

func TestConstructUnicastNSPacket(t *testing.T) {
	initTestPacket()
	targetAddr := "2002::1"
	srcMac := "00:e0:ec:26:a7:ee"
	dstMac := "33:33:ff:00:00:01"
	dstIP := "2002::2"
	rcvdBytes := ConstructNSPacket(srcMac, dstMac, targetAddr, dstIP)
	encodedEthLayer := &layers.Ethernet{}
	p := gopacket.NewPacket(rcvdBytes, layers.LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	err := getEthLayer(p, encodedEthLayer)
	if err != nil {
		t.Error(err)
	}
	wantSrcMac := net.HardwareAddr{0x00, 0xe0, 0xec, 0x26, 0xa7, 0xee}
	wantDstMac := net.HardwareAddr{0x33, 0x33, 0xff, 0x00, 0x00, 0x01}
	wantEthType := layers.EthernetTypeIPv6
	checkEthLayer(encodedEthLayer, wantSrcMac, wantDstMac, wantEthType, t)
	icmpv6Hdr := &layers.ICMPv6{}
	ipv6Hdr := &layers.IPv6{}
	err = getIpAndICMPv6Hdr(p, ipv6Hdr, icmpv6Hdr)
	if err != nil {
		t.Error("Decoding ipv6 and icmpv6 header failed", err)
	}

	// Validate that constructed ipv6 header has correct information
	wantIPv6Hdr := &testIPv6{
		Version:      6,
		TrafficClass: 0,
		FlowLabel:    0,
		Length:       ICMPV6_MIN_LENGTH + ICMPV6_SOURCE_LINK_LAYER_LENGTH,
		NextHeader:   layers.IPProtocolICMPv6,
		HopLimit:     HOP_LIMIT,
		SrcIP:        net.ParseIP(targetAddr),
		DstIP:        net.ParseIP(dstIP),
	}
	checkIPv6Layer(ipv6Hdr, wantIPv6Hdr, t)
	// Validate That construct icmpv6 header has correct information
	wantICMPv6Hdr := &testICMPv6{
		TypeCode:      layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborSolicitation, 0),
		Checksum:      icmpv6Hdr.Checksum,
		Reserved:      []byte{0, 0, 0, 0},
		TargetAddress: net.ParseIP(dstIP),
	}
	optionWant := &NDOption{
		Type:   1,
		Length: 1,
		Value:  []byte{0x00, 0xe0, 0xec, 0x26, 0xa7, 0xee},
	}
	wantICMPv6Hdr.Options = append(wantICMPv6Hdr.Options, optionWant)
	checkICMPv6Layer(icmpv6Hdr, wantICMPv6Hdr, t)
}
