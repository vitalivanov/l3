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
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"infra/sysd/sysdCommonDefs"
	"l3/ndp/config"
	"log/syslog"
	"net"
	"reflect"
	"testing"
	"utils/logging"
)

var ndaPkt = []byte{
	0x33, 0x33, 0x00, 0x00, 0x00, 0x01, 0xc2, 0x00, 0x54, 0xf5, 0x00, 0x00, 0x86, 0xdd, 0x6e, 0x00,
	0x00, 0x00, 0x00, 0x20, 0x3a, 0xff, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00,
	0x54, 0xff, 0xfe, 0xf5, 0x00, 0x00, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x88, 0x00, 0x9a, 0xbb, 0xa0, 0x00, 0x00, 0x00, 0xfe, 0x80,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x54, 0xff, 0xfe, 0xf5, 0x00, 0x00, 0x02, 0x01,
	0xc2, 0x00, 0x54, 0xf5, 0x00, 0x00,
}

var testPkt = []byte{
	0x33, 0x33, 0xff, 0xf5, 0x00, 0x00, 0xc2, 0x00, 0x54, 0xf5, 0x00, 0x00, 0x86, 0xdd, 0x6e, 0x00,
	0x00, 0x00, 0x00, 0x18, 0x3a, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x01, 0xff, 0xf5, 0x00, 0x00, 0x87, 0x00, 0x67, 0x3c, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x80,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x54, 0xff, 0xfe, 0xf5, 0x00, 0x00,
}

var ndsTest = []byte{0x33, 0x33, 0xff, 0x00, 0x00, 0x01, 0x00, 0xe0, 0xec, 0x26, 0xa7, 0xee, 0x86, 0xdd,
	0x60, 0x00, 0x00, 0x00, 0x00, 0x18, 0x3a, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x01, 0xff, 0x00, 0x00, 0x01,
	0x87, 0x00, 0x5a, 0xa4, 0x00, 0x00, 0x00, 0x00, 0x20, 0x02,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	0x01, 0x01, 0x00, 0xe0, 0xec, 0x26, 0xa7, 0xee}

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

func DeepCheckIPv6Hdr(ipv6Hdr, ipv6Want *layers.IPv6, t *testing.T) {
	if !reflect.DeepEqual(ipv6Hdr.Version, ipv6Want.Version) {
		t.Error("Version mismatch", ipv6Hdr.Version, ipv6Want.Version)
	}
	if !reflect.DeepEqual(ipv6Hdr.TrafficClass, ipv6Want.TrafficClass) {
		t.Error("TrafficClass mismatch")
	}
	if !reflect.DeepEqual(ipv6Hdr.HopLimit, ipv6Want.HopLimit) {
		t.Error("HopLimit mismatch")
	}
	if !reflect.DeepEqual(ipv6Hdr.SrcIP, ipv6Want.SrcIP) {
		t.Error("SrcIP mismatch")
	}
	if !reflect.DeepEqual(ipv6Hdr.DstIP, ipv6Want.DstIP) {
		t.Error("DstIP mismatch")
	}
	if !reflect.DeepEqual(ipv6Hdr.NextHeader, ipv6Want.NextHeader) {
		t.Error("NextHeader mismatch")
	}
	if !reflect.DeepEqual(ipv6Hdr.Length, ipv6Want.Length) {
		t.Error("lenght mismatch")
	}
}

func DeepCheckNDHdr(icmpv6Hdr, ndWant *layers.ICMPv6, t *testing.T) {
	if !reflect.DeepEqual(icmpv6Hdr.TypeCode, ndWant.TypeCode) {
		t.Error("TypeCode MisMatch")
	}
	if !reflect.DeepEqual(icmpv6Hdr.Checksum, ndWant.Checksum) {
		t.Error("Checksum MisMatch")
	}
}

func TestEthLayer(t *testing.T) {
	initTestPacket()
	p := gopacket.NewPacket(testPkt, layers.LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	eth := &layers.Ethernet{}
	err := getEthLayer(p, eth)
	if err != nil {
		t.Error("failed to get ethener layer", err)
	}

	if (eth.SrcMAC).String() != "c2:00:54:f5:00:00" {
		t.Error("Src Mac", (eth.SrcMAC).String(), "doesn't match with existing raw byte src mac")
	}
}

// Test ND Solicitation message Decoder
func TestIPv6AndICMPv6Header(t *testing.T) {
	initTestPacket()
	var err error
	p := gopacket.NewPacket(testPkt, layers.LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	icmpv6Hdr := &layers.ICMPv6{}
	ipv6Hdr := &layers.IPv6{}
	err = getIpAndICMPv6Hdr(p, ipv6Hdr, icmpv6Hdr)
	if err != nil {
		t.Error("Decoding ipv6 and icmpv6 header failed", err)
	}
	ipv6Want := &layers.IPv6{
		Version:      6,
		TrafficClass: 0xe0,
		FlowLabel:    0,
		Length:       24,
		NextHeader:   layers.IPProtocolICMPv6,
		HopLimit:     255,
		SrcIP:        net.IP{0x00, 0x00, 0x0, 0x0, 0x00, 0x0, 0x0, 0x0, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x0, 0x00},
		DstIP:        net.IP{0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0xf5, 0x00, 0x00},
	}
	ndWant := &layers.ICMPv6{
		TypeCode: 0x8700,
		Checksum: 0x673c,
	}
	DeepCheckIPv6Hdr(ipv6Hdr, ipv6Want, t)
	DeepCheckNDHdr(icmpv6Hdr, ndWant, t)
}

func TestValidateIpv6hdr(t *testing.T) {
	initTestPacket()
	p := gopacket.NewPacket(testPkt, layers.LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	icmpv6Hdr := &layers.ICMPv6{}
	ipv6Hdr := &layers.IPv6{}
	err := getIpAndICMPv6Hdr(p, ipv6Hdr, icmpv6Hdr)
	if err != nil {
		t.Error("Decoding ipv6 and icmpv6 header failed", err)
	}
	validateIPv6Hdr(ipv6Hdr)
	if err != nil {
		t.Error("Validating IPv6 Hdr failed", err)
	}
}

func TestValidateICMPv6NDSChecksum(t *testing.T) {
	initTestPacket()
	p := gopacket.NewPacket(testPkt, layers.LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	icmpv6Hdr := &layers.ICMPv6{}
	ipv6Hdr := &layers.IPv6{}
	err := getIpAndICMPv6Hdr(p, ipv6Hdr, icmpv6Hdr)
	if err != nil {
		t.Error("Decoding ipv6 and icmpv6 header failed", err)
	}
	err = validateChecksum(ipv6Hdr.SrcIP, ipv6Hdr.DstIP, icmpv6Hdr)
	if err != nil {
		t.Error("Validating Checksum failed", err)
	}
}

func TestValidateICMPv6Hdr(t *testing.T) {
	initTestPacket()
	p := gopacket.NewPacket(testPkt, layers.LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	icmpv6Hdr := &layers.ICMPv6{}
	ipv6Hdr := &layers.IPv6{}
	pkt := testPktObj
	err := getIpAndICMPv6Hdr(p, ipv6Hdr, icmpv6Hdr)
	if err != nil {
		t.Error("Decoding ipv6 and icmpv6 header failed", err)
	}
	//t.Log("SrcIP->", ipv6Hdr.SrcIP.String(), "DstIP->", ipv6Hdr.DstIP.String())
	var testPkt = net.IP{
		0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x54, 0xff, 0xfe, 0xf5, 0x00, 0x00,
	}
	nds, err := pkt.decodeICMPv6Hdr(icmpv6Hdr, ipv6Hdr.SrcIP, ipv6Hdr.DstIP)
	if err != nil {
		t.Error("Validating ICMPv6 Header failed:", err)
	}
	if !reflect.DeepEqual(nds.TargetAddress, testPkt) {
		t.Error("Link Local Ip Mismatch:", err)
	}
}

func TestPopulateNeighborInfo(t *testing.T) {
	initTestPacket()
	nbrInfo := &config.NeighborInfo{}
	nds := NDInfo{}
	pkt := testPktObj
	pkt.InitLink(100, "ff02::1:fff5:0/64", "00:e0:ec:26:a7:ee")
	addTestNbrEntryWithMac("ff02::1:fff5:0", "::", "c2:00:54:f5:00:00")
	pkt.populateNeighborInfo(nbrInfo, nil, nil, nil, &nds)
	if nbrInfo.IpAddr != "" {
		t.Error("nil error check failed")
	}
	p := gopacket.NewPacket(testPkt, layers.LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	icmpv6Hdr := &layers.ICMPv6{}
	ipv6Hdr := &layers.IPv6{}
	err := getIpAndICMPv6Hdr(p, ipv6Hdr, icmpv6Hdr)
	if err != nil {
		t.Error("Decoding ipv6 and icmpv6 header failed", err)
	}
	eth := &layers.Ethernet{}
	err = getEthLayer(p, eth)
	if err != nil {
		t.Error("failed to get ethener layer", err)
	}
	pkt.populateNeighborInfo(nbrInfo, eth, nil, nil, &nds)
	if nbrInfo.IpAddr != "" {
		t.Error("nil error check failed")
	}
	pkt.populateNeighborInfo(nbrInfo, nil, ipv6Hdr, nil, &nds)
	if nbrInfo.IpAddr != "" {
		t.Error("nil error check failed")
	}
	pkt.populateNeighborInfo(nbrInfo, nil, nil, icmpv6Hdr, &nds)
	if nbrInfo.IpAddr != "" {
		t.Error("nil error check failed")
	}
	/*
		pkt.populateNeighborInfo(nbrInfo, eth, ipv6Hdr, icmpv6Hdr, &nds)
		t.Log(nbrInfo)
		if nbrInfo.MacAddr != "c2:00:54:f5:00:00" {
			t.Error("Src Mac copy to NeighborInfo failed")
		}

		if nbrInfo.IpAddr != "::" {
			t.Error("src ip address copy failed")
		}
		nds.TargetAddress = net.ParseIP("22:33::1/64")
		pkt.populateNeighborInfo(nbrInfo, eth, ipv6Hdr, icmpv6Hdr, &nds)
		if nbrInfo.PktOperation != byte(PACKET_DROP) {
			t.Error("packet drop populate neighbor info condition is not working")
		}
	*/
}

func TestValidateNDSPkt(t *testing.T) {
	initTestPacket()
	pkt := testPktObj
	//dumpLinkInfo(t)
	pkt.InitLink(100, "fe80::c000:54ff:fef5:0/64", "33:33:ff:00:00:01")
	addTestNbrEntryWithMac("fe80::c000:54ff:fef5:0", "::", "c2:00:54:f5:00:00")
	//dumpLinkInfo(t)
	p := gopacket.NewPacket(testPkt, layers.LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	nbrInfo := &config.NeighborInfo{}
	err := pkt.ValidateAndParse(nbrInfo, p)
	if err != nil {
		t.Error("Failed to Validate Packet, Error:", err)
	}
	if nbrInfo.MacAddr != "c2:00:54:f5:00:00" {
		t.Error("Src Mac copy to NeighborInfo failed")
	}

	if nbrInfo.IpAddr != "::" {
		t.Error("src ip address copy failed")
	}
}

var lotsOfZeros [1024]byte

func TestDecodeNDA(t *testing.T) {
	initTestPacket()
	testPktObj.InitLink(100, "ff02::1/64", "00:e0:ec:26:a7:ee")
	addTestNbrEntry("ff02::1", "fe80::c000:54ff:fef5:0")
	//dumpLinkInfo(t)
	p := gopacket.NewPacket(ndaPkt, layers.LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	icmpv6Hdr := &layers.ICMPv6{}
	ipv6Hdr := &layers.IPv6{}
	pkt := testPktObj

	err := getIpAndICMPv6Hdr(p, ipv6Hdr, icmpv6Hdr)
	if err != nil {
		t.Error("Decoding ipv6 and icmpv6 header failed", err)
	}
	nda, err := pkt.decodeICMPv6Hdr(icmpv6Hdr, ipv6Hdr.SrcIP, ipv6Hdr.DstIP)
	if err != nil {
		t.Error("Validating ICMPv6 Header failed:", err)
	}

	var testPkt = net.IP{
		0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x54, 0xff, 0xfe, 0xf5, 0x00, 0x00,
	}
	optionWant := &NDOption{
		Type:   2,
		Length: 1,
		Value:  []byte{0xc2, 0x00, 0x54, 0xf5, 0x00, 0x00},
	}
	want := &NDInfo{
		TargetAddress: testPkt,
	}
	want.Options = append(want.Options, optionWant)

	if !reflect.DeepEqual(nda, want) {
		t.Error("NDInfo is not correct")
	}
}

func TestPseudoChecksumBuf(t *testing.T) {
	initTestPacket()
	p := gopacket.NewPacket(ndaPkt, layers.LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	icmpv6Hdr := &layers.ICMPv6{}
	ipv6Hdr := &layers.IPv6{}

	err := getIpAndICMPv6Hdr(p, ipv6Hdr, icmpv6Hdr)
	if err != nil {
		t.Error("Decoding ipv6 and icmpv6 header failed", err)
	}
	buf := createPseudoHeader(ipv6Hdr.SrcIP, ipv6Hdr.DstIP, icmpv6Hdr)
	if buf[39] != ICMPV6_NEXT_HEADER {
		t.Error("creating pseudo header failed")
	}
	if len(buf) != 40 {
		t.Error("invalid pseudo header for checksum calculation")
	}
}

func TestNDAChecksum(t *testing.T) {
	initTestPacket()
	testPktObj.InitLink(100, "ff02::1/64", "00:e0:ec:26:a7:ee")
	addTestNbrEntry("ff02::1", "fe80::c000:54ff:fef5:0")
	p := gopacket.NewPacket(ndaPkt, layers.LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	icmpv6Hdr := &layers.ICMPv6{}
	ipv6Hdr := &layers.IPv6{}
	pkt := testPktObj

	err := getIpAndICMPv6Hdr(p, ipv6Hdr, icmpv6Hdr)
	if err != nil {
		t.Error("Decoding ipv6 and icmpv6 header failed", err)
	}

	nda, err := pkt.decodeICMPv6Hdr(icmpv6Hdr, ipv6Hdr.SrcIP, ipv6Hdr.DstIP)
	if err != nil {
		t.Error("Validating ICMPv6 Header failed:", err)
	}

	var testPkt = net.IP{
		0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x54, 0xff, 0xfe, 0xf5, 0x00, 0x00,
	}
	optionWant := &NDOption{
		Type:   2,
		Length: 1,
		Value:  []byte{0xc2, 0x00, 0x54, 0xf5, 0x00, 0x00},
	}
	want := &NDInfo{
		TargetAddress: testPkt,
	}
	want.Options = append(want.Options, optionWant)

	if !reflect.DeepEqual(nda, want) {
		t.Error("NDInfo is not correct")
	}
	err = validateChecksum(ipv6Hdr.SrcIP, ipv6Hdr.DstIP, icmpv6Hdr)
	if err != nil {
		t.Error("Validating Checksum failed:-", err)
	}
}

func TestUnSupportedICMPv6(t *testing.T) {
	initTestPacket()
	icmpv6Hdr := &layers.ICMPv6{}
	pkt := testPktObj
	csum := []byte{0x9a, 0xbb}
	flags := []byte{0xa0, 00, 00, 00}
	icmpv6Hdr.TypeCode = layers.CreateICMPv6TypeCode(137, 0)
	icmpv6Hdr.Checksum = binary.BigEndian.Uint16(csum[:])
	icmpv6Hdr.TypeBytes = append(icmpv6Hdr.TypeBytes, flags...)
	var ip net.IP
	_, err := pkt.decodeICMPv6Hdr(icmpv6Hdr, ip, ip)
	if err == nil {
		t.Error("Validating ICMPv6 Header should have failed:", err)
	}
	icmpv6Hdr.TypeCode = layers.CreateICMPv6TypeCode(133, 0)
	_, err = pkt.decodeICMPv6Hdr(icmpv6Hdr, ip, ip)
	if err == nil {
		t.Error("Validating ICMPv6 Header should have failed:", err)
	}
}

func TestValidateNDAPkt(t *testing.T) {
	initTestPacket()
	testPktObj.InitLink(100, "ff02::1/64", "00:e0:ec:26:a7:ee")
	addTestNbrEntry("ff02::1", "fe80::c000:54ff:fef5:0")
	p := gopacket.NewPacket(ndaPkt, layers.LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	nbrInfo := &config.NeighborInfo{}
	pkt := testPktObj
	err := pkt.ValidateAndParse(nbrInfo, p)
	if err != nil {
		t.Error("Failed to Validate Packet, Error:", err)
	}
	if nbrInfo.MacAddr != "c2:00:54:f5:00:00" {
		t.Error("Src Mac copy to NeighborInfo failed")
	}

	if nbrInfo.IpAddr != "fe80::c000:54ff:fef5:0" {
		t.Error("src ip address copy failed")
	}
}

func TestNDSOption(t *testing.T) {
	initTestPacket()
	testPktObj.InitLink(100, "2002::1/64", "00:e0:ec:26:a7:ee")
	addTestNbrEntry("2002::1", "2002::2")
	//dumpLinkInfo(t)
	ndsSourceTestPkt := []byte{0x33, 0x33, 0xff, 0x00, 0x00, 0x01, 0xd8, 0xeb, 0x97, 0xb6, 0x49, 0x7a, 0x86, 0xdd, 0x60, 0x00,
		0x00, 0x00, 0x00, 0x20, 0x3a, 0xff, 0x20, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x01, 0xff, 0x00, 0x00, 0x01, 0x87, 0x00, 0x7f, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x20, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01,
		0xd8, 0xeb, 0x97, 0xb6, 0x49, 0x7a,
	}
	p := gopacket.NewPacket(ndsSourceTestPkt, layers.LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	icmpv6Hdr := &layers.ICMPv6{}
	ipv6Hdr := &layers.IPv6{}
	pkt := testPktObj

	err := getIpAndICMPv6Hdr(p, ipv6Hdr, icmpv6Hdr)
	if err != nil {
		t.Error("Decoding ipv6 and icmpv6 header failed", err)
	}

	nds, err := pkt.decodeICMPv6Hdr(icmpv6Hdr, ipv6Hdr.SrcIP, ipv6Hdr.DstIP)
	if err != nil {
		t.Error("Validating ICMPv6 Header failed:", err)
	}
	optionWant := &NDOption{
		Type:   1,
		Length: 1,
		Value:  []byte{0xd8, 0xeb, 0x97, 0xb6, 0x49, 0x7a},
	}

	if !reflect.DeepEqual(nds.Options[0], optionWant) {
		t.Error("NDInfo Option is not correct", optionWant, nds.Options[0])
	}
}
