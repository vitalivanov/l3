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
	/*
		"encoding/binary"
		"fmt"
		"infra/sysd/sysdCommonDefs"
		"l3/ndp/config"
		"log/syslog"
		"utils/logging"
	*/
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
	"reflect"
	"testing"
)

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
		t.Error("DstIP mismatch, want:", ipv6Want.DstIP, "got:", ipv6Hdr.DstIP)
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
	initPacketTestBasics()
	p := gopacket.NewPacket(nsBaseTestPkt, layers.LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	eth := &layers.Ethernet{}
	err := getEthLayer(p, eth)
	if err != nil {
		t.Error("failed to get ethener layer", err)
	}

	if (eth.SrcMAC).String() != testNsSrcMac {
		t.Error("Src Mac", (eth.SrcMAC).String(), "doesn't match:", testNsSrcMac)
		return
	}

	if (eth.DstMAC).String() != testNsDstMac {
		t.Error("DstMac", (eth.SrcMAC).String(), "doesn't match:", testNsDstMac)
		return
	}
}

// Test ND Solicitation message Decoder
func TestIPv6AndICMPv6UnicastNSHdr(t *testing.T) {
	initPacketTestBasics()
	var err error
	p := gopacket.NewPacket(nsBaseTestPkt, layers.LinkTypeEthernet, gopacket.Default)
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
		TrafficClass: 0x00,
		FlowLabel:    0,
		Length:       32,
		NextHeader:   layers.IPProtocolICMPv6,
		HopLimit:     255,
		SrcIP:        net.IP{0xfe, 0x80, 0x0, 0x0, 0x00, 0x0, 0x0, 0x0, 0x02, 0x1f, 0x16, 0xff, 0xfe, 0x25, 0x33, 0xce},
		DstIP:        net.IP{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0xf1, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
	}
	ndWant := &layers.ICMPv6{
		TypeCode: 0x8700,
		Checksum: 0xa686,
	}
	DeepCheckIPv6Hdr(ipv6Hdr, ipv6Want, t)
	DeepCheckNDHdr(icmpv6Hdr, ndWant, t)
}

func TestDecodeUnicstNSICMPv6Hdr(t *testing.T) {
	initPacketTestBasics()
	p := gopacket.NewPacket(nsBaseTestPkt, layers.LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	icmpv6Hdr := &layers.ICMPv6{}
	ipv6Hdr := &layers.IPv6{}
	err := getIpAndICMPv6Hdr(p, ipv6Hdr, icmpv6Hdr)
	if err != nil {
		t.Error("Decoding ipv6 and icmpv6 header failed", err)
	}

	pkt := &Packet{}
	ndOpt := &NDOption{
		Type:   NDOptionTypeSourceLinkLayerAddress,
		Length: 1,
		Value:  []byte{0x00, 0x1f, 0x16, 0x25, 0x33, 0xce},
	}
	wantNDinfo := &NDInfo{
		TargetAddress: net.ParseIP("2001:db8:0:f101::1"),
		PktType:       layers.ICMPv6TypeNeighborSolicitation,
	}
	wantNDinfo.Options = append(wantNDinfo.Options, ndOpt)

	ndInfo, err := pkt.decodeICMPv6Hdr(icmpv6Hdr, ipv6Hdr.SrcIP, ipv6Hdr.DstIP)
	if err != nil {
		t.Error("Validating ICMPv6 Header failed:", err)
	}
	if !reflect.DeepEqual(ndInfo, wantNDinfo) {
		t.Error("ndinfo:", ndInfo, "doesnt match wanted ndInfo:", wantNDinfo, "for unicast NS", err)
		t.Error(ndInfo.Options[0], wantNDinfo.Options[0])
	}
}
