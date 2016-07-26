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
	err = DecodeNDInfo(ndTestPkt, nds)
	if err != nil {
		t.Error("Decoding ipv6 and icmpv6 header failed", err)
	}
	ndWant := &NDInfo{
		TargetAddress: net.IP{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x54, 0xff, 0xfe, 0xf5, 0x00, 0x01},
	}
	if !reflect.DeepEqual(nds, ndWant) {
		t.Error("Decoding NDS Failed")
	}
}

// Test ND Options
func TestNDOptionDecoder(t *testing.T) {
	nds := &NDInfo{}
	err := DecodeNDInfo(OptionRawByteWithTarget, nds)
	if err != nil {
		t.Error("Decoding ipv6 and icmpv6 header failed", err)
	}
	ndWant := &NDInfo{
		TargetAddress: net.IP{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x54, 0xff, 0xfe, 0xf5, 0x00, 0x01},
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
	b := net.IP{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x54, 0xff, 0xfe, 0xf5, 0x00, 0x01}

	// b is not multicast address, fail the test case if true is returned
	if IsTargetMulticast(b) {
		t.Error("byte is not ipv6 muticast address", b)
	}

	b[0] = 0xff
	// b is multicast address, fail the test case if false is returned
	if !IsTargetMulticast(b) {
		t.Error("byte is ipv6 muticast address", b)
	}
}

// Test ND Solicitation src ip Address Validation
func TestNDSInformation(t *testing.T) {
	srcIP := net.IP{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	dstIP := net.IP{0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x10, 0x78, 0x2e}
	//t.Log("SrcIP->", srcIP.String(), "DstIP->", dstIP.String())
	err := ValidateNDSInfo(srcIP, dstIP, nil)
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

	err = ValidateNDSInfo(srcIP, dstIP, ndInfo.Options)
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
	err = ValidateNDSInfo(srcIP, dstIP, ndInfo1.Options)
	if err == nil {
		t.Error("Neigbor solicitation should fail for any option other than Source Link Layer Address")
	}
	srcIP = net.IP{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	//t.Log("SrcIP->", srcIP.String(), "DstIP->", dstIP.String())
	err = ValidateNDSInfo(srcIP, dstIP, nil)
	if err != nil {
		t.Error("Validation of ip address", srcIP, "failed with error", err)
	}
	dstIP = net.IP{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x54, 0xff, 0xfe, 0xf5, 0x00, 0x01}
	//t.Log("SrcIP->", srcIP.String(), "DstIP->", dstIP.String())
	err = ValidateNDSInfo(srcIP, dstIP, nil)
	if err != nil {
		t.Error("Validation of ip address", srcIP, "dst Ip", dstIP, "failed with error", err)
	}
}

// Test ND Advertisement check
func TestValidateNDAInfo(t *testing.T) {
	dstIp := net.IP{0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	flags := []byte{0xa0, 00, 00, 00}
	err := ValidateNDAInfo(flags, dstIp)
	if err != nil {
		t.Error("Validation of nda failed, error:", err)
	}
	flags1 := []byte{0x40, 00, 00, 00, 00}
	err = ValidateNDAInfo(flags1, dstIp)
	if err == nil {
		t.Error("Validation of nda didn't failed, error:", err)
	}
	dstIp = net.IP{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x54, 0xff, 0xfe, 0xf5, 0x00, 0x01}
	err = ValidateNDAInfo(flags1, dstIp)
	if err != nil {
		t.Error("Validation of nda failed, error:", err)
	}
}

func TestConstructNSPacket(t *testing.T) {
	targetAddr := "2002::1"
	srcMac := "00:e0:ec:26:a7:ee"
	dstMac := "33:33:ff:00:00:01"
	rcvdBytes := ConstructNSPacket(targetAddr, "::", srcMac, dstMac, net.ParseIP(targetAddr).To16())
	wantEthLayer := []byte{0x33, 0x33, 0xff, 0x00, 0x00, 0x01, 0x00, 0xe0, 0xec, 0x26, 0xa7, 0xee, 0x86, 0xdd}
	encodedEthLayer := &layers.Ethernet{}
	p := gopacket.NewPacket(rcvdBytes, layers.LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	err := getEthLayer(p, encodedEthLayer)
	if err != nil {
		t.Error(err)
	}
	t.Log(rcvdBytes)
	t.Log(ndsTest)
	if !reflect.DeepEqual(encodedEthLayer, wantEthLayer) {
		t.Error("Ethernet layer construct is invalid")
	}
}
