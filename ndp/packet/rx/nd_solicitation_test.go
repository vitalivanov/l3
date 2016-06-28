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
package rx

import (
	_ "fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	_ "github.com/google/gopacket/pcap"
	"reflect"
	"testing"
)

var testPkt = []byte{
	0x33, 0x33, 0xff, 0xf5, 0x00, 0x00, 0xc2, 0x00, 0x54, 0xf5, 0x00, 0x00, 0x86, 0xdd, 0x6e, 0x00,
	0x00, 0x00, 0x00, 0x18, 0x3a, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x01, 0xff, 0xf5, 0x00, 0x00, 0x87, 0x00, 0x67, 0x3c, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x80,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x54, 0xff, 0xfe, 0xf5, 0x00, 0x00,
}

// Test ND Solicitation message Decoder
func TestICMPv6PayloadDecode(t *testing.T) {
	var err error
	p := gopacket.NewPacket(testPkt, layers.LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	t.Log("Calling GetNdSolicitationHeader")
	ndHeader := &layers.ICMPv6{}
	err = GetNdSolicitationHeader(p, ndHeader)
	if err != nil {
		t.Error("Decoding ND Solicitation message failed", err)
	} else {
		t.Log("Decoding ND Solicitation message success")
	}
	want := layers.ICMPv6{
		TypeCode: 0x8700,
		Checksum: 0x673c,
	}
	t.Log("ndHeader type:", ndHeader.TypeCode)
	t.Log("want type:", want.TypeCode)
	if !reflect.DeepEqual(ndHeader.TypeCode, want.TypeCode) {
		t.Error("TypeCode MisMatch")
	}
	t.Log("ndHeader Checksum:", ndHeader.Checksum)
	t.Log("want Checksum:", want.Checksum)
	if !reflect.DeepEqual(ndHeader.Checksum, want.Checksum) {
		t.Error("Checksum MisMatch")
	}
}
