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
	"github.com/google/gopacket/layers"
	"infra/sysd/sysdCommonDefs"
	"l3/ndp/debug"
	"log/syslog"
	"reflect"
	"testing"
	"utils/logging"
)

const (
	TEST_ALL_NODES_MULTICAST_IPV6_ADDRESS       = "ff02::1"
	TEST_ALL_NODES_MULTICAST_LINK_LAYER_ADDRESS = "33:33:00:00:00:01"
)

var raBaseTestPkt = []byte{
	0x33, 0x33, 0x00, 0x00, 0x00, 0x01, 0x88, 0x1d, 0xfc, 0xcf, 0x15, 0xfc, 0x86, 0xdd, 0x60, 0x00,
	0x00, 0x00, 0x00, 0x20, 0x3a, 0xff, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x1d,
	0xfc, 0xff, 0xfe, 0xcf, 0x15, 0xfc, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x86, 0x00, 0xf2, 0x66, 0x40, 0x00, 0x07, 0x08, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x88, 0x1d, 0xfc, 0xcf, 0x15, 0xfc, 0x05, 0x01,
	0x00, 0x00, 0x00, 0x00, 0x05, 0xdc,
}

var test_srcMac = "88:1d:fc:cf:15:fc"
var test_linkScope_IP = "fe80::8a1d:fcff:fecf:15fc"

func PacketTestNewLogger(name string, tag string, listenToConfig bool) (*logging.Writer, error) {
	var err error
	srLogger := new(logging.Writer)
	srLogger.MyComponentName = name

	srLogger.SysLogger, err = syslog.New(syslog.LOG_DEBUG|syslog.LOG_DAEMON, tag)
	if err != nil {
		fmt.Println("Failed to initialize syslog - ", err)
		return srLogger, err
	}

	srLogger.GlobalLogging = true
	srLogger.MyLogLevel = sysdCommonDefs.INFO
	return srLogger, err
}

func initPacketTestBasics() {
	t := &testing.T{}
	logger, err := PacketTestNewLogger("ndpd", "NDPTEST", true)
	if err != nil {
		t.Error("creating logger failed")
	}
	debug.NDPSetLogger(logger)
}

func TestRAEncode(t *testing.T) {
	initPacketTestBasics()
	pkt := &Packet{
		SrcMac: test_srcMac,
		DstMac: TEST_ALL_NODES_MULTICAST_LINK_LAYER_ADDRESS,
		DstIp:  TEST_ALL_NODES_MULTICAST_IPV6_ADDRESS,
		PType:  layers.ICMPv6TypeRouterAdvertisement,
	}
	pkt.SrcIp = test_linkScope_IP
	pktToSend := pkt.Encode()

	if !reflect.DeepEqual(pktToSend, raBaseTestPkt) {
		t.Error("Failed encoding RA pkt")
		for idx, _ := range pktToSend {
			t.Errorf("0x%x", pktToSend[idx])
		}
		for idx, _ := range raBaseTestPkt {
			t.Errorf("0x%x", raBaseTestPkt[idx])
		}
		return
	}
}
