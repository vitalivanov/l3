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

/*
                 NEIGHBOR SOLICITATION MESSAGE FORMAT

*    0                   1                   2                   3
*    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
*   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*   |     Type      |     Code      |          Checksum             |
*   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*   |                           Reserved                            |
*   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*   |                                                               |
*   +                                                               +
*   |                                                               |
*   +                       Target Address                          +
*   |                                                               |
*   +                                                               +
*   |                                                               |
*   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*   |   Options ...
*   +-+-+-+-+-+-+-+-+-+-+-+-

*/
import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	_ "github.com/google/gopacket/pcap"
	"l3/ndp/debug"
	_ "net"
	_ "time"
)

func ProcessNdSolicitationPkt(pkt gopacket.Packet) error {
	ethLayer := pkt.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return errors.New("Invalid eth layer")
	}
	eth := ethLayer.(*layers.Ethernet)
	// copy src mac and dst mac
	debug.Logger.Info(fmt.Sprintln("ethernet layer is", eth))

	ipLayer := pkt.Layer(layers.LayerTypeIPv6)
	if ipLayer == nil {
		return errors.New("Invalid IPv6 layer")
	}

	ipHdr := ipLayer.(*layers.IPv6)
	debug.Logger.Info(fmt.Sprintln("ip header is", ipHdr))

	ipPayload := ipLayer.LayerPayload()
	//DecodeNdSolicitation(ipPayload)
	var icmpv6 layers.ICMPv6
	icmpv6.DecodeFromBytes(ipPayload, nil)

	return nil
}
