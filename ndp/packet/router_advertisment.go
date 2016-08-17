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
	_ "encoding/binary"
	"errors"
	"fmt"
	"github.com/google/gopacket/layers"
	"l3/ndp/config"
	_ "l3/ndp/debug"
	"net"
)

/*
 * Validate
 *	- All included options have a length that is greater than zero.
 *
 * Cache below information during validation
 *	- Source Link-Layer Address
 *	- Prefix Information
 *	- MTU options
 */
func (nd *NDInfo) ValidateRAInfo() error {
	options := nd.Options
	if len(options) > 0 {
		for _, option := range options {
			switch option.Type {
			case NDOptionTypeSourceLinkLayerAddress:
				if option.Length == 0 {
					return errors.New(fmt.Sprintln("During Router Advertisement",
						"Source Link Layer Option has length as zero"))
				}
			case NDOptionTypeMTU:
				if option.Length == 0 {
					return errors.New(fmt.Sprintln("During Router Advertisement",
						"MTU Option has length as zero"))
				}
			}
		}
	}
	return nil
}

/*
 * When we get router advertisement packet we need to update the mac address of peer and move the state to
 * REACHABLE
 *
 * Based on ifIndex we will get a prefixLink which contains all the prefixes for that link
 *
 * fill the NDInfo and then return it back to caller
 */
func (p *Packet) HandleRAMsg(hdr *layers.ICMPv6, srcIP, dstIP net.IP, ifIndex int32) (*NDInfo, error) {
	prefixFound := false
	ndInfo := &NDInfo{}
	ndInfo.DecodeRAInfo(hdr.TypeBytes, hdr.LayerPayload())
	err := ndInfo.ValidateRAInfo()
	if err != nil {
		return ndInfo, err
	}
	prefixLink, exists := p.GetLinkPrefix(ifIndex)
	if !exists {
		return nil, errors.New(fmt.Sprintln("No Prefix found for ifIndex:", ifIndex))
	}

	// iterate over prefix list and update the information
	for _, prefix := range prefixLink.PrefixList {
		// check if this is the prefix I am looking for or not
		if prefix.IpAddr == srcIP.String() {
			prefixFound = true
			// @TODO: jgheewala add this support
			// update timer value with received Router Lifetime
		}
	}

	// if Prefix is found then we will return from here
	if prefixFound {
		return ndInfo, nil
	}

	// if no prefix is found then lets create a new entry
	prefix := PrefixInfo{}
	prefix.InitPrefix(srcIP.String(), ndInfo.RouterLifetime)
	prefixLink.PrefixList = append(prefixLink.PrefixList, prefix)
	return ndInfo, nil
}

/*
 * From eth, ipv6 and ndInfo populate neighbor information for programming chip
 */
func (p *Packet) GetNbrInfoUsingRAPkt(eth *layers.Ethernet, v6hdr *layers.IPv6,
	ndInfo *NDInfo) (nbrInfo config.NeighborInfo) {
	return nbrInfo
}
