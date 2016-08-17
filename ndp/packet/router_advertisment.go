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
	"l3/ndp/debug"
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
 * @TODO: need to handle case if srcIP is my own IP
 *
 * If srcIP is peer ip then we need to use dst ip to get link information and then update cache entry to be
 * reachable and also update peer mac address into the cache
 *
 * fill the NDInfo and then return it back to caller
 */
func (p *Packet) HandleRAMsg(hdr *layers.ICMPv6, srcIP, dstIP net.IP) (*NDInfo, error) {
	ndInfo := &NDInfo{}
	ndInfo.DecodeRAInfo(hdr.TypeBytes, hdr.LayerPayload())
	err := ndInfo.ValidateRAInfo()
	if err != nil {
		return ndInfo, err
	}

	_, exists := p.GetLink(srcIP.String())
	if exists {
		return ndInfo, errors.New("RA for my own IP is not yet supported")
	} else {
		link, found := p.GetLink(dstIP.String())
		if !found {
			return nil, errors.New("No link found for:" + dstIP.String())
		}
		cache, exists := link.NbrCache[srcIP.String()]
		if !exists {
			debug.Logger.Err("No Neigbor Entry found for:", srcIP.String(), "link IP:", dstIP.String())
			return nil, errors.New("No Neigbor Entry found for:" + srcIP.String() +
				" link IP:" + dstIP.String())
		}
		cache.State = REACHABLE
		cache.UpdateProbe()
		cache.RchTimer()
		if len(ndInfo.Options) > 0 {
			for _, option := range ndInfo.Options {
				if option.Type == NDOptionTypeSourceLinkLayerAddress {
					mac := net.HardwareAddr(option.Value)
					cache.LinkLayerAddress = mac.String()
				}
			}
		}
		debug.Logger.Debug("PEERRA: nbrCach (key, value) ---> (", srcIP.String(), ",", cache, ")")
		link.NbrCache[srcIP.String()] = cache
		p.SetLink(dstIP.String(), link)
	}

	return ndInfo, nil
}

/*
 * From eth, ipv6 and ndInfo populate neighbor information for programming chip
 */
func (p *Packet) GetNbrInfoUsingRAPkt(eth *layers.Ethernet, v6hdr *layers.IPv6,
	ndInfo *NDInfo) (nbrInfo config.NeighborInfo) {
	return nbrInfo
}
