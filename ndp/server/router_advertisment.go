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
package server

import (
	_ "encoding/binary"
	_ "github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"l3/ndp/config"
	_ "l3/ndp/debug"
	"l3/ndp/packet"
	_ "net"
)

/*
 * When we get router advertisement packet we need to update the mac address of peer and move the state to
 * REACHABLE
 *
 * Based on ifIndex we will get a prefixLink which contains all the prefixes for that link
 *
 * fill the NDInfo and then return it back to caller
 */
func (intf *Interface) processRA(ndInfo *packet.NDInfo) (nbrInfo *config.NeighborConfig, oper NDP_OPERATION) {
	nbrKey := intf.createNbrKey(ndInfo)
	nbr, exists := intf.Neighbor[nbrKey]
	if exists {
		if ndInfo.RouterLifetime == 0 {
			// delete this neighbor
			nbrInfo = nbr.populateNbrInfo(intf.IfIndex, intf.IntfRef)
			nbr.DeInit()
			delete(intf.Neighbor, nbr.IpAddr)
			return nbrInfo, DELETE
		} else {
			// update existing neighbor timers
			// Recahable timer reset
			// Router Lifetime/Invalidation Timer reset
			// Stop any probes
			nbr.State = REACHABLE
			nbr.InValidTimer(ndInfo.RouterLifetime)
			nbr.RchTimer()
			oper = UPDATE
		}
	} else {
		// create new neighbor
		nbr.InitCache(intf.reachableTime, intf.retransTime, nbrKey, intf.PktDataCh, intf.IfIndex)
		nbr.InValidTimer(ndInfo.RouterLifetime)
		nbr.RchTimer()
		nbr.State = REACHABLE
		nbrInfo = nbr.populateNbrInfo(intf.IfIndex, intf.IntfRef)
		oper = CREATE

	}
	intf.Neighbor[nbrKey] = nbr
	return nbrInfo, oper
}

/*
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
	var mac string
	for _, option := range ndInfo.Options {
		if option.Type == NDOptionTypeSourceLinkLayerAddress {
			macAddr := net.HardwareAddr(option.Value)
			mac = macAddr.String()
			break
		}
	}
	prefix.InitPrefix(srcIP.String(), mac, ndInfo.RouterLifetime)
	prefixLink.PrefixList = append(prefixLink.PrefixList, prefix)
	return ndInfo, nil
}
*/

/*
 * From eth, ipv6 and ndInfo populate neighbor information for programming chip
 */
/*
func (p *Packet) GetNbrInfoUsingRAPkt(eth *layers.Ethernet, v6hdr *layers.IPv6,
	ndInfo *NDInfo) (nbrInfo config.NeighborInfo) {

	if ndInfo.RouterLifetime == 0 {
		// @TODO: mark this entry for delete
	}
	// by default all RA Pkt are marked as reachable, is this correct??
	nbrInfo.State = REACHABLE
	// @TODO: can we use eth layer for mac Address ???
	nbrInfo.MacAddr = eth.SrcMAC.String()
	nbrInfo.IpAddr = v6hdr.SrcIP.String()

	return nbrInfo
}

/*
 *  Router Advertisement Packet is send out for both link scope ip and global scope ip on timer expiry & port
 *  up notification
*/
func (intf *Interface) SendRA(srcMac string) {
	pkt := &packet.Packet{
		SrcMac: srcMac,
		PType:  layers.ICMPv6TypeRouterAdvertisement,
	}
	pkt.SrcIp = intf.linkScope
	pktToSend := pkt.Encode()
	intf.writePkt(pktToSend)

	pkt.SrcIp = intf.globalScope
	pktToSend = pkt.Encode()
	intf.writePkt(pktToSend)

	intf.RAResTransmitTimer()
}
