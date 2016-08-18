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
	"l3/ndp/config"
	"l3/ndp/debug"
	"net"
)

type Packet struct {
	PktCh chan config.PacketData
	// Neighbor Cache Information
	// This is map of string to link with (map of string to NeighborCache). Each key of the outer map is the our own
	// IP Address with its own Neigbor's map. Each inner map key is a Neighbor IP Address. Each inner map
	// expression retrieve the information pertaining to that neighbor
	LinkInfo map[string]Link

	// Prefix List Information
	// This is map of ifIndex (port where packet is received). Each key has PrefixList of its own
	LinkPrefixInfo map[int32]PrefixLink
}

func Init(pktCh chan config.PacketData) *Packet {
	pkt := &Packet{
		PktCh: pktCh,
	}
	pkt.LinkInfo = make(map[string]Link, 100)
	pkt.LinkPrefixInfo = make(map[int32]PrefixLink, 100)
	return pkt
}

/*
 * for a given link local ip address return the link information
 * link should be created via InitLink only... and it should be accessed in non-CIDR format
 */
func (p *Packet) GetLink(localIP string) (Link, bool) {
	debug.Logger.Debug("getlink called for", localIP)
	link, exists := p.LinkInfo[localIP]
	return link, exists
}

/*
 * Link has been modified update map entry with latest link information, this should only accept non-CIDR
 * ip address format
 */
func (p *Packet) SetLink(localIP string, link Link) {
	p.LinkInfo[localIP] = link
}

/*
 * Do Neighbor Cache Link Initialization Per Ip Address
 */
func (p *Packet) initLinkInfo(ifIndex int32, ip, mac string) {
	debug.Logger.Debug("Initializing link Info with ifIndex:", ifIndex, "ip:", ip, "mac:", mac)
	localIP, _, err := net.ParseCIDR(ip)
	if err != nil {
		debug.Logger.Err("Creating link Info for ip:", ip, "mac:", mac, "ifIndex:", ifIndex,
			"failed with error:", err)
		return
	}
	link, exists := p.LinkInfo[localIP.String()]
	if !exists {
		link.Init()
	}
	link.PortIfIndex = ifIndex
	link.LinkLocalAddress = mac
	// @TODO: need to get RETRANS_TIMER & REACHABLE_TIMER from config
	link.RetransTimer = 1000
	link.ReachableTime = 30000
	p.SetLink(localIP.String(), link)
	debug.Logger.Debug("New Packet LinkInfo is", link)
}

/*
 * for a given ifIndex it will return mylink where prefixes are learned
 */
func (p *Packet) GetLinkPrefix(ifIndex int32) (PrefixLink, bool) {
	debug.Logger.Debug("GetLinkPrefix called for", ifIndex)
	prefixLink, exists := p.LinkPrefixInfo[ifIndex]
	return prefixLink, exists
}

/*
 * Prefix Link has been modified and hence updating the map
 */
func (p *Packet) SetLinkPrefix(ifIndex int32, prefixLink PrefixLink) {
	p.LinkPrefixInfo[ifIndex] = prefixLink
}

/*
 *  Do Prefix Link Initialization Per IfIndex
 */
func (p *Packet) initPrefixList(ifIndex int32, ipAddr, mac string) {
	debug.Logger.Debug("Initializing Prefix Link for ifIndex:", ifIndex, "ip:", ipAddr, "mac:", mac)
	ip, _, err := net.ParseCIDR(ipAddr)
	if err != nil {
		debug.Logger.Err("Creating Link Prefix Info for ip:", ipAddr, "mac:", mac, "ifIndex:", ifIndex,
			"failed with error:", err)
		return
	}
	myLink, exists := p.LinkPrefixInfo[ifIndex]
	if exists {
		// then it means that we have received an update in ip address
		debug.Logger.Debug("Received Update for ifIndex:", ifIndex, "ipAddr:", ipAddr)
	} else {
		// this is first time create for the ifIndex
		debug.Logger.Debug("Received Create for ifIndex:", ifIndex, "ipAddr:", ipAddr)
	}

	if ip.IsLinkLocalUnicast() {
		// this is link local ip address
		myLink.LinkLocalIp = ip.String()
	} else {
		myLink.GlobalIp = ip.String()
	}

	p.LinkPrefixInfo[ifIndex] = myLink
	debug.Logger.Debug("New Packet LinkPrefixInfo is", myLink)
}

/*
 * Init Link information with IP Address, PortIfIndex, PortMacAddress, API is called when ip interface
 * is created. Input is expected to be in CIDR format only. This will be called during ip link create
 */
func (p *Packet) InitLink(ifIndex int32, ip, mac string) {
	// Initializing link for Neighbor Cache
	p.initLinkInfo(ifIndex, ip, mac)
	// Inititalizing link for PrefixList
	p.initPrefixList(ifIndex, ip, mac)
}

/*
 *  On delete ipv6 interface, we will get a request to delete the link.. we will call flush neighbor entries
 *  internally within the api and return the caller list of neighbor entries that need to be deleted from
 *  hardware
 *  @NOTE: input should in CIDR format
 */
func (p *Packet) DeleteLink(ip string) []string {
	deleteEntries, _ := p.FlushNeighbors(ip)
	localIp, _, err := net.ParseCIDR(ip)
	if err != nil {
		debug.Logger.Err("Parsing ip", ip, "failed with err:", err)
		return deleteEntries
	}
	// @TODO: add api to handle ip interface delete
	delete(p.LinkInfo, localIp.String())
	return deleteEntries
}
