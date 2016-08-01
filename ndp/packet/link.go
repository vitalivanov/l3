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
	"l3/ndp/debug"
	"net"
)

/*
 *  initialize link neigbor cache map
 */
func (l *Link) Init() {
	if l.NbrCache == nil {
		l.NbrCache = make(map[string]NeighborCache, 10)
	}
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
 * Init Link information with IP Address, PortIfIndex, PortMacAddress, API is called when ip interface
 * is created. Input is expected to be in CIDR format only. This will be called during ip link create
 */
func (p *Packet) InitLink(ifIndex int32, ip, mac string) {
	debug.Logger.Debug("Initializing link with ifIndex:", ifIndex, "ip:", ip, "mac:", mac)
	localIP, _, err := net.ParseCIDR(ip)
	if err != nil {
		debug.Logger.Err("Creating link for ip:", ip, "mac:", mac, "ifIndex:", ifIndex,
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
	debug.Logger.Debug("Packet Link Info is", p.LinkInfo)
}
