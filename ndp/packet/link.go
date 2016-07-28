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
	"l3/ndp/debug"
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
 */
func (p *Packet) GetLink(localIP string) (Link, bool) {
	link, exists := p.LinkInfo[localIP]
	if !exists {
		link.Init()
	}
	return link, exists
}

/*
 * Link has been modified update map entry with latest link information
 */
func (p *Packet) SetLink(localIP string, link Link) {
	p.LinkInfo[localIP] = link
}

/*
 * Init Link information with IP Address, PortIfIndex, PortMacAddress, API is called when ip interface
 * is created
 */
func (p *Packet) InitLink(ifIndex int32, ip, mac string) {
	debug.Logger.Info(fmt.Sprintln("Initializing link with ifIndex:", ifIndex, "ip:", ip, "mac:", mac))
	link, _ := p.GetLink(ip)
	link.PortIfIndex = ifIndex
	link.LinkLocalAddress = mac
	p.SetLink(ip, link)
}
