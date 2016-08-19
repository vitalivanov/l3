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
	"errors"
	"fmt"
	"l3/ndp/debug"
	"net"
)

type Link struct {
	NbrCache         map[string]NeighborCache
	PortIfIndex      int32
	LinkLocalAddress string // This is our link local mac address
	RetransTimer     uint32 // User should enter the value in mili-seconds, which is transferred to NbrCache
	ReachableTime    uint32 // User should enter the value in mili-seconds, which is transferred to NbrCache
}

/*
 *  initialize link neigbor cache map
 */
func (l *Link) Init() {
	if l.NbrCache == nil {
		l.NbrCache = make(map[string]NeighborCache, 10)
	}
}

/*
 *  On link down.. server will request to delete all the neighbors from the cache..
 *  We will iterate over all the neighbors, stop its timer and delete the neighbor cache
 *  @NOTE: Always start from the bottom most layer as we never know when golang will run its garbage collector
 */
func (p *Packet) FlushNeighbors(ip string) ([]string, error) {
	debug.Logger.Debug("Deleting all neighbor entries for link", ip)
	deleteEntries := make([]string, 0)
	// during link local down we will have CIDR format ip
	localIp, _, err := net.ParseCIDR(ip)
	if err != nil {
		debug.Logger.Err("Parsing ip", ip, "failed with err:", err)
		return deleteEntries, errors.New(fmt.Sprintln("Parsing ip", ip, "failed with err:", err))
	}
	link, exists := p.GetLink(localIp.String())
	if !exists {
		debug.Logger.Err("Cannot delete neighbors for", localIp.String(), "as there is no such link entry")
		return deleteEntries, errors.New(fmt.Sprintln("Cannot delete neighbors for", localIp.String(),
			"as there is no such link entry"))
	}
	for _, cache := range link.NbrCache {
		key := cache.IpAddr
		deleteEntries = append(deleteEntries, key)
		debug.Logger.Debug("Deleting Neighbor", cache.IpAddr)
		cache.DeInitCache()
		delete(link.NbrCache, key)
	}
	p.SetLink(localIp.String(), link)
	// do not delete link information here... only if IP interface is deleted then we need to delete
	// link information
	return deleteEntries, nil
}

/*
 *  On timer expires and max unicast solicitation we will delete a specific neighbor from link neighbor cache
 */
func (p *Packet) DeleteNeighbor(ip string, nbrIP string) (deleteEntries []string, err error) {
	// Input is absolute ip address
	link, exists := p.GetLink(ip)
	if !exists {
		return deleteEntries, errors.New(fmt.Sprintln("Cannot delete neighbors for", ip,
			"as there is no such link entry"))
	}

	for _, cache := range link.NbrCache {
		if nbrIP == cache.IpAddr {
			deleteEntries = append(deleteEntries, nbrIP)
			debug.Logger.Debug("Deleting Neighbor", cache.IpAddr)
			cache.DeInitCache()
			delete(link.NbrCache, nbrIP)
			break
		}
	}
	p.SetLink(ip, link)

	return deleteEntries, nil
}
