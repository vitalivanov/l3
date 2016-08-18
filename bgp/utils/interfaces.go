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

// interfaces.go
package utils

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"utils/logging"
	netutils "utils/netUtils"
)

type IPInfo struct {
	IpAddr          net.IP
	IpMask          net.IPMask
	LinklocalIpAddr string
}
type InterfaceMgr struct {
	logger      *logging.Writer
	rwMutex     *sync.RWMutex
	ifIndexToIP map[int32]IPInfo //string
	ipToIfIndex map[string]int32
}

var ifaceMgr *InterfaceMgr

func NewInterfaceMgr(logger *logging.Writer) *InterfaceMgr {
	if ifaceMgr != nil {
		logger.Info("NewInterfaceMgr: Return the existing interface manager", ifaceMgr)
		return ifaceMgr
	}

	ifaceMgr = &InterfaceMgr{
		logger:      logger,
		rwMutex:     &sync.RWMutex{},
		ifIndexToIP: make(map[int32]IPInfo),
		ipToIfIndex: make(map[string]int32),
	}
	logger.Info("NewInterfaceMgr: Creating new interface manager", ifaceMgr)
	return ifaceMgr
}

func (i *InterfaceMgr) IsIPConfigured(ip string) bool {
	i.rwMutex.RLock()
	defer i.rwMutex.RUnlock()
	i.logger.Info("IsIPConfigured: ip", ip, "ipToIfIndex", i.ipToIfIndex)
	_, ok := i.ipToIfIndex[ip]
	return ok
}

func (i *InterfaceMgr) GetIfaceIP(ifIndex int32) (ipInfo IPInfo, err error) {
	var ok bool
	i.rwMutex.RLock()
	defer i.rwMutex.RUnlock()
	i.logger.Info("GetIfaceIP: ifIndex", ifIndex, "ifIndexToIP", i.ifIndexToIP)
	if ipInfo, ok = i.ifIndexToIP[ifIndex]; !ok {
		err = errors.New(fmt.Sprintf("Iface %d is not configured", ifIndex))
	}

	return ipInfo, err
}

func (i *InterfaceMgr) GetIfaceIfIdx(ipAddr string) (idx int32, err error) {
	var ok bool
	i.rwMutex.RLock()
	defer i.rwMutex.RUnlock()
	i.logger.Info("GetIfaceIdx: ipAddr", ipAddr, "ipAddrToIdx", i.ipToIfIndex)
	if idx, ok = i.ipToIfIndex[ipAddr]; !ok {
		err = errors.New(fmt.Sprintf("Iface %s is not configured", ipAddr))
	}

	return idx, err
}
func (i *InterfaceMgr) AddIface(ifIndex int32, addr string) {
	i.rwMutex.Lock()
	defer i.rwMutex.Unlock()
	i.logger.Info("AddIface: ifIndex", ifIndex, "ip", addr, "ifIndexToIP", i.ifIndexToIP, "ipToIfIndex", i.ipToIfIndex)

	ip, ipMask, err := net.ParseCIDR(addr)
	if err != nil {
		i.logger.Err("AddIface: ParseCIDR failed for addr", addr, "with error", err)
		return
	}

	var ipAddr string
	if oldIP, ok := i.ifIndexToIP[ifIndex]; ok {
		//delete(i.ifIndexToIP, ifIndex)
		//delete(i.ipToIfIndex, oldIP)
		ipAddr = oldIP.LinklocalIpAddr
	}
	ipInfo := IPInfo{
		IpAddr:          ip,
		IpMask:          ipMask.Mask,
		LinklocalIpAddr: ipAddr,
	}
	i.ifIndexToIP[ifIndex] = ipInfo //ip.String()
	i.ipToIfIndex[ip.String()] = ifIndex
}
func (i *InterfaceMgr) AddLinkLocalIface(ifIndex int32, addr string) {
	i.rwMutex.Lock()
	defer i.rwMutex.Unlock()
	i.logger.Info("AddIface: ifIndex", ifIndex, "ip", addr, "ifIndexToIP", i.ifIndexToIP, "ipToIfIndex", i.ipToIfIndex)

	var ipAddr net.IP
	var ipMask net.IPMask
	if oldIP, ok := i.ifIndexToIP[ifIndex]; ok {
		//delete(i.ifIndexToIP, ifIndex)
		//delete(i.ipToIfIndex, oldIP)
		ipAddr = oldIP.IpAddr
		ipMask = oldIP.IpMask
	}
	ipInfo := IPInfo{
		IpAddr:          ipAddr,
		IpMask:          ipMask,
		LinklocalIpAddr: addr,
	}
	i.ifIndexToIP[ifIndex] = ipInfo //ip.String()
	i.ipToIfIndex[addr] = ifIndex
}

func (i *InterfaceMgr) RemoveIface(ifIndex int32, addr string) {
	i.rwMutex.Lock()
	defer i.rwMutex.Unlock()
	i.logger.Info("RemoveIface: ifIndex", ifIndex, "ip", addr, "ifIndexToIP", i.ifIndexToIP, "ipToIfIndex",
		i.ipToIfIndex)

	if oldIP, ok := i.ifIndexToIP[ifIndex]; ok {
		if oldIP.LinklocalIpAddr == "" {
			delete(i.ifIndexToIP, ifIndex)
			delete(i.ipToIfIndex, oldIP.IpAddr.String())
			return
		}
		ipInfo := IPInfo{
			LinklocalIpAddr: oldIP.LinklocalIpAddr,
		}
		i.ifIndexToIP[ifIndex] = ipInfo
	}
}
func (i *InterfaceMgr) RemoveLinkLocalIface(ifIndex int32, addr string) {
	i.rwMutex.Lock()
	defer i.rwMutex.Unlock()
	i.logger.Info("RemoveIface: ifIndex", ifIndex, "ip", addr, "ifIndexToIP", i.ifIndexToIP, "ipToIfIndex",
		i.ipToIfIndex)

	if oldIP, ok := i.ifIndexToIP[ifIndex]; ok {
		if netutils.IsZeros(oldIP.IpAddr) {
			delete(i.ifIndexToIP, ifIndex)
			delete(i.ipToIfIndex, oldIP.LinklocalIpAddr)
			return
		}
		ipInfo := IPInfo{
			IpAddr: oldIP.IpAddr,
			IpMask: oldIP.IpMask,
		}
		i.ifIndexToIP[ifIndex] = ipInfo
	}
}
