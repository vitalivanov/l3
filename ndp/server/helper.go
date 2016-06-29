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
	"fmt"
	"github.com/google/gopacket/pcap"
	"l3/ndp/config"
	"l3/ndp/debug"
)

/*
 * API: will return all system port information
 */
func (svr *NDPServer) GetPorts() []*config.PortInfo {
	debug.Logger.Info("Get Port State List")
	portStates := make([]*config.PortInfo, 0)
	portsInfo, err := svr.SwitchPlugin.GetAllPortState()
	if err != nil {
		debug.Logger.Err(fmt.Sprintln("Failed to get all ports from system, ERROR:", err))
		return portStates
	}
	for _, obj := range portsInfo {
		port := &config.PortInfo{
			IntfRef:   obj.IntfRef,
			IfIndex:   obj.IfIndex,
			OperState: obj.OperState,
			Name:      obj.Name,
		}
		pObj, err := svr.SwitchPlugin.GetPort(obj.Name)
		if err != nil {
			debug.Logger.Err(fmt.Sprintln("Getting mac address for",
				obj.Name, "failed, error:", err))
		} else {
			port.MacAddr = pObj.MacAddr
			port.Description = pObj.Description
		}
		portStates = append(portStates, port)
	}

	debug.Logger.Info("Done with Port State list")
	return portStates
}

/*
 * API: will return all system L3 interfaces information
 */
func (svr *NDPServer) GetIPIntf() []*config.IPv6IntfInfo {
	debug.Logger.Info("Get IPv6 Interface List")
	ipStates := make([]*config.IPv6IntfInfo, 0)
	ipsInfo, err := svr.SwitchPlugin.GetAllIPv6IntfState()
	if err != nil {
		debug.Logger.Err(fmt.Sprintln("Failed to get all ipv6 interfaces from system, ERROR:", err))
		return ipStates
	}
	for _, obj := range ipsInfo {
		ipInfo := &config.IPv6IntfInfo{
			IntfRef:   obj.IntfRef,
			IfIndex:   obj.IfIndex,
			OperState: obj.OperState,
			IpAddr:    obj.IpAddr,
		}
		ipStates = append(ipStates, ipInfo)
	}
	debug.Logger.Info("Done with IPv6 State list")
	return ipStates
}

/*
 * API: will create pcap handler for each port
 */
func (svr *NDPServer) CreatePcapHandler(name string, pHdl *pcap.Handle) error {
	pHdl, err := pcap.OpenLive(name, svr.SnapShotLen, svr.Promiscuous, svr.Timeout)
	if err != nil {
		debug.Logger.Err(fmt.Sprintln("Creating Pcap Handler failed for", name, "Error:", err))
		return err
	}
	filter := "(ip6[6] == 0x3a) and (ip6[40] >= 133 && ip6[40] <= 137)"
	err = pHdl.SetBPFFilter(filter)
	if err != nil {
		debug.Logger.Err(fmt.Sprintln("Creating BPF Filter failed Error", err))
		pHdl = nil
		return err
	}
	return err
}

/*
 * API: will delete pcap handler for each port
 */
func (svr *NDPServer) DeletePcapHandler(pHdl *pcap.Handle) {
	if pHdl != nil {
		pHdl.Close()
		pHdl = nil
	}
}

/*  API: will handle IPv6 notifications received from switch/asicd
 */
func (svr *NDPServer) HandleIPv6Notification(msg *config.IPv6IntfInfo) {

}
