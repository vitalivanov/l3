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
	"l3/ndp/config"
	"l3/ndp/debug"
)

/*
 *	StartRxTx      a) Check if entry is present in the map
 *		       b) If no entry create one do the initialization for the entry
 *		       c) Create Pcap Handler & add the entry to up interface slice
 *		       d) Start receiving Packets
 */
func (svr *NDPServer) StartRxTx(msg *config.IPv6IntfInfo) {
	ipPort, exists := svr.L3Port[msg.IfIndex]
	if !exists {
		// This will copy msg (intRef, ifIndex, ipAddr) into ipPort
		// And also create an entry into the ndpL3IntfStateSlice
		svr.InitSystemIPIntf(&ipPort, msg)
	}
	err := svr.CreatePcapHandler(ipPort.IntfRef, ipPort.PcapBase.PcapHandle)
	if err != nil {
		return
	}
	svr.L3Port[msg.IfIndex] = ipPort
	debug.Logger.Info(fmt.Sprintln("Start rx/tx for port:", ipPort.IntfRef, "ifIndex:", ipPort.IfIndex,
		"ip address", ipPort.IpAddr))

	// Spawn go routines for rx & tx
	svr.ndpUpL3IntfStateSlice = append(svr.ndpUpL3IntfStateSlice, msg.IfIndex)
}

/*
 *	StopRxTx       a) Check if entry is present in the map
 *		       b) If present then send a ctrl signal to stop receiving packets
 *		       c) block until cleanup is going on
 *		       c) delete the entry from up interface slice
 */
func (svr *NDPServer) StopRxTx(ifIndex int32) {
	ipPort, exists := svr.L3Port[ifIndex]
	if !exists {
		debug.Logger.Err(fmt.Sprintln("No entry found for ifIndex:", ifIndex))
		return
	}

	// Delete Entry from Slice
	svr.DeleteL3IntfFromUpState(ipPort.IfIndex)
}
