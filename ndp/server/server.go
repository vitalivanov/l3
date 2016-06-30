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
	"l3/ndp/packet"
	_ "models/objects"
	"os"
	"os/signal"
	"syscall"
	"time"
	"utils/asicdClient"
)

func NDPNewServer(sPlugin asicdClient.AsicdClientIntf) *NDPServer {
	svr := &NDPServer{}
	svr.SwitchPlugin = sPlugin
	return svr
}

/* OS signal handler.
 *      If the process get a sighup signal then close all the pcap handlers.
 *      After that delete all the memory which was used during init process
 */
func (svr *NDPServer) SignalHandler(sigChannel <-chan os.Signal) {
	signal := <-sigChannel
	switch signal {
	case syscall.SIGHUP:
		//svr.lldpExit <- true
		debug.Logger.Alert("Received SIGHUP Signal")
		//svr.CloseAllPktHandlers()
		svr.DeInitGlobalDS()
		//svr.CloseDB()
		//pprof.StopCPUProfile()
		debug.Logger.Alert("Exiting!!!!!")
		os.Exit(0)
	default:
		debug.Logger.Info(fmt.Sprintln("Unhandled Signal:", signal))
	}
}

/*  Create os signal handler channel and initiate go routine for that
 */
func (svr *NDPServer) OSSignalHandle() {
	sigChannel := make(chan os.Signal, 1)
	signalList := []os.Signal{syscall.SIGHUP}
	signal.Notify(sigChannel, signalList...)
	go svr.SignalHandler(sigChannel)
}

func (svr *NDPServer) InitGlobalDS() {
	svr.PhyPort = make(map[int32]config.PortInfo, NDP_SYSTEM_PORT_MAP_CAPACITY)
	svr.L3Port = make(map[int32]config.IPv6IntfInfo, NDP_SYSTEM_PORT_MAP_CAPACITY)
	svr.Ipv6Ch = make(chan *config.IPv6IntfInfo)
	svr.RxPktCh = make(chan *RxPktInfo)
	svr.SnapShotLen = 1024
	svr.Promiscuous = false
	svr.Timeout = 1 * time.Second
}

func (svr *NDPServer) DeInitGlobalDS() {
	svr.PhyPort = nil
	svr.L3Port = nil
	svr.Ipv6Ch = nil
	svr.RxPktCh = nil
}

func (svr *NDPServer) InitSystemPortInfo(portInfo *config.PortInfo) {
	if portInfo == nil {
		return
	}
	svr.PhyPort[portInfo.IfIndex] = *portInfo
	svr.ndpIntfStateSlice = append(svr.ndpIntfStateSlice, portInfo.IfIndex)
}

func (svr *NDPServer) InitSystemIPIntf(entry *config.IPv6IntfInfo, ipInfo *config.IPv6IntfInfo) {
	if ipInfo == nil || entry == nil {
		return
	}
	entry.IfIndex = ipInfo.IfIndex
	entry.IntfRef = ipInfo.IntfRef
	entry.OperState = ipInfo.OperState
	entry.IpAddr = ipInfo.IpAddr
	svr.ndpL3IntfStateSlice = append(svr.ndpL3IntfStateSlice, ipInfo.IfIndex)
}

/*
 * API: it will collect all ipv6 interface ports from the system... If needed we can collect port information
 *      also from the system.
 *	After the information is collected, if the oper state is up then we will start rx/tx
 */
func (svr *NDPServer) InitSystem() {
	/*
		//we really should not be carrying for system port state...???
		portStates := svr.GetPorts()
		for _, port := range portStates {
			svr.InitSystemPortInfo(port)
		}

	*/
	ipIntfs := svr.GetIPIntf()
	for _, ipIntf := range ipIntfs {
		ipPort := svr.L3Port[ipIntf.IfIndex]
		svr.InitSystemIPIntf(&ipPort, ipIntf)
		svr.L3Port[ipIntf.IfIndex] = ipPort
		if ipPort.OperState == NDP_IP_STATE_UP {
			svr.StartRxTx(ipIntf)
		}
	}
}

func (svr *NDPServer) EventsListener() {
	for {
		select {
		case ipv6Notify := <-svr.Ipv6Ch:
			svr.HandleIPv6Notification(ipv6Notify)
		case inPkt, ok := <-svr.RxPktCh:
			if !ok {
				continue
			}
			_, exists := svr.L3Port[inPkt.ifIndex]
			if !exists {
				continue
			}
			packet.ValidateNdSolicitation(inPkt.pkt)
		}
	}
}

/*  ndp server:
 * 1) OS Signal Handler
 * 2) Read from DB and close DB
 * 3) Connect to all the clients
 * 4) Call AsicPlugin for port information
 * 5) go routine to handle all the channels within lldp server
 */

func (svr *NDPServer) NDPStartServer() {
	svr.OSSignalHandle()
	svr.ReadDB()
	svr.InitGlobalDS()
	svr.InitSystem()
	go svr.EventsListener()
}
