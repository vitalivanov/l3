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
	"l3/ndp/flexswitch"
	_ "models/objects"
	"os"
	"os/signal"
	"syscall"
	"utils/dmnBase"
)

func NDPNewServer(baseObj *dmnBase.FSDaemon) *NDPServer {
	svr := &NDPServer{}
	svr.DmnBase = baseObj
	svr.DmnBase.NewServer()                      // Allocate memory to channels
	debug.NDPSetLogger(baseObj.FSBaseDmn.Logger) // @TODO: Change this to interface and move it to util
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
	svr.PhyPort = make(map[string]config.PortInfo, NDP_SYSTEM_PORT_MAP_CAPACITY)
	svr.L3Port = make(map[string]config.IPv6IntfInfo, NDP_SYSTEM_PORT_MAP_CAPACITY)
}

func (svr *NDPServer) DeInitGlobalDS() {
	svr.PhyPort = nil
	svr.L3Port = nil
}

func (svr *NDPServer) InitSystemPortInfo(portInfo *config.PortInfo) {
	if portInfo == nil {
		return
	}
	svr.PhyPort[portInfo.IntfRef] = *portInfo
	svr.ndpIntfStateSlice = append(svr.ndpIntfStateSlice, portInfo.IntfRef)
}

func (svr *NDPServer) InitSystemIPIntf(ipInfo *config.IPv6IntfInfo) {
	if ipInfo == nil {
		return
	}
	svr.L3Port[ipInfo.IntfRef] = *ipInfo
	svr.ndpL3IntfStateSlice = append(svr.ndpL3IntfStateSlice, ipInfo.IntfRef)
}

// @TODO: Once we have the changes for modularity from FS Base Daemon we will use that to change this code
func (svr *NDPServer) CollectSystemInformation() {
	portStates := flexswitch.GetPorts(svr.DmnBase.Asicdclnt.ClientHdl, svr.DmnBase.AsicdSubSocket)
	for _, port := range portStates {
		svr.InitSystemPortInfo(port)
	}

	//vlans := flexswitch.GetVlans(svr.DmnBase.Asicdclnt.ClientHdl, svr.DmnBase.AsicdSubSocket)

	ipIntfs := flexswitch.GetIPIntf(svr.DmnBase.Asicdclnt.ClientHdl, svr.DmnBase.AsicdSubSocket)
	for _, ipIntf := range ipIntfs {
		svr.InitSystemIPIntf(ipIntf)
	}
}

func (svr *NDPServer) InitPcapHdlrs() {
	for _, intfRef := range svr.ndpIntfStateSlice {
		port := svr.PhyPort[intfRef]
		if port.OperState == NDP_PORT_STATE_UP {
			// create pcap handler
			svr.ndpUpIntfStateSlice = append(svr.ndpUpIntfStateSlice, port.IntfRef)
		}
	}

	for _, intfRef := range svr.ndpL3IntfStateSlice {
		l3 := svr.L3Port[intfRef]
		if l3.OperState == NDP_IP_STATE_UP {
			// create pcap handler
			svr.ndpUpL3IntfStateSlice = append(svr.ndpUpL3IntfStateSlice, l3.IntfRef)
		}
	}
}

func (svr *NDPServer) EventsListener() {
	for {
		select {
		//@TODO: need to make this modular... this is bad design, we cannot run ndp alone
		case rxBuf, ok := <-svr.DmnBase.AsicdSubSocketCh:
			if !ok {
				debug.Logger.Err("Switch Channel Closed")
			} else {
				flexswitch.ProcessMsg(rxBuf)
			}
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
	// @TODO: Base class should be interface where the call is agnostic to the server
	svr.DmnBase.InitSubscribers(make([]string, 0))
	svr.InitGlobalDS()
	svr.CollectSystemInformation()
	svr.InitPcapHdlrs()
	go svr.EventsListener()
}
