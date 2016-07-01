
//
//Copyright [2016] [SnapRoute Inc]
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//       Unless required by applicable law or agreed to in writing, software
//       distributed under the License is distributed on an "AS IS" BASIS,
//       WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//       See the License for the specific language governing permissions and
//       limitations under the License.
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
	"infra/sysd/sysdCommonDefs"
	"l3/ospf/config"
	"log/syslog"
	"net"
	"time"
	"utils/logging"
)

const (
	SUCCESS = 0
	FAIL    = 1
)

var ospfHdrMd OspfHdrMetadata
var ipHdrMd IpHdrMetadata
var key IntfConfKey
var srcMAC net.HardwareAddr
var ipIntfProp IPIntfProperty
var ifType int
var nbrConf OspfNeighborEntry
var nbrKey NeighborConfKey
var intConf IntfConf
var dstMAC net.HardwareAddr
var ospf *OSPFServer

/* Intf FSM */
var msg NbrStateChangeMsg
var msgNbrFull NbrFullStateMsg
var intf IntfConf

/* Nbr FSM */
var ospfNbrEntry OspfNeighborEntry
var nbrConfMsg ospfNeighborConfMsg

func OSPFNewLogger(name string, tag string, listenToConfig bool) (*logging.Writer, error) {
	var err error
	srLogger := new(logging.Writer)
	srLogger.MyComponentName = name

	srLogger.SysLogger, err = syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, tag)
	if err != nil {
		fmt.Println("Failed to initialize syslog - ", err)
		return srLogger, err
	}

	srLogger.GlobalLogging = true
	srLogger.MyLogLevel = sysdCommonDefs.INFO
	return srLogger, err
}

func initAttr() {
	ospf.initOspfGlobalConfDefault()
	ifType = int(config.Broadcast)
	ospfHdrMd = OspfHdrMetadata{
		pktType:  HelloType,
		pktlen:   OSPF_HELLO_MIN_SIZE,
		backbone: false,
		routerId: []byte{10, 1, 1, 10},
		areaId:   101010,
	}

	ipHdrMd = IpHdrMetadata{
		srcIP:     []byte{10, 1, 1, 2},
		dstIP:     []byte{10, 1, 1, 2},
		dstIPType: Normal,
	}

	key = IntfConfKey{
		IPAddr:  config.IpAddress(net.IP{10, 1, 1, 2}),
		IntfIdx: config.InterfaceIndexOrZero(2),
	}

	srcMAC = net.HardwareAddr{0x01, 0x00, 0x50, 0x00, 0x00, 0x07}
	dstMAC = net.HardwareAddr{0x24, 00, 0x50, 0x00, 0x00, 0x05}
	ipIntfProp = IPIntfProperty{
		IfName:  "fpPort1",
		IpAddr:  net.IP{10, 1, 1, 1},
		MacAddr: srcMAC,
		NetMask: []byte{10, 1, 0, 0},
		Mtu:     8124,
		Cost:    10,
	}
	nbrConf = OspfNeighborEntry{
		OspfNbrRtrId:   20,
		OspfNbrIPAddr:  net.IP{10, 1, 1, 2},
		OspfRtrPrio:    17,
		intfConfKey:    key,
		OspfNbrOptions: 0,
		OspfNbrState:   config.NbrInit,
		isStateUpdate:  false,
		isDRBDR:        true,
		ospfNbrSeqNum:  1223,
	}

	nbrKey = NeighborConfKey{
		IPAddr:  config.IpAddress(net.IP{10, 1, 1, 2}),
		IntfIdx: config.InterfaceIndexOrZero(2),
	}

	msg = NbrStateChangeMsg{
		nbrKey: nbrKey,
	}

	msgNbrFull = NbrFullStateMsg{
		FullState: true,
		NbrRtrId:  10,
		nbrKey:    nbrKey,
	}

	intf = IntfConf{
		IfAreaId:          []byte{0, 0, 0, 1},
		IfType:            config.Broadcast,
		IfAdminStat:       config.Enabled,
		IfRtrPriority:     uint8(2),
		IfTransitDelay:    config.UpToMaxAge(3600),
		IfRetransInterval: config.UpToMaxAge(3600),
		IfHelloInterval:   uint16(10),
		IfRtrDeadInterval: uint32(40),
		IfPollInterval:    config.PositiveInteger(50),
		IfDemand:          false,

		/* IntefaceState: Start */
		IfDRIp:     []byte{10, 1, 1, 2},
		IfBDRIp:    []byte{10, 1, 1, 10},
		IfFSMState: config.Down,
		IfDRtrId:   uint32(10),
		IfBDRtrId:  uint32(20),
		/* IntefaceState: End */
		IfName:    "fpPort1",
		IfIpAddr:  net.IP{10, 1, 1, 2},
		IfMacAddr: net.HardwareAddr{0x01, 0x00, 0x50, 0x00, 0x00, 0x07},
		IfNetmask: []byte{10, 0, 0, 0},
		IfMtu:     8124,
	}

	ospfNbrEntry = OspfNeighborEntry{
		OspfNbrRtrId:           20,
		OspfNbrIPAddr:          net.IP{10, 1, 1, 2},
		OspfRtrPrio:            2,
		intfConfKey:            key,
		OspfNbrOptions:         0,
		OspfNbrState:           config.NbrInit,
		isStateUpdate:          true,
		OspfNbrInactivityTimer: time.Now(),
		OspfNbrDeadTimer:       40,
		ospfNbrSeqNum:          2001,
		isSeqNumUpdate:         true,
		isMaster:               true,
		isMasterUpdate:         true,
		ospfNbrLsaIndex:        0,
	}

	nbrConfMsg = ospfNeighborConfMsg{
		ospfNbrConfKey: nbrKey,
		ospfNbrEntry:   ospfNbrEntry,
		nbrMsgType:     NBRADD,
	}

}

func startDummyChannels(server *OSPFServer) {

	for {
		select {
		case data := <-server.neighborDBDEventCh:
			fmt.Println("Receieved data from neighbor DBD : ", data)

		case data := <-server.NetworkDRChangeCh:
			fmt.Println("Received data from NetworkDRChangeCh ", data)
		}
	}

}

func getServerObject() *OSPFServer {
	logger, err := OSPFNewLogger("ospfd", "OSPFTEST", true)
	if err != nil {
		fmt.Println("ospftest: creating logger failed")
	}
	ospfServer := NewOSPFServer(logger)
	if ospfServer == nil {
		fmt.Sprintln("ospf server object is null ")
	}
	ospf = ospfServer
	return ospfServer
}
