// server.go
package vxlan

import (
	"fmt"
	nanomsg "github.com/op/go-nanomsg"
	"net"
	"utils/logging"
)

var SwitchMac [6]uint8
var NetSwitchMac net.HardwareAddr
var logger *logging.Writer

type VXLANServer struct {
	Configchans        *VxLanConfigChannels
	Paramspath         string // location of params path
	ribdSubSocket      *nanomsg.SubSocket
	ribdSubSocketCh    chan []byte
	ribdSubSocketErrCh chan error
}

type cfgFileJson struct {
	SwitchMac        string            `json:"SwitchMac"`
	PluginList       []string          `json:"PluginList"`
	IfNameMap        map[string]string `json:"IfNameMap"`
	IfNamePrefix     map[string]string `json:"IfNamePrefix"`
	SysRsvdVlanRange string            `json:"SysRsvdVlanRange"`
}

func SetLogger(l *logging.Writer) {
	logger = l
}

func NewVXLANServer(l *logging.Writer, paramspath string) *VXLANServer {

	SetLogger(l)

	logger.Info(fmt.Sprintf("Params path: %s", paramspath))
	server := &VXLANServer{
		Paramspath: paramspath,
	}

	// save off the switch mac for use by the VTEPs
	//server.SaveVtepSrcMacSrcIp()

	// connect to the various servers
	ConnectToClients(paramspath + "clients.json")

	server.CreateRIBdSubscriber()
	// listen for config messages from server
	server.ConfigListener()

	return server
}

func (s *VXLANServer) HandleNextHopChange(nexthopip string, reachable bool) {
	// TOOD do some work to find all VTEP's and deprovision the entries
}
