package snapclient

import (
	vxlan "l3/tunnel/vxlan/protocol"
	"utils/logging"
)

// setup local refs to server info
var logger *logging.Writer
var serverchannels *vxlan.VxLanConfigChannels
var client VXLANSnapClient

func init() {
	logger = vxlan.GetLogger()
	serverchannels = vxlan.GetConfigChannels()
	PortVlanDb = make(map[uint16][]*portVlanValue, 0)

}
