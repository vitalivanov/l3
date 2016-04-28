// base.go
package snapclient

import (
	nanomsg "github.com/op/go-nanomsg"
	vxlan "l3/tunnel/vxlan/protocol"
)

// Base Snaproute Interface
type VXLANSnapClient struct {
	vxlan.BaseClientIntf
	ribdSubSocket       *nanomsg.SubSocket
	ribdSubSocketCh     chan []byte
	ribdSubSocketErrCh  chan error
	asicdSubSocket      *nanomsg.SubSocket
	asicdSubSocketCh    chan []byte
	asicdSubSocketErrCh chan error
}

func NewVXLANSnapClient() VXLANSnapClient {
	return VXLANSnapClient{}
}
