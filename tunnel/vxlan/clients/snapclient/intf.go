// base.go
package snapclient

import (
	nanomsg "github.com/op/go-nanomsg"
)

// Base Snaproute Interface
type VXLANSnapClient struct {
	ribdSubSocket       *nanomsg.SubSocket
	ribdSubSocketCh     chan []byte
	ribdSubSocketErrCh  chan error
	asicdSubSocket      *nanomsg.SubSocket
	asicdSubSocketCh    chan []byte
	asicdSubSocketErrCh chan error
}

func NewVXLANSnapClient() VXLANSnapClient {
	return &VXLANSnapClient{}
}
