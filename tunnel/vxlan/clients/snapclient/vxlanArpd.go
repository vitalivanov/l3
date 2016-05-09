// vxlanArpd.go
package snapclient

import (
	"arpd"
	"fmt"
	vxlan "l3/tunnel/vxlan/protocol"
	"net"
)

type ArpdClient struct {
	VXLANClientBase
	ClientHdl *arpd.ARPDServicesClient
}

var arpdclnt ArpdClient

func (intf VXLANSnapClient) ResolveNextHopMac(nexthopip net.IP, macchan chan<- vxlan.MachineEvent) {
	if arpdclnt.ClientHdl != nil {
		arpentrystate, err := arpdclnt.ClientHdl.GetArpEntryState(nexthopip.String())
		logger.Info(fmt.Sprintln("calling GetArpEntryState", arpentrystate, err))
		if err == nil {
			nexthopmac, _ := net.ParseMAC(arpentrystate.MacAddr)
			event := vxlan.MachineEvent{
				E:    vxlan.VxlanVtepEventNextHopInfoNextHopInfoMacResolved,
				Src:  vxlan.VXLANSnapClientStr,
				Data: nexthopmac,
			}
			macchan <- event
		}
	}
}
