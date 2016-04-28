// vxlanArpd.go
package snapclient

import (
	"arpd"
	"net"
)

type ArpdClient struct {
	VXLANClientBase
	ClientHdl *arpd.ARPDServicesClient
}

var arpdclnt ArpdClient

func (intf VXLANSnapClient) ResolveNextHopMac(nexthopip net.IP, macchan chan<- net.HardwareAddr) {
	if arpdclnt.ClientHdl != nil {
		arpentrystate, err := arpdclnt.ClientHdl.GetArpEntryState(nexthopip.String())
		if err == nil {
			nexthopip, _ := net.ParseMAC(arpentrystate.MacAddr)
			macchan <- nexthopip
		}
	}
}
