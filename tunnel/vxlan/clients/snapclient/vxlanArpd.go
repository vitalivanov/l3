// vxlanArpd.go
package snapclient

import (
	"arpd"
	"fmt"
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
		logger.Info(fmt.Sprintln("calling GetArpEntryState", arpentrystate, err))
		if err == nil {
			nexthopmac, _ := net.ParseMAC(arpentrystate.MacAddr)
			macchan <- nexthopmac
		}
	}
}
