// rib.go
package server

import (
	"fmt"
	"l3/bgp/packet"
	"log/syslog"
)

type AdjRib struct {
	server *BGPServer
	logger *syslog.Writer
	destPathMap map[string]*Destination
}

func NewAdjRib(server *BGPServer) *AdjRib {
	rib := &AdjRib{
		server: server,
		logger: server.logger,
		destPathMap: make(map[string]*Destination),
	}

	return rib
}

func isIpInList(ipPrefix []packet.IPPrefix, ip packet.IPPrefix) bool {
	for _, prefix := range ipPrefix {
		if prefix.Prefix.Equal(ip.Prefix) {
			return true
		}
	}
	return false
}

func (adjRib *AdjRib) getDest(nlri packet.IPPrefix, createIfNotExist bool) (*Destination, bool) {
	dest, ok := adjRib.destPathMap[nlri.Prefix.String()]
	if !ok && createIfNotExist {
		dest = NewDestination(adjRib.server, nlri)
		adjRib.destPathMap[nlri.Prefix.String()] = dest
		ok = true
	}

	return dest, ok
}

func (adjRib *AdjRib) ProcessUpdate(peer *Peer, pktInfo *packet.BGPPktSrc) {
	adjRib.logger.Info(fmt.Sprintln("AdjRib:ProcessUpdate - start"))
	body := pktInfo.Msg.Body.(*packet.BGPUpdate)

	// process withdrawn routes
	for _, nlri := range body.WithdrawnRoutes {
		if !isIpInList(body.NLRI, nlri){
			adjRib.logger.Info(fmt.Sprintln("Processing withdraw destination", nlri.Prefix.String()))
			dest, ok := adjRib.getDest(nlri, false)
			if !ok {
				adjRib.logger.Warning(fmt.Sprintln("Can't process withdraw field. Destination does not exist, Dest:", nlri.Prefix.String()))
			}
			dest.RemovePath(pktInfo.Src)
			dest.SelectRouteForLocRib()
		} else {
			adjRib.logger.Info(fmt.Sprintln("Can't withdraw destination", nlri.Prefix.String(),
				"Destination is part of NLRI in the UDPATE"))
		}
	}

	for _, nlri := range body.NLRI {
		dest, _ := adjRib.getDest(nlri, true)
		dest.AddOrUpdatePath(peer, pktInfo.Src, body.PathAttributes)
		dest.SelectRouteForLocRib()
	}
}
