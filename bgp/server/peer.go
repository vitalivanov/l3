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

// peer.go
package server

import (
	_ "fmt"
	"l3/bgp/baseobjects"
	"l3/bgp/config"
	"l3/bgp/fsm"
	"l3/bgp/packet"
	bgppolicy "l3/bgp/policy"
	bgprib "l3/bgp/rib"
	"net"
	"runtime"
	"strconv"
	"sync/atomic"
	"utils/logging"
	"utils/patriciaDB"
	utilspolicy "utils/policy"
	"utils/policy/policyCommonDefs"
)

const (
	Reject int = iota
	Accept
)

type AdjRIBPolicyParams struct {
	CreateType int
	DeleteType int
	Route      *bgprib.AdjRIBRoute
	Peer       *Peer
	Accept     int
}

type Peer struct {
	server       *BGPServer
	logger       *logging.Writer
	locRib       *bgprib.LocRib
	NeighborConf *base.NeighborConf
	fsmManager   *fsm.FSMManager
	ifIdx        int32
	ribIn        map[uint32]map[string]*bgprib.AdjRIBRoute
	ribOut       map[uint32]map[string]*bgprib.AdjRIBRoute
}

func NewPeer(server *BGPServer, locRib *bgprib.LocRib, globalConf *config.GlobalConfig,
	peerGroup *config.PeerGroupConfig, peerConf config.NeighborConfig) *Peer {
	peer := Peer{
		server: server,
		logger: server.logger,
		locRib: locRib,
		ifIdx:  -1,
		ribIn:  make(map[uint32]map[string]*bgprib.AdjRIBRoute),
		ribOut: make(map[uint32]map[string]*bgprib.AdjRIBRoute),
	}

	peer.NeighborConf = base.NewNeighborConf(peer.logger, globalConf, peerGroup, peerConf)
	peer.fsmManager = fsm.NewFSMManager(peer.logger, peer.NeighborConf, server.BGPPktSrcCh,
		server.PeerFSMConnCh, server.ReachabilityCh)
	return &peer
}

func (p *Peer) UpdatePeerGroup(peerGroup *config.PeerGroupConfig) {
	p.NeighborConf.UpdatePeerGroup(peerGroup)
}

func (p *Peer) UpdateNeighborConf(nConf config.NeighborConfig, bgp *config.Bgp) {
	p.NeighborConf.UpdateNeighborConf(nConf, bgp)
}
func (p *Peer) initAdjRIBTables() {
	for protoFamily, ok := range p.NeighborConf.AfiSafiMap {
		if ok {
			p.ribIn[protoFamily] = make(map[string]*bgprib.AdjRIBRoute)
			p.ribOut[protoFamily] = make(map[string]*bgprib.AdjRIBRoute)
		}
	}
}

func (p *Peer) IsBfdStateUp() bool {
	up := true
	if p.NeighborConf.Neighbor.State.UseBfdState {
		if p.NeighborConf.RunningConf.BfdEnable &&
			p.NeighborConf.Neighbor.State.BfdNeighborState == "down" {
			p.logger.Infof("Neighbor's bfd state is down for %s", p.NeighborConf.Neighbor.NeighborAddress)
			up = false
		}
	}
	return up
}

func (p *Peer) GetActionType(adjRIBDir bgprib.AdjRIBDir) (int, bool) {
	switch adjRIBDir {
	case bgprib.AdjRIBDirIn:
		return policyCommonDefs.PolicyActionTypeRIBIn, true

	case bgprib.AdjRIBDirOut:
		return policyCommonDefs.PolicyActionTypeRIBOut, true
	}
	return -1, false
}

func (p *Peer) RemoveAdjRIBFilter(pe *bgppolicy.AdjRibPPolicyEngine, policyName string, adjRIBDir bgprib.AdjRIBDir) {
	p.logger.Debug("RemoveAdjRIBFilter")
	policyEngine := pe.GetPolicyEngine()
	policyDB := policyEngine.PolicyDB
	//neighborIP := p.NeighborConf.RunningConf.NeighborAddress.String()

	nodeGet := policyDB.Get(patriciaDB.Prefix(policyName))
	if nodeGet == nil {
		p.logger.Err("Policy ", policyName, " not created yet")
		return
	}
	node := nodeGet.(utilspolicy.Policy)
	actionType, ok := p.GetActionType(adjRIBDir)
	if !ok {
		p.logger.Err("Action type not found for Adj RIB direction", adjRIBDir)
		return
	}

	neighborIP := p.NeighborConf.RunningConf.NeighborAddress.String()
	conditionNameList := make([]string, 1)
	conditionNameList[0] = neighborIP

	policyAction := utilspolicy.PolicyAction{
		Name:       neighborIP,
		ActionType: actionType,
	}

	p.logger.Debug("Calling applypolicy with conditionNameList: ", conditionNameList)
	pe.UpdateUndoApplyPolicy(utilspolicy.ApplyPolicyInfo{node, policyAction, conditionNameList}, true)
}

func (p *Peer) AddAdjRIBFilter(pe *bgppolicy.AdjRibPPolicyEngine, policyName string, adjRIBDir bgprib.AdjRIBDir) {
	p.logger.Debug("AddAdjRIBFilter")
	policyEngine := pe.GetPolicyEngine()
	policyDB := policyEngine.PolicyDB
	nodeGet := policyDB.Get(patriciaDB.Prefix(policyName))
	if nodeGet == nil {
		p.logger.Err("Policy ", policyName, " not defined")
		return
	}
	node := nodeGet.(utilspolicy.Policy)

	actionType, ok := p.GetActionType(adjRIBDir)
	if !ok {
		p.logger.Err("Action type not found for Adj RIB direction", adjRIBDir)
		return
	}

	neighborIP := p.NeighborConf.RunningConf.NeighborAddress.String()
	cond := utilspolicy.PolicyConditionConfig{
		Name:                       neighborIP,
		ConditionType:              "MatchNeighbor",
		MatchNeighborConditionInfo: neighborIP,
	}

	_, err := pe.CreatePolicyCondition(cond)
	if err != nil {
		p.logger.Errf("Failed to create policy condition to match neighbor %s with error %s", neighborIP, err)
		return
	}

	conditionNameList := make([]string, 1)
	conditionNameList[0] = neighborIP

	policyAction := utilspolicy.PolicyAction{
		Name:       neighborIP,
		ActionType: actionType,
	}

	p.logger.Debug("Calling applypolicy with conditionNameList: ", conditionNameList)
	pe.UpdateApplyPolicy(utilspolicy.ApplyPolicyInfo{node, policyAction, conditionNameList}, true)
}
func (p *Peer) Init() {
	var fsmMgr *fsm.FSMManager
	if p.NeighborConf.RunningConf.AdjRIBInFilter != "" {
		p.AddAdjRIBFilter(p.server.ribInPE, p.NeighborConf.RunningConf.AdjRIBInFilter, bgprib.AdjRIBDirIn)
	}

	if p.NeighborConf.RunningConf.AdjRIBOutFilter != "" {
		p.AddAdjRIBFilter(p.server.ribOutPE, p.NeighborConf.RunningConf.AdjRIBOutFilter, bgprib.AdjRIBDirOut)
	}

	if p.fsmManager == nil {
		p.logger.Infof("Instantiating new FSM Manager for neighbor %s", p.NeighborConf.Neighbor.NeighborAddress)
		fsmMgr = fsm.NewFSMManager(p.logger, p.NeighborConf, p.server.BGPPktSrcCh,
			p.server.PeerFSMConnCh, p.server.ReachabilityCh)
	} else {
		fsmMgr = p.fsmManager
	}

	p.clearRibOut()
	go fsmMgr.Init()
	runtime.Gosched()

	p.fsmManager = fsmMgr
	p.ProcessBfd(true)
}

func (p *Peer) Cleanup() {
	if p.NeighborConf.RunningConf.AdjRIBInFilter != "" {
		p.RemoveAdjRIBFilter(p.server.ribInPE, p.NeighborConf.RunningConf.AdjRIBInFilter, bgprib.AdjRIBDirIn)
	}

	if p.NeighborConf.RunningConf.AdjRIBOutFilter != "" {
		p.RemoveAdjRIBFilter(p.server.ribOutPE, p.NeighborConf.RunningConf.AdjRIBOutFilter, bgprib.AdjRIBDirOut)
	}

	p.ProcessBfd(false)

	if p.fsmManager == nil {
		p.logger.Errf("Can't cleanup FSM, FSM Manager is not instantiated for neighbor %s",
			p.NeighborConf.Neighbor.NeighborAddress)
		return
	}

	fsmMgr := p.fsmManager
	p.fsmManager = nil
	fsmMgr.CloseCh <- true
}

func (p *Peer) StopFSM(msg string) {
	if p.fsmManager == nil {
		p.logger.Errf("Can't stop FSM, FSM Manager is not instantiated for neighbor %s",
			p.NeighborConf.Neighbor.NeighborAddress)
		return
	}

	p.fsmManager.StopFSMCh <- msg
}

func (p *Peer) MaxPrefixesExceeded() {
	if p.NeighborConf.RunningConf.MaxPrefixesDisconnect {
		p.Command(int(fsm.BGPEventAutoStop), fsm.BGPCmdReasonMaxPrefixExceeded)
	}
}

func (p *Peer) setIfIdx(ifIdx int32) {
	p.ifIdx = ifIdx
}

func (p *Peer) getIfIdx() int32 {
	return p.ifIdx
}

func (p *Peer) AcceptConn(conn *net.TCPConn) {
	if p.fsmManager == nil {
		p.logger.Errf("FSM Manager is not instantiated yet for neighbor %s",
			p.NeighborConf.Neighbor.NeighborAddress)
		(*conn).Close()
		return
	}
	p.fsmManager.AcceptCh <- conn
}

func (p *Peer) Command(command int, reason int) {
	if p.fsmManager == nil {
		p.logger.Errf("FSM Manager is not instantiated yet for neighbor %s",
			p.NeighborConf.Neighbor.NeighborAddress)
		return
	}
	p.fsmManager.CommandCh <- fsm.PeerFSMCommand{command, reason}
}

func (p *Peer) getAddPathsMaxTx() int {
	return int(p.NeighborConf.Neighbor.State.AddPathsMaxTx)
}

func (p *Peer) clearRibOut() {
	p.ribIn = nil
	p.ribOut = nil
	p.ribIn = make(map[uint32]map[string]*bgprib.AdjRIBRoute)
	p.ribOut = make(map[uint32]map[string]*bgprib.AdjRIBRoute)
	p.initAdjRIBTables()
}

func (p *Peer) ProcessBfd(add bool) {
	ipAddr := p.NeighborConf.Neighbor.NeighborAddress.String()
	sessionParam := p.NeighborConf.RunningConf.BfdSessionParam
	if add && p.NeighborConf.RunningConf.BfdEnable {
		p.logger.Info("Bfd enabled on", p.NeighborConf.Neighbor.NeighborAddress)
		ret, err := p.server.bfdMgr.CreateBfdSession(ipAddr, sessionParam)
		if !ret {
			p.logger.Info("BfdSessionConfig FAILED, ret:", ret, "err:", err)
		} else {
			p.logger.Info("Bfd session configured: ", ipAddr, " param: ", sessionParam)
			p.NeighborConf.Neighbor.State.BfdNeighborState = "up"
		}
	} else {
		if p.NeighborConf.Neighbor.State.BfdNeighborState != "" {
			p.logger.Info("Bfd disabled on", p.NeighborConf.Neighbor.NeighborAddress)
			ret, err := p.server.bfdMgr.DeleteBfdSession(ipAddr)
			if !ret {
				p.logger.Info("BfdSessionConfig FAILED, ret:", ret, "err:", err)
			} else {
				p.logger.Info("Bfd session removed for", p.NeighborConf.Neighbor.NeighborAddress)
				p.NeighborConf.Neighbor.State.BfdNeighborState = ""
			}
		}
	}

}

func (p *Peer) PeerConnEstablished(conn *net.Conn) {
	host, _, err := net.SplitHostPort((*conn).LocalAddr().String())
	if err != nil {
		p.logger.Errf("Neighbor %s: Can't find local address from the peer connection: %s",
			p.NeighborConf.Neighbor.NeighborAddress, (*conn).LocalAddr())
		return
	}
	p.NeighborConf.Neighbor.Transport.Config.LocalAddress = net.ParseIP(host)
	p.NeighborConf.PeerConnEstablished()
	p.clearRibOut()
	//p.Server.PeerConnEstCh <- p.Neighbor.NeighborAddress.String()
}

func (p *Peer) PeerConnBroken(fsmCleanup bool) {
	if p.NeighborConf.Neighbor.Transport.Config.LocalAddress != nil {
		p.NeighborConf.Neighbor.Transport.Config.LocalAddress = nil
		//p.Server.PeerConnBrokenCh <- p.Neighbor.NeighborAddress.String()
	}
	p.NeighborConf.PeerConnBroken()
	p.clearRibOut()
}

func (p *Peer) processWithdraws(protoFamily uint32, nlris *[]packet.NLRI) {
	var route *bgprib.AdjRIBRoute
	var ok bool
	total := len(*nlris)
	last := total - 1
	idx := 0
	for i := 0; i < total; i++ {
		nlri := (*nlris)[idx]
		if nlri == nil {
			continue
		}

		ip := nlri.GetPrefix().String()
		if route, ok = p.ribIn[protoFamily][ip]; !ok {
			p.logger.Errf("Neighbor %s: Withdraw Prefix %s not found in RIB-In",
				p.NeighborConf.Neighbor.NeighborAddress, ip)
			(*nlris)[idx] = (*nlris)[last]
			(*nlris)[last] = nil
			last--
			continue
		}

		if route.GetPath(nlri.GetPathId()) == nil {
			p.logger.Errf("Neighbor %s: Withdraw Prefix %s Path id %d not found in RIB-In",
				p.NeighborConf.Neighbor.NeighborAddress, ip, nlri.GetPathId())
			(*nlris)[idx] = (*nlris)[last]
			(*nlris)[last] = nil
			last--
			continue
		}

		idx++
		route.RemovePath(nlri.GetPathId())
		if route.DoesPathsExist() {
			delete(p.ribIn[protoFamily], ip)
		}
	}
	(*nlris) = (*nlris)[:idx]
}

func (p *Peer) checkRIBInFilter(nlri packet.NLRI, route *bgprib.AdjRIBRoute) bool {
	if p.NeighborConf.Neighbor.Config.AdjRIBInFilter == "" {
		p.logger.Debugf("Peer %s - RIB In filter is not set", p.NeighborConf.Neighbor.NeighborAddress)
		return true
	}

	if route != nil {
		peEntity := utilspolicy.PolicyEngineFilterEntityParams{
			DestNetIp:  route.NLRI.GetPrefix().String() + "/" + strconv.Itoa(int(route.NLRI.GetLength())),
			Neighbor:   p.NeighborConf.RunningConf.NeighborAddress.String(),
			CreatePath: true,
		}
		callbackInfo := &AdjRIBPolicyParams{
			CreateType: utilspolicy.Valid,
			DeleteType: utilspolicy.Invalid,
			Peer:       p,
			Route:      route,
		}
		p.server.ribInPE.PolicyEngine.PolicyEngineFilter(peEntity, policyCommonDefs.PolicyPath_Import, callbackInfo)
		p.logger.Infof("checkRIBInFilter - NLRI %s policylist %v hit %v after applying create policy, callbackInfo=%+v",
			nlri.GetPrefix().String(), route.PolicyList, route.PolicyHitCounter, callbackInfo)
		return callbackInfo.Accept == Accept
	}
	return false
}

func (p *Peer) processUpdates(protoFamily uint32, nlris *[]packet.NLRI, path *bgprib.Path) {
	var ok bool
	var route *bgprib.AdjRIBRoute
	total := len(*nlris)
	last := total - 1
	idx := 0
	for i := 0; i < total; i++ {
		nlri := (*nlris)[idx]
		if nlri == nil {
			continue
		}

		ip := nlri.GetPrefix().String()
		if route, ok = p.ribIn[protoFamily][ip]; !ok {
			route = bgprib.NewAdjRIBRoute(p.NeighborConf.Neighbor.NeighborAddress, protoFamily, nlri)
			p.ribIn[protoFamily][ip] = route
		}
		route.AddPath(nlri.GetPathId(), path)

		if len(route.PolicyList) != 0 {
			p.logger.Info("Peer", p.NeighborConf.RunningConf.NeighborAddress, "nlri", nlri.GetIPPrefix().String(),
				"is already filtered")
			(*nlris)[idx] = (*nlris)[last]
			last--
			continue
		}

		accept := p.checkRIBInFilter(nlri, route)
		if !accept {
			p.logger.Info("Peer", p.NeighborConf.RunningConf.NeighborAddress, "filter nlri",
				nlri.GetIPPrefix().String())
			(*nlris)[idx] = (*nlris)[last]
			last--
			continue
		}
		idx++
	}
	(*nlris) = (*nlris)[:idx]
}

func (p *Peer) ReceiveUpdate(pktInfo *packet.BGPPktSrc) (map[uint32]map[*bgprib.Path][]*bgprib.Destination,
	[]*bgprib.Destination, []*bgprib.Destination) {
	updated := make(map[uint32]map[*bgprib.Path][]*bgprib.Destination)
	withdrawn := make([]*bgprib.Destination, 0)
	updatedAddPaths := make([]*bgprib.Destination, 0)
	addedAllPrefixes := true

	atomic.AddUint32(&p.NeighborConf.Neighbor.State.Queues.Input, ^uint32(0))
	p.NeighborConf.Neighbor.State.Messages.Received.Update++

	updateMsg := pktInfo.Msg.Body.(*packet.BGPUpdate)
	if packet.HasASLoop(updateMsg.PathAttributes, p.NeighborConf.RunningConf.LocalAS) {
		p.logger.Infof("Neighbor %s: Recived Update message has AS loop", p.NeighborConf.Neighbor.NeighborAddress)
		return updated, withdrawn, updatedAddPaths
	}

	protoFamily := packet.GetProtocolFamily(packet.AfiIP, packet.SafiUnicast)
	mpReach, mpUnreach := packet.GetMPAttrs(updateMsg.PathAttributes)
	path := bgprib.NewPath(p.locRib, p.NeighborConf, updateMsg.PathAttributes, mpReach, bgprib.RouteTypeEGP)
	p.processWithdraws(protoFamily, &updateMsg.WithdrawnRoutes)
	p.processUpdates(protoFamily, &updateMsg.NLRI, path)

	if mpUnreach != nil {
		protoFamily = packet.GetProtocolFamily(mpUnreach.AFI, mpUnreach.SAFI)
		p.processWithdraws(protoFamily, &(mpUnreach.NLRI))
	}
	if mpReach != nil {
		protoFamily = packet.GetProtocolFamily(mpReach.AFI, mpReach.SAFI)
		p.processUpdates(protoFamily, &(mpReach.NLRI), path)
	}

	updated, withdrawn, updatedAddPaths, addedAllPrefixes = p.locRib.ProcessUpdate(p.NeighborConf, pktInfo,
		p.server.AddPathCount)
	if !addedAllPrefixes {
		p.MaxPrefixesExceeded()
	}

	return updated, withdrawn, updatedAddPaths
}

func (p *Peer) updatePathAttrs(bgpMsg *packet.BGPMessage, path *bgprib.Path) bool {
	if p.NeighborConf.Neighbor.Transport.Config.LocalAddress == nil {
		p.logger.Errf("Neighbor %s: Can't send Update message, FSM is not in Established state",
			p.NeighborConf.Neighbor.NeighborAddress)
		return false
	}

	if bgpMsg == nil || bgpMsg.Body.(*packet.BGPUpdate).PathAttributes == nil {
		p.logger.Errf("Neighbor %s: Path attrs not found in BGP Update message",
			p.NeighborConf.Neighbor.NeighborAddress)
		return false
	}

	updateMsg := bgpMsg.Body.(*packet.BGPUpdate)
	if len(updateMsg.NLRI) == 0 && !packet.HasMPReachNLRI(updateMsg.PathAttributes) {
		return true
	}

	if p.NeighborConf.ASSize == 2 {
		packet.Convert4ByteTo2ByteASPath(bgpMsg)
	}

	removeRRPathAttrs := true
	if p.NeighborConf.IsInternal() {
		if path.NeighborConf != nil && (path.NeighborConf.IsRouteReflectorClient() ||
			p.NeighborConf.IsRouteReflectorClient()) {
			removeRRPathAttrs = false
			packet.AddOriginatorId(bgpMsg, path.NeighborConf.BGPId)
			packet.AddClusterId(bgpMsg, path.NeighborConf.RunningConf.RouteReflectorClusterId)
		} else {
			packet.SetLocalPref(bgpMsg, path.GetPreference())
		}
	} else {
		// Do change these path attrs for local routes
		if path.NeighborConf != nil {
			packet.RemoveMultiExitDisc(bgpMsg)
		}
		packet.PrependAS(bgpMsg, p.NeighborConf.RunningConf.LocalAS, p.NeighborConf.ASSize)
		if updateMsg.NLRI != nil && len(updateMsg.NLRI) > 0 {
			packet.SetNextHop(bgpMsg, p.NeighborConf.Neighbor.Transport.Config.LocalAddress)
		} else if len(updateMsg.PathAttributes) > 0 {
			packet.RemoveNextHop(&(updateMsg.PathAttributes))
		}
		packet.RemoveLocalPref(bgpMsg)
	}

	if removeRRPathAttrs {
		packet.RemoveOriginatorId(bgpMsg)
		packet.RemoveClusterList(bgpMsg)
	}

	return true
}

func (p *Peer) sendUpdateMsg(msg *packet.BGPMessage, path *bgprib.Path) {
	if p.fsmManager == nil {
		p.logger.Errf("Can't send update, FSM Manager is not instantiated for neighbor %s",
			p.NeighborConf.Neighbor.NeighborAddress)
		return
	}

	if path != nil && path.NeighborConf != nil {
		if path.NeighborConf.IsInternal() {

			if p.NeighborConf.IsInternal() && !path.NeighborConf.IsRouteReflectorClient() &&
				!p.NeighborConf.IsRouteReflectorClient() {
				return
			}
		}

		// Don't send the update to the peer that sent the update.
		if p.NeighborConf.RunningConf.NeighborAddress.String() ==
			path.NeighborConf.RunningConf.NeighborAddress.String() {
			return
		}
	}

	if p.updatePathAttrs(msg, path) {
		atomic.AddUint32(&p.NeighborConf.Neighbor.State.Queues.Output, 1)
		p.fsmManager.SendUpdateMsg(msg)
	}

}

func (p *Peer) isAdvertisable(path *bgprib.Path) bool {
	if path != nil && path.NeighborConf != nil {
		if path.NeighborConf.IsInternal() {

			if p.NeighborConf.IsInternal() && !path.NeighborConf.IsRouteReflectorClient() &&
				!p.NeighborConf.IsRouteReflectorClient() {
				return false
			}
		}

		// Don't send the update to the peer that sent the update.
		if p.NeighborConf.RunningConf.NeighborAddress.String() ==
			path.NeighborConf.RunningConf.NeighborAddress.String() {
			return false
		}
	}

	return true
}

func (p *Peer) calculateAddPathsAdvertisements(dest *bgprib.Destination, path *bgprib.Path,
	newUpdated map[*bgprib.Path]map[uint32][]packet.NLRI, withdrawList map[uint32][]packet.NLRI, addPathsTx int) (
	map[*bgprib.Path]map[uint32][]packet.NLRI, map[uint32][]packet.NLRI) {
	pathIdMap := make(map[uint32]*bgprib.Path)
	ip := dest.NLRI.GetPrefix().String()
	protoFamily := dest.GetProtocolFamily()

	if _, ok := p.ribOut[protoFamily][ip]; !ok {
		p.logger.Info("Neighbor", p.NeighborConf.Neighbor.NeighborAddress,
			"calculateAddPathsAdvertisements - processing updates, dest", ip, "not found in rib out")
		p.ribOut[protoFamily][ip] = bgprib.NewAdjRIBRoute(p.NeighborConf.Neighbor.NeighborAddress, protoFamily,
			dest.NLRI)
	}

	pathAdded := false
	protoFamilyAdded := false
	if _, ok := newUpdated[path]; ok {
		pathAdded = true
		if _, ok := newUpdated[path][protoFamily]; ok {
			protoFamilyAdded = true
		}
	}

	if p.isAdvertisable(path) {
		route := dest.LocRibPathRoute
		if path != nil { // Loc-RIB path changed
			if !pathAdded {
				newUpdated[path] = make(map[uint32][]packet.NLRI)
				pathAdded = true
			}
			if !protoFamilyAdded {
				newUpdated[path][protoFamily] = make([]packet.NLRI, 0)
				protoFamilyAdded = true
			}
			nlri := packet.NewExtNLRI(route.OutPathId, dest.NLRI.GetIPPrefix())
			newUpdated[path][protoFamily] = append(newUpdated[path][protoFamily], nlri)
		} else {
			path = dest.LocRibPath
		}
		pathIdMap[route.OutPathId] = path
	}

	for i := 0; i < len(dest.AddPaths) && len(pathIdMap) < (addPathsTx-1); i++ {
		route := dest.GetPathRoute(dest.AddPaths[i])
		if route != nil && p.isAdvertisable(dest.AddPaths[i]) {
			pathIdMap[route.OutPathId] = dest.AddPaths[i]
		}
	}

	ribOutRoute := p.ribOut[protoFamily][ip]
	for ribOutPathId, ribOutPath := range ribOutRoute.GetPathMap() {
		if path, ok := pathIdMap[ribOutPathId]; !ok {
			nlri := packet.NewExtNLRI(ribOutPathId, dest.NLRI.GetIPPrefix())
			withdrawList[protoFamily] = append(withdrawList[protoFamily], nlri)
			ribOutRoute.RemovePath(ribOutPathId)
		} else if ribOutPath == path {
			delete(pathIdMap, ribOutPathId)
		} else if ribOutPath != path {
			if !pathAdded {
				newUpdated[path] = make(map[uint32][]packet.NLRI)
				pathAdded = true
			}
			if !protoFamilyAdded {
				newUpdated[path][protoFamily] = make([]packet.NLRI, 0)
				protoFamilyAdded = true
			}
			nlri := packet.NewExtNLRI(ribOutPathId, dest.NLRI.GetIPPrefix())
			newUpdated[path][protoFamily] = append(newUpdated[path][protoFamily], nlri)
			ribOutRoute.AddPath(ribOutPathId, path)
			delete(pathIdMap, ribOutPathId)
		}
	}

	for pathId, path := range pathIdMap {
		if !pathAdded {
			newUpdated[path] = make(map[uint32][]packet.NLRI)
			pathAdded = true
		}
		if !protoFamilyAdded {
			newUpdated[path][protoFamily] = make([]packet.NLRI, 0)
			protoFamilyAdded = true
		}
		nlri := packet.NewExtNLRI(pathId, dest.NLRI.GetIPPrefix())
		newUpdated[path][protoFamily] = append(newUpdated[path][protoFamily], nlri)
		ribOutRoute.AddPath(pathId, path)
		delete(pathIdMap, pathId)
	}

	return newUpdated, withdrawList
}

func (p *Peer) SendUpdate(updated map[uint32]map[*bgprib.Path][]*bgprib.Destination, withdrawn,
	updatedAddPaths []*bgprib.Destination) {
	p.logger.Infof("Neighbor %s: Send update message valid routes:%v, withdraw routes:%v",
		p.NeighborConf.Neighbor.NeighborAddress, updated, withdrawn)
	if p.NeighborConf.Neighbor.Transport.Config.LocalAddress == nil {
		p.logger.Errf("Neighbor %s: Can't send Update message, FSM is not in Established state",
			p.NeighborConf.Neighbor.NeighborAddress)
		return
	}

	addPathsTx := p.getAddPathsMaxTx()
	withdrawList := make(map[uint32][]packet.NLRI)
	newUpdated := make(map[*bgprib.Path]map[uint32][]packet.NLRI)
	if len(withdrawn) > 0 {
		for _, dest := range withdrawn {
			if dest != nil {
				protoFamily := dest.GetProtocolFamily()
				if _, ok := withdrawList[protoFamily]; !ok {
					withdrawList[protoFamily] = make([]packet.NLRI, 0)
				}
				ip := dest.NLRI.GetPrefix().String()
				if p.ribOut[protoFamily] != nil && p.ribOut[protoFamily][ip] != nil &&
					p.NeighborConf.AfiSafiMap[protoFamily] {
					route, ok := p.ribOut[protoFamily][ip]
					if !ok {
						p.logger.Errf("Neighbor %s: processing withdraws, dest %s not found in rib out",
							p.NeighborConf.Neighbor.NeighborAddress, ip)
						continue
					}
					if addPathsTx > 0 {
						for pathId, _ := range route.GetPathMap() {
							nlri := packet.NewExtNLRI(pathId, dest.NLRI.GetIPPrefix())
							withdrawList[protoFamily] = append(withdrawList[protoFamily], nlri)
						}
						delete(p.ribOut[protoFamily], ip)
					} else {
						withdrawList[protoFamily] = append(withdrawList[protoFamily], dest.NLRI)
						delete(p.ribOut[protoFamily], ip)
					}
					route.RemoveAllPaths()
				}
			}
		}
	}

	for protoFamily, pathDestMap := range updated {
		if !p.NeighborConf.AfiSafiMap[protoFamily] {
			continue
		}
		if _, ok := p.ribOut[protoFamily]; !ok {
			p.ribOut[protoFamily] = make(map[string]*bgprib.AdjRIBRoute)
		}
		if _, ok := withdrawList[protoFamily]; !ok {
			withdrawList[protoFamily] = make([]packet.NLRI, 0)
		}
		for path, destinations := range pathDestMap {
			for _, dest := range destinations {
				if dest == nil {
					continue
				}
				ip := dest.NLRI.GetPrefix().String()
				if addPathsTx > 0 {
					newUpdated, withdrawList = p.calculateAddPathsAdvertisements(dest, path, newUpdated,
						withdrawList, addPathsTx)
				} else {
					if !p.isAdvertisable(path) {
						if p.ribOut[protoFamily][ip] != nil {
							withdrawList[protoFamily] = append(withdrawList[protoFamily], dest.NLRI)
							p.ribOut[protoFamily][ip].RemoveAllPaths()
							delete(p.ribOut[protoFamily], ip)
						}
					} else {
						route := dest.LocRibPathRoute
						pathId := route.OutPathId
						if _, ok := p.ribOut[protoFamily][ip]; !ok {
							p.ribOut[protoFamily][ip] = bgprib.NewAdjRIBRoute(p.NeighborConf.Neighbor.NeighborAddress,
								protoFamily, dest.NLRI)
						}
						ribOutRoute := p.ribOut[protoFamily][ip]
						for ribPathId, _ := range ribOutRoute.GetPathMap() {
							if pathId != ribPathId {
								ribOutRoute.RemovePath(ribPathId)
							}
						}
						if ribOutPath := ribOutRoute.GetPath(pathId); ribOutPath == nil || ribOutPath != path {
							if _, ok := newUpdated[path]; !ok {
								newUpdated[path] = make(map[uint32][]packet.NLRI)
							}
							if _, ok := newUpdated[path][protoFamily]; !ok {
								newUpdated[path][protoFamily] = make([]packet.NLRI, 0)
							}
							newUpdated[path][protoFamily] = append(newUpdated[path][protoFamily],
								dest.NLRI.GetIPPrefix())
						}
						ribOutRoute.AddPath(pathId, path)
					}
				}
			}
		}
	}

	if addPathsTx > 0 {
		for _, dest := range updatedAddPaths {
			newUpdated, withdrawList = p.calculateAddPathsAdvertisements(dest, nil, newUpdated, withdrawList,
				addPathsTx)
		}
	}

	if withdrawList != nil {
		p.logger.Infof("Neighbor %s: Send update message withdraw routes:%+v",
			p.NeighborConf.Neighbor.NeighborAddress, withdrawList)
		var updateMsg *packet.BGPMessage
		var ipv4List []packet.NLRI
		protoFamily := packet.GetProtocolFamily(packet.AfiIP, packet.SafiUnicast)
		if nlriList, ok := withdrawList[protoFamily]; ok && len(nlriList) > 0 {
			ipv4List = nlriList
			delete(withdrawList, protoFamily)
		}
		for protoFamily, nlriList := range withdrawList {
			if len(nlriList) > 0 {
				mpUnreachNLRI := packet.ConstructMPUnreachNLRI(protoFamily, nlriList)
				pathAtts := make([]packet.BGPPathAttr, 0)
				pathAtts = append(pathAtts, mpUnreachNLRI)
				updateMsg = packet.NewBGPUpdateMessage(ipv4List, pathAtts, nil)
				p.sendUpdateMsg(updateMsg.Clone(), nil)
				ipv4List = nil
			}
		}
		if ipv4List != nil {
			updateMsg = packet.NewBGPUpdateMessage(ipv4List, nil, nil)
			p.sendUpdateMsg(updateMsg.Clone(), nil)
		}
	}

	localAddress := p.NeighborConf.Neighbor.Transport.Config.LocalAddress
	p.logger.Infof("Neighbor %s: new updated routes:%+v", p.NeighborConf.Neighbor.NeighborAddress, newUpdated)
	for path, pfNLRIMap := range newUpdated {
		var updateMsg *packet.BGPMessage
		var ipv4List []packet.NLRI
		protoFamily := packet.GetProtocolFamily(packet.AfiIP, packet.SafiUnicast)
		if nlriList, ok := pfNLRIMap[protoFamily]; ok {
			if len(nlriList) > 0 {
				ipv4List = nlriList
				delete(pfNLRIMap, protoFamily)
			}
		}

		for protoFamily, nlriList := range pfNLRIMap {
			if len(nlriList) > 0 {
				mpReachNLRI := packet.ConstructIPv6MPReachNLRI(protoFamily, localAddress, nil, nlriList)
				pa := packet.CopyPathAttrs(path.PathAttrs)
				pa = packet.AddMPReachNLRIToPathAttrs(pa, mpReachNLRI)
				updateMsg = packet.NewBGPUpdateMessage(nil, pa, ipv4List)
				p.logger.Infof("Neighbor %s: Send update message valid routes:%+v, path attrs:%+v",
					p.NeighborConf.Neighbor.NeighborAddress, nlriList, path.PathAttrs)
				p.sendUpdateMsg(updateMsg.Clone(), path)
				ipv4List = nil
			}
		}

		if ipv4List != nil {
			p.logger.Infof("Neighbor %s: Send update message valid routes:%+v, path attrs:%+v",
				p.NeighborConf.Neighbor.NeighborAddress, ipv4List, path.PathAttrs)
			updateMsg := packet.NewBGPUpdateMessage(make([]packet.NLRI, 0), path.PathAttrs, ipv4List)
			p.sendUpdateMsg(updateMsg.Clone(), path)
		}
	}
}
