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
//  _______  __       __________   ___      _______.____    __    ____  __  .___________.  ______  __    __
// |   ____||  |     |   ____\  \ /  /     /       |\   \  /  \  /   / |  | |           | /      ||  |  |  |
// |  |__   |  |     |  |__   \  V  /     |   (----` \   \/    \/   /  |  | `---|  |----`|  ,----'|  |__|  |
// |   __|  |  |     |   __|   >   <       \   \      \            /   |  |     |  |     |  |     |   __   |
// |  |     |  `----.|  |____ /  .  \  .----)   |      \    /\    /    |  |     |  |     |  `----.|  |  |  |
// |__|     |_______||_______/__/ \__\ |_______/        \__/  \__/     |__|     |__|      \______||__|  |__|
//

// server.go
package server

import (
	"errors"
	"fmt"
	"l3/bgp/config"
	"l3/bgp/fsm"
	"l3/bgp/packet"
	bgppolicy "l3/bgp/policy"
	bgprib "l3/bgp/rib"
	"l3/bgp/utils"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"utils/dbutils"
	"utils/eventUtils"
	"utils/logging"
	"utils/netUtils"
	"utils/patriciaDB"
	utilspolicy "utils/policy"
	"utils/policy/policyCommonDefs"
	"utils/statedbclient"
)

type GlobalUpdate struct {
	OldConfig config.GlobalConfig
	NewConfig config.GlobalConfig
	AttrSet   []bool
}

type PeerUpdate struct {
	OldPeer config.NeighborConfig
	NewPeer config.NeighborConfig
	AttrSet []bool
}

type PeerGroupUpdate struct {
	OldGroup config.PeerGroupConfig
	NewGroup config.PeerGroupConfig
	AttrSet  []bool
}

type AggUpdate struct {
	OldAgg  config.BGPAggregate
	NewAgg  config.BGPAggregate
	AttrSet []bool
}

type PolicyParams struct {
	CreateType      int
	DeleteType      int
	route           *bgprib.Route
	dest            *bgprib.Destination
	updated         *(map[uint32]map[*bgprib.Path][]*bgprib.Destination)
	withdrawn       *([]*bgprib.Destination)
	updatedAddPaths *([]*bgprib.Destination)
}

type BGPServer struct {
	logger           *logging.Writer
	policyManager    *bgppolicy.BGPPolicyManager
	locRibPE         *bgppolicy.LocRibPolicyEngine
	ribInPE          *bgppolicy.AdjRibPPolicyEngine
	ribOutPE         *bgppolicy.AdjRibPPolicyEngine
	listener         *net.TCPListener
	ifaceMgr         *utils.InterfaceMgr
	BgpConfig        config.Bgp
	GlobalConfigCh   chan GlobalUpdate
	AddPeerCh        chan PeerUpdate
	RemPeerCh        chan string
	AddPeerGroupCh   chan PeerGroupUpdate
	RemPeerGroupCh   chan string
	AddAggCh         chan AggUpdate
	RemAggCh         chan string
	PeerFSMConnCh    chan fsm.PeerFSMConn
	PeerConnEstCh    chan string
	PeerConnBrokenCh chan string
	PeerCommandCh    chan config.PeerCommand
	ReachabilityCh   chan config.ReachabilityInfo
	BGPPktSrcCh      chan *packet.BGPPktSrc
	BfdCh            chan config.BfdInfo
	IntfCh           chan config.IntfStateInfo
	RoutesCh         chan *config.RouteCh
	acceptCh         chan *net.TCPConn
	GlobalCfgDone    bool

	NeighborMutex  sync.RWMutex
	PeerMap        map[string]*Peer
	Neighbors      []*Peer
	LocRib         *bgprib.LocRib
	ConnRoutesPath *bgprib.Path
	IfacePeerMap   map[int32][]string
	ifaceIP        net.IP
	actionFuncMap  map[int]bgppolicy.PolicyActionFunc
	AddPathCount   int
	// all managers
	IntfMgr    config.IntfStateMgrIntf
	routeMgr   config.RouteMgrIntf
	bfdMgr     config.BfdMgrIntf
	stateDBMgr statedbclient.StateDBClient
	eventDbHdl *dbutils.DBUtil
}

func NewBGPServer(logger *logging.Writer, policyManager *bgppolicy.BGPPolicyManager, iMgr config.IntfStateMgrIntf,
	rMgr config.RouteMgrIntf, bMgr config.BfdMgrIntf, sDBMgr statedbclient.StateDBClient) *BGPServer {
	bgpServer := &BGPServer{}
	bgpServer.logger = logger
	bgpServer.policyManager = policyManager
	bgpServer.ifaceMgr = utils.NewInterfaceMgr(logger)
	bgpServer.BgpConfig = config.Bgp{}
	bgpServer.GlobalCfgDone = false
	bgpServer.GlobalConfigCh = make(chan GlobalUpdate)
	bgpServer.AddPeerCh = make(chan PeerUpdate)
	bgpServer.RemPeerCh = make(chan string)
	bgpServer.AddPeerGroupCh = make(chan PeerGroupUpdate)
	bgpServer.RemPeerGroupCh = make(chan string)
	bgpServer.AddAggCh = make(chan AggUpdate)
	bgpServer.RemAggCh = make(chan string)
	bgpServer.PeerFSMConnCh = make(chan fsm.PeerFSMConn, 50)
	bgpServer.PeerConnEstCh = make(chan string)
	bgpServer.PeerConnBrokenCh = make(chan string)
	bgpServer.PeerCommandCh = make(chan config.PeerCommand)
	bgpServer.ReachabilityCh = make(chan config.ReachabilityInfo)
	bgpServer.BGPPktSrcCh = make(chan *packet.BGPPktSrc)
	bgpServer.BfdCh = make(chan config.BfdInfo)
	bgpServer.IntfCh = make(chan config.IntfStateInfo)
	bgpServer.RoutesCh = make(chan *config.RouteCh)

	bgpServer.NeighborMutex = sync.RWMutex{}
	bgpServer.PeerMap = make(map[string]*Peer)
	bgpServer.Neighbors = make([]*Peer, 0)
	bgpServer.IntfMgr = iMgr
	bgpServer.routeMgr = rMgr
	bgpServer.bfdMgr = bMgr
	bgpServer.stateDBMgr = sDBMgr
	bgpServer.LocRib = bgprib.NewLocRib(logger, rMgr, sDBMgr, &bgpServer.BgpConfig.Global.Config)
	bgpServer.IfacePeerMap = make(map[int32][]string)
	bgpServer.ifaceIP = nil
	bgpServer.actionFuncMap = make(map[int]bgppolicy.PolicyActionFunc)
	bgpServer.AddPathCount = 0

	var aggrActionFunc bgppolicy.PolicyActionFunc
	aggrActionFunc.ApplyFunc = bgpServer.ApplyAggregateAction
	aggrActionFunc.UndoFunc = bgpServer.UndoAggregateAction

	bgpServer.actionFuncMap[policyCommonDefs.PolicyActionTypeAggregate] = aggrActionFunc

	locRibPE := bgppolicy.NewLocRibPolicyEngine(logger)
	bgpServer.logger.Infof("BGPServer: actionfuncmap=%v", bgpServer.actionFuncMap)
	locRibPE.SetEntityUpdateFunc(bgpServer.UpdateRouteAndPolicyDB)
	locRibPE.SetIsEntityPresentFunc(bgpServer.DoesRouteExist)
	locRibPE.SetActionFuncs(bgpServer.actionFuncMap)
	locRibPE.SetTraverseFuncs(bgpServer.TraverseAndApplyBGPRib, bgpServer.TraverseAndReverseBGPRib)
	bgpServer.locRibPE = locRibPE
	bgpServer.policyManager.AddPolicyEngine(bgpServer.locRibPE)

	return bgpServer
}

func (s *BGPServer) createListener() (*net.TCPListener, error) {
	proto := "tcp4"
	addr := ":" + config.BGPPort
	s.logger.Infof("Listening for incomig connections on %s", addr)
	tcpAddr, err := net.ResolveTCPAddr(proto, addr)
	if err != nil {
		s.logger.Info("ResolveTCPAddr failed with", err)
		return nil, err
	}

	listener, err := net.ListenTCP(proto, tcpAddr)
	if err != nil {
		s.logger.Info("ListenTCP failed with", err)
		return nil, err
	}

	return listener, nil
}

func (s *BGPServer) listenForPeers(listener *net.TCPListener, acceptCh chan *net.TCPConn) {
	for {
		s.logger.Info("Waiting for peer connections...")
		tcpConn, err := listener.AcceptTCP()
		if err != nil {
			s.logger.Info("AcceptTCP failed with", err)
			continue
		}
		s.logger.Info("Got a peer connection from %s", tcpConn.RemoteAddr())
		s.acceptCh <- tcpConn
	}
}

func (s *BGPServer) IsPeerLocal(peerIp string) bool {
	return s.PeerMap[peerIp].NeighborConf.RunningConf.PeerAS == s.BgpConfig.Global.Config.AS
}

func (s *BGPServer) SendUpdate(updated map[uint32]map[*bgprib.Path][]*bgprib.Destination, withdrawn,
	updatedAddPaths []*bgprib.Destination) {
	for _, peer := range s.PeerMap {
		peer.SendUpdate(updated, withdrawn, updatedAddPaths)
	}
}

func (s *BGPServer) DoesRouteExist(params interface{}) bool {
	policyParams := params.(PolicyParams)
	dest := policyParams.dest
	if dest == nil {
		s.logger.Info("BGPServer:DoesRouteExist - dest not found for ip",
			policyParams.route.Dest.BGPRouteState.Network, "prefix length",
			policyParams.route.Dest.BGPRouteState.CIDRLen)
		return false
	}

	locRibRoute := dest.GetLocRibPathRoute()
	if policyParams.route == locRibRoute {
		return true
	}

	return false
}

func (s *BGPServer) getAggPrefix(conditionsList []interface{}) *packet.IPPrefix {
	s.logger.Info("BGPServer:getAggPrefix")
	var ipPrefix *packet.IPPrefix
	var err error
	for _, condition := range conditionsList {
		switch condition.(type) {
		case utilspolicy.MatchPrefixConditionInfo:
			s.logger.Info("BGPServer:getAggPrefix - PolicyConditionTypeDstIpPrefixMatch case")
			matchPrefix := condition.(utilspolicy.MatchPrefixConditionInfo)
			s.logger.Info("BGPServer:getAggPrefix - exact prefix match conditiontype")
			ipPrefix, err = packet.ConstructIPPrefixFromCIDR(matchPrefix.Prefix.IpPrefix)
			if err != nil {
				s.logger.Info("BGPServer:getAggPrefix - ipPrefix invalid ")
				return nil
			}
			break
		default:
			s.logger.Info("BGPServer:getAggPrefix - Not a known condition type")
			break
		}
	}
	return ipPrefix
}

func (s *BGPServer) setUpdatedAddPaths(policyParams *PolicyParams,
	updatedAddPaths []*bgprib.Destination) {
	if len(updatedAddPaths) > 0 {
		addPathsMap := make(map[*bgprib.Destination]bool)
		for _, dest := range *(policyParams.updatedAddPaths) {
			addPathsMap[dest] = true
		}

		for _, dest := range updatedAddPaths {
			if !addPathsMap[dest] {
				(*policyParams.updatedAddPaths) =
					append((*policyParams.updatedAddPaths), dest)
			}
		}
	}
}

func (s *BGPServer) setWithdrawnWithAggPaths(policyParams *PolicyParams, withdrawn []*bgprib.Destination,
	sendSummaryOnly bool, updatedAddPaths []*bgprib.Destination) {
	destMap := make(map[*bgprib.Destination]bool)
	for _, dest := range *policyParams.withdrawn {
		destMap[dest] = true
	}

	aggDestMap := make(map[*bgprib.Destination]bool)
	for _, aggDestination := range withdrawn {
		aggDestMap[aggDestination] = true
		if !destMap[aggDestination] {
			s.logger.Infof("setWithdrawnWithAggPaths: add agg dest %+v to withdrawn",
				aggDestination.NLRI.GetPrefix())
			(*policyParams.withdrawn) = append((*policyParams.withdrawn), aggDestination)
		}
	}

	// There will be only one destination per aggregated path.
	// So, break out of the loop as soon as we find it.
	for protoFamily, pathDestMap := range *policyParams.updated {
		for path, destinations := range pathDestMap {
			for idx, dest := range destinations {
				if aggDestMap[dest] {
					(*policyParams.updated)[protoFamily][path][idx] = nil
					s.logger.Infof("setWithdrawnWithAggPaths: remove dest %+v from withdrawn",
						dest.NLRI.GetPrefix())
				}
			}
		}
	}

	if sendSummaryOnly {
		if policyParams.DeleteType == utilspolicy.Valid {
			for idx, dest := range *policyParams.withdrawn {
				if dest == policyParams.dest {
					s.logger.Infof("setWithdrawnWithAggPaths: remove dest %+v from withdrawn",
						dest.NLRI.GetPrefix())
					(*policyParams.withdrawn)[idx] = nil
				}
			}
		} else if policyParams.CreateType == utilspolicy.Invalid {
			if policyParams.dest != nil && policyParams.dest.LocRibPath != nil {
				found := false
				protoFamily := policyParams.dest.GetProtocolFamily()
				if destinations, ok :=
					(*policyParams.updated)[protoFamily][policyParams.dest.LocRibPath]; ok {
					for _, dest := range destinations {
						if dest == policyParams.dest {
							found = true
						}
					}
				} else {
					(*policyParams.updated)[protoFamily][policyParams.dest.LocRibPath] = make([]*bgprib.Destination, 0)
				}
				if !found {
					s.logger.Infof("setWithdrawnWithAggPaths: add dest %+v to update",
						policyParams.dest.NLRI.GetPrefix())
					(*policyParams.updated)[protoFamily][policyParams.dest.LocRibPath] = append(
						(*policyParams.updated)[protoFamily][policyParams.dest.LocRibPath], policyParams.dest)
				}
			}
		}
	}

	s.setUpdatedAddPaths(policyParams, updatedAddPaths)
}

func (s *BGPServer) setUpdatedWithAggPaths(policyParams *PolicyParams,
	updated map[uint32]map[*bgprib.Path][]*bgprib.Destination, sendSummaryOnly bool, ipPrefix *packet.IPPrefix,
	protoFamily uint32, updatedAddPaths []*bgprib.Destination) {
	var routeDest *bgprib.Destination
	var ok bool
	if routeDest, ok = s.LocRib.GetDest(ipPrefix, protoFamily, false); !ok {
		s.logger.Err("setUpdatedWithAggPaths: Did not find destination for ip", ipPrefix)
		if policyParams.dest != nil {
			routeDest = policyParams.dest
		} else {
			sendSummaryOnly = false
		}
	}

	withdrawMap := make(map[*bgprib.Destination]bool, len(*policyParams.withdrawn))
	if sendSummaryOnly {
		for _, dest := range *policyParams.withdrawn {
			withdrawMap[dest] = true
		}
	}

	for aggFamily, aggPathDestMap := range updated {
		for aggPath, aggDestinations := range aggPathDestMap {
			destMap := make(map[*bgprib.Destination]bool)
			ppUpdated := *policyParams.updated
			if _, ok := ppUpdated[aggFamily][aggPath]; !ok {
				ppUpdated[aggFamily][aggPath] = make([]*bgprib.Destination, 0)
			} else {
				for _, dest := range ppUpdated[aggFamily][aggPath] {
					destMap[dest] = true
				}
			}

			for _, dest := range aggDestinations {
				if !destMap[dest] {
					s.logger.Infof("setUpdatedWithAggPaths: add agg dest %+v to updated", dest.NLRI.GetPrefix())
					ppUpdated[aggFamily][aggPath] = append(ppUpdated[aggFamily][aggPath], dest)
				}
			}

			if sendSummaryOnly {
				if policyParams.CreateType == utilspolicy.Valid {
					if pathDestMap, ok := ppUpdated[protoFamily]; ok {
						for path, destinations := range pathDestMap {
							for idx, dest := range destinations {
								if routeDest == dest {
									ppUpdated[protoFamily][path][idx] = nil
									s.logger.Infof("setUpdatedWithAggPaths: summaryOnly, remove dest %+v"+
										" from updated", dest.NLRI.GetPrefix())
								}
							}
						}
					}
				} else if policyParams.DeleteType == utilspolicy.Invalid {
					if !withdrawMap[routeDest] {
						s.logger.Infof("setUpdatedWithAggPaths: summaryOnly, add dest %+v to withdrawn",
							routeDest.NLRI.GetPrefix())
						(*policyParams.withdrawn) = append((*policyParams.withdrawn), routeDest)
					}
				}
			}
		}
	}

	s.setUpdatedAddPaths(policyParams, updatedAddPaths)
}

func (s *BGPServer) UndoAggregateAction(actionInfo interface{},
	conditionList []interface{}, params interface{}, policyStmt utilspolicy.PolicyStmt) {
	policyParams := params.(PolicyParams)
	ipPrefix := packet.NewIPPrefix(net.ParseIP(policyParams.route.Dest.BGPRouteState.Network),
		uint8(policyParams.route.Dest.BGPRouteState.CIDRLen))
	protoFamily := policyParams.route.Dest.GetProtocolFamily()
	aggPrefix := s.getAggPrefix(conditionList)
	aggActions := actionInfo.(utilspolicy.PolicyAggregateActionInfo)
	bgpAgg := config.BGPAggregate{
		GenerateASSet:   aggActions.GenerateASSet,
		SendSummaryOnly: aggActions.SendSummaryOnly,
	}

	s.logger.Infof("UndoAggregateAction: ipPrefix=%+v, aggPrefix=%+v", ipPrefix.Prefix, aggPrefix.Prefix)
	var updated map[uint32]map[*bgprib.Path][]*bgprib.Destination
	var withdrawn []*bgprib.Destination
	var updatedAddPaths []*bgprib.Destination
	var origDest *bgprib.Destination
	if policyParams.dest != nil {
		origDest = policyParams.dest
	}
	updated, withdrawn, updatedAddPaths = s.LocRib.RemoveRouteFromAggregate(ipPrefix, aggPrefix,
		s.BgpConfig.Global.Config.RouterId.String(), protoFamily, &bgpAgg, origDest, s.AddPathCount)

	s.logger.Infof("UndoAggregateAction: aggregate result update=%+v, withdrawn=%+v", updated, withdrawn)
	s.setWithdrawnWithAggPaths(&policyParams, withdrawn, aggActions.SendSummaryOnly, updatedAddPaths)
	s.logger.Infof("UndoAggregateAction: after updating withdraw agg paths, update=%+v, withdrawn=%+v,"+
		"policyparams.update=%+v, policyparams.withdrawn=%+v", updated, withdrawn, *policyParams.updated,
		*policyParams.withdrawn)
	return
}

func (s *BGPServer) ApplyAggregateAction(actionInfo interface{},
	conditionInfo []interface{}, params interface{}) {
	policyParams := params.(PolicyParams)
	ipPrefix := packet.NewIPPrefix(net.ParseIP(policyParams.route.Dest.BGPRouteState.Network),
		uint8(policyParams.route.Dest.BGPRouteState.CIDRLen))
	protoFamily := policyParams.route.Dest.GetProtocolFamily()
	aggPrefix := s.getAggPrefix(conditionInfo)
	aggActions := actionInfo.(utilspolicy.PolicyAggregateActionInfo)
	bgpAgg := config.BGPAggregate{
		GenerateASSet:   aggActions.GenerateASSet,
		SendSummaryOnly: aggActions.SendSummaryOnly,
	}

	s.logger.Infof("ApplyAggregateAction: ipPrefix=%+v, aggPrefix=%+v", ipPrefix.Prefix, aggPrefix.Prefix)
	var updated map[uint32]map[*bgprib.Path][]*bgprib.Destination
	var withdrawn []*bgprib.Destination
	var updatedAddPaths []*bgprib.Destination
	if (policyParams.CreateType == utilspolicy.Valid) ||
		(policyParams.DeleteType == utilspolicy.Invalid) {
		s.logger.Infof("ApplyAggregateAction: CreateType= Valid or DeleteType = Invalid")
		updated, withdrawn, updatedAddPaths = s.LocRib.AddRouteToAggregate(ipPrefix, aggPrefix,
			s.BgpConfig.Global.Config.RouterId.String(), protoFamily, s.ifaceIP, &bgpAgg, s.AddPathCount)
	} else if policyParams.DeleteType == utilspolicy.Valid {
		s.logger.Infof("ApplyAggregateAction: DeleteType = Valid")
		origDest := policyParams.dest
		updated, withdrawn, updatedAddPaths = s.LocRib.RemoveRouteFromAggregate(ipPrefix, aggPrefix,
			s.BgpConfig.Global.Config.RouterId.String(), protoFamily, &bgpAgg, origDest, s.AddPathCount)
	}

	s.logger.Infof("ApplyAggregateAction: aggregate result update=%+v, withdrawn=%+v", updated, withdrawn)
	s.setUpdatedWithAggPaths(&policyParams, updated, aggActions.SendSummaryOnly, ipPrefix, protoFamily,
		updatedAddPaths)
	s.logger.Infof("ApplyAggregateAction: after updating agg paths, update=%+v, withdrawn=%+v, "+
		"policyparams.update=%+v, policyparams.withdrawn=%+v", updated, withdrawn, *policyParams.updated,
		*policyParams.withdrawn)
	return
}

func (s *BGPServer) CheckForAggregation(updated map[uint32]map[*bgprib.Path][]*bgprib.Destination, withdrawn,
	updatedAddPaths []*bgprib.Destination) (map[uint32]map[*bgprib.Path][]*bgprib.Destination, []*bgprib.Destination,
	[]*bgprib.Destination) {
	s.logger.Infof("BGPServer:checkForAggregate - start, updated %v withdrawn %v", updated, withdrawn)

	for _, dest := range withdrawn {
		if dest == nil || dest.LocRibPath == nil || dest.LocRibPath.IsAggregate() {
			continue
		}

		route := dest.GetLocRibPathRoute()
		if route == nil {
			s.logger.Infof("BGPServer:checkForAggregate - route not found withdraw dest %s",
				dest.NLRI.GetPrefix().String())
			continue
		}
		peEntity := utilspolicy.PolicyEngineFilterEntityParams{
			DestNetIp:  route.Dest.BGPRouteState.Network + "/" + strconv.Itoa(int(route.Dest.BGPRouteState.CIDRLen)),
			NextHopIp:  route.PathInfo.NextHop,
			DeletePath: true,
		}
		s.logger.Infof("BGPServer:checkForAggregate - withdraw dest %s policylist %v hit %v before ",
			"applying delete policy", dest.NLRI.GetPrefix().String(), route.PolicyList, route.PolicyHitCounter)
		callbackInfo := PolicyParams{
			CreateType:      utilspolicy.Invalid,
			DeleteType:      utilspolicy.Valid,
			route:           route,
			dest:            dest,
			updated:         &updated,
			withdrawn:       &withdrawn,
			updatedAddPaths: &updatedAddPaths,
		}
		s.locRibPE.PolicyEngine.PolicyEngineFilter(peEntity, policyCommonDefs.PolicyPath_Export, callbackInfo)
	}

	for _, pathDestMap := range updated {
		for _, destinations := range pathDestMap {
			s.logger.Infof("BGPServer:checkForAggregate - update destinations %+v", destinations)
			for _, dest := range destinations {
				s.logger.Infof("BGPServer:checkForAggregate - update dest %+v", dest.NLRI.GetPrefix())
				if dest == nil || dest.LocRibPath == nil || dest.LocRibPath.IsAggregate() {
					continue
				}
				route := dest.GetLocRibPathRoute()
				s.logger.Infof("BGPServer:checkForAggregate - update dest %s policylist %v hit %v before ",
					"applying create policy", dest.NLRI.GetPrefix().String(), route.PolicyList, route.PolicyHitCounter)
				if route != nil {
					peEntity := utilspolicy.PolicyEngineFilterEntityParams{
						DestNetIp:  route.Dest.BGPRouteState.Network + "/" + strconv.Itoa(int(route.Dest.BGPRouteState.CIDRLen)),
						NextHopIp:  route.PathInfo.NextHop,
						CreatePath: true,
					}
					callbackInfo := PolicyParams{
						CreateType:      utilspolicy.Valid,
						DeleteType:      utilspolicy.Invalid,
						route:           route,
						dest:            dest,
						updated:         &updated,
						withdrawn:       &withdrawn,
						updatedAddPaths: &updatedAddPaths,
					}
					s.locRibPE.PolicyEngine.PolicyEngineFilter(peEntity, policyCommonDefs.PolicyPath_Export, callbackInfo)
					s.logger.Infof("BGPServer:checkForAggregate - update dest %s policylist %v hit %v ",
						"after applying create policy", dest.NLRI.GetPrefix().String(), route.PolicyList,
						route.PolicyHitCounter)
				}
			}
		}
	}

	s.logger.Infof("BGPServer:checkForAggregate - complete, updated %v withdrawn %v", updated, withdrawn)
	return updated, withdrawn, updatedAddPaths
}

func (s *BGPServer) UpdateRouteAndPolicyDB(policyDetails utilspolicy.PolicyDetails, params interface{}) {
	policyParams := params.(PolicyParams)
	var op int
	if policyParams.DeleteType != bgppolicy.Invalid {
		op = bgppolicy.Del
	} else {
		if policyDetails.EntityDeleted == false {
			s.logger.Info("Reject action was not applied, so add this policy to the route")
			op = bgppolicy.Add
			bgppolicy.UpdateRoutePolicyState(policyParams.route, op, policyDetails.Policy, policyDetails.PolicyStmt)
		}
		policyParams.route.PolicyHitCounter++
	}
	s.locRibPE.UpdatePolicyRouteMap(policyParams.route, policyDetails.Policy, op)
}

func (s *BGPServer) TraverseAndApplyBGPRib(data interface{}, updateFunc utilspolicy.PolicyApplyfunc) {
	s.logger.Infof("BGPServer:TraverseRibForPolicies - start")
	policy := data.(utilspolicy.ApplyPolicyInfo)
	updated := make(map[uint32]map[*bgprib.Path][]*bgprib.Destination, 10)
	withdrawn := make([]*bgprib.Destination, 0, 10)
	updatedAddPaths := make([]*bgprib.Destination, 0)
	locRib := s.LocRib.GetLocRib()
	for _, pathDestMap := range locRib {
		for path, destinations := range pathDestMap {
			for _, dest := range destinations {
				if !path.IsAggregatePath() {
					route := dest.GetLocRibPathRoute()
					if route == nil {
						continue
					}
					peEntity := utilspolicy.PolicyEngineFilterEntityParams{
						DestNetIp: route.Dest.BGPRouteState.Network + "/" +
							strconv.Itoa(int(route.Dest.BGPRouteState.CIDRLen)),
						NextHopIp:  route.PathInfo.NextHop,
						PolicyList: route.PolicyList,
					}
					callbackInfo := PolicyParams{
						route:           route,
						dest:            dest,
						updated:         &updated,
						withdrawn:       &withdrawn,
						updatedAddPaths: &updatedAddPaths,
					}

					updateFunc(peEntity, policy, callbackInfo)
				}
			}
		}
	}
	s.logger.Infof("BGPServer:TraverseRibForPolicies - updated %v withdrawn %v", updated, withdrawn)
	s.SendUpdate(updated, withdrawn, updatedAddPaths)
}

func (s *BGPServer) TraverseAndReverseBGPRib(policyData interface{}) {
	policy := policyData.(utilspolicy.Policy)
	s.logger.Info("BGPServer:TraverseAndReverseBGPRib - policy", policy.Name)
	policyExtensions := policy.Extensions.(bgppolicy.PolicyExtensions)
	if len(policyExtensions.RouteList) == 0 {
		fmt.Println("No route affected by this policy, so nothing to do")
		return
	}

	updated := make(map[uint32]map[*bgprib.Path][]*bgprib.Destination, 10)
	withdrawn := make([]*bgprib.Destination, 0, 10)
	updatedAddPaths := make([]*bgprib.Destination, 0)
	var route *bgprib.Route
	for idx := 0; idx < len(policyExtensions.RouteInfoList); idx++ {
		route = policyExtensions.RouteInfoList[idx]
		dest := s.LocRib.GetDestFromIPAndLen(route.Dest.GetProtocolFamily(), route.Dest.BGPRouteState.Network,
			uint32(route.Dest.BGPRouteState.CIDRLen))
		callbackInfo := PolicyParams{
			route:           route,
			dest:            dest,
			updated:         &updated,
			withdrawn:       &withdrawn,
			updatedAddPaths: &updatedAddPaths,
		}
		peEntity := utilspolicy.PolicyEngineFilterEntityParams{
			DestNetIp: route.Dest.BGPRouteState.Network + "/" + strconv.Itoa(int(route.Dest.BGPRouteState.CIDRLen)),
			NextHopIp: route.PathInfo.NextHop,
		}

		ipPrefix, err := bgppolicy.GetNetworkPrefixFromCIDR(route.Dest.BGPRouteState.Network + "/" +
			strconv.Itoa(int(route.Dest.BGPRouteState.CIDRLen)))
		if err != nil {
			s.logger.Info("Invalid route ", ipPrefix)
			continue
		}
		s.locRibPE.PolicyEngine.PolicyEngineUndoPolicyForEntity(peEntity, policy, callbackInfo)
		s.locRibPE.DeleteRoutePolicyState(route, policy.Name)
		s.locRibPE.PolicyEngine.DeletePolicyEntityMapEntry(peEntity, policy.Name)
	}
}

func (s *BGPServer) ProcessUpdate(pktInfo *packet.BGPPktSrc) {
	peer, ok := s.PeerMap[pktInfo.Src]
	if !ok {
		s.logger.Err("BgpServer:ProcessUpdate - Peer not found, address:", pktInfo.Src)
		return
	}

	atomic.AddUint32(&peer.NeighborConf.Neighbor.State.Queues.Input, ^uint32(0))
	peer.NeighborConf.Neighbor.State.Messages.Received.Update++
	updated, withdrawn, updatedAddPaths, addedAllPrefixes := s.LocRib.ProcessUpdate(
		peer.NeighborConf, pktInfo, s.AddPathCount)
	if !addedAllPrefixes {
		peer.MaxPrefixesExceeded()
	}
	updated, withdrawn, updatedAddPaths = s.CheckForAggregation(updated, withdrawn, updatedAddPaths)
	s.SendUpdate(updated, withdrawn, updatedAddPaths)
}

func (s *BGPServer) convertDestIPToIPPrefix(routes []*config.RouteInfo) map[uint32][]packet.NLRI {
	pfNLRI := make(map[uint32][]packet.NLRI)
	for _, r := range routes {
		ip := net.ParseIP(r.IPAddr)
		if ip == nil {
			s.logger.Errf("Connected route %s/%s is not a valid IP", r.IPAddr, r.Mask)
			continue
		}

		var protoFamily uint32
		if ip.To4() != nil {
			protoFamily = packet.GetProtocolFamily(packet.AfiIP, packet.SafiUnicast)
		} else {
			protoFamily = packet.GetProtocolFamily(packet.AfiIP6, packet.SafiUnicast)
		}

		s.logger.Infof("Connected route: addr %s netmask %s", r.IPAddr, r.Mask)
		if _, ok := pfNLRI[protoFamily]; !ok {
			pfNLRI[protoFamily] = make([]packet.NLRI, 0)
		}

		ipPrefix := packet.ConstructIPPrefix(r.IPAddr, r.Mask)
		pfNLRI[protoFamily] = append(pfNLRI[protoFamily], ipPrefix)
	}
	return pfNLRI
}

func (s *BGPServer) ProcessConnectedRoutes(installedRoutes, withdrawnRoutes []*config.RouteInfo) {
	s.logger.Info("valid routes:", installedRoutes, "invalid routes:", withdrawnRoutes)
	valid := s.convertDestIPToIPPrefix(installedRoutes)
	invalid := s.convertDestIPToIPPrefix(withdrawnRoutes)
	s.logger.Info("pfNLRI valid:", valid, "invalid:", invalid)
	routerId := s.BgpConfig.Global.Config.RouterId.String()
	updated, withdrawn, updatedAddPaths := s.LocRib.ProcessConnectedRoutes(routerId, s.ConnRoutesPath, valid,
		invalid, s.AddPathCount)
	updated, withdrawn, updatedAddPaths = s.CheckForAggregation(updated, withdrawn, updatedAddPaths)
	s.SendUpdate(updated, withdrawn, updatedAddPaths)
}

func (s *BGPServer) ProcessIntfStates(intfs []*config.IntfStateInfo) {
	for _, ifState := range intfs {
		if ifState.State == config.INTF_CREATED {
			s.ifaceMgr.AddIface(ifState.Idx, ifState.IPAddr)
		} else if ifState.State == config.INTF_DELETED {
			s.ifaceMgr.RemoveIface(ifState.Idx, ifState.IPAddr)
		}
	}
}

func (s *BGPServer) ProcessRemoveNeighbor(peerIp string, peer *Peer) {
	updated, withdrawn, updatedAddPaths := s.LocRib.RemoveUpdatesFromNeighbor(peerIp, peer.NeighborConf,
		s.AddPathCount)
	s.logger.Infof("ProcessRemoveNeighbor - Neighbor %s, send updated paths %v, withdrawn paths %v",
		peerIp, updated, withdrawn)
	updated, withdrawn, updatedAddPaths = s.CheckForAggregation(updated, withdrawn, updatedAddPaths)
	s.SendUpdate(updated, withdrawn, updatedAddPaths)
}

func (s *BGPServer) SendAllRoutesToPeer(peer *Peer) {
	withdrawn := make([]*bgprib.Destination, 0)
	updatedAddPaths := make([]*bgprib.Destination, 0)
	updated := s.LocRib.GetLocRib()
	s.SendUpdate(updated, withdrawn, updatedAddPaths)
}

func (s *BGPServer) RemoveRoutesFromAllNeighbor() {
	s.LocRib.RemoveUpdatesFromAllNeighbors(s.AddPathCount)
}

func (s *BGPServer) addPeerToList(peer *Peer) {
	s.Neighbors = append(s.Neighbors, peer)
}

func (s *BGPServer) removePeerFromList(peer *Peer) {
	for idx, item := range s.Neighbors {
		if item == peer {
			s.Neighbors[idx] = s.Neighbors[len(s.Neighbors)-1]
			s.Neighbors[len(s.Neighbors)-1] = nil
			s.Neighbors = s.Neighbors[:len(s.Neighbors)-1]
			break
		}
	}
}

func (s *BGPServer) StopPeersByGroup(groupName string) []*Peer {
	peers := make([]*Peer, 0)
	for peerIP, peer := range s.PeerMap {
		if peer.NeighborConf.Group != nil && peer.NeighborConf.Group.Name == groupName {
			s.logger.Info("Clean up peer", peerIP)
			peer.Cleanup()
			s.ProcessRemoveNeighbor(peerIP, peer)
			peers = append(peers, peer)

			runtime.Gosched()
		}
	}

	return peers
}

func (s *BGPServer) UpdatePeerGroupInPeers(groupName string, peerGroup *config.PeerGroupConfig) {
	peers := s.StopPeersByGroup(groupName)
	for _, peer := range peers {
		peer.UpdatePeerGroup(peerGroup)
		peer.Init()
	}
}

func (s *BGPServer) SetupRedistribution(gConf config.GlobalConfig) {
	s.logger.Info("SetUpRedistribution")
	if gConf.Redistribution == nil || len(gConf.Redistribution) == 0 {
		s.logger.Info("No redistribution policies configured")
		return
	}
	conditions := make([]*config.ConditionInfo, 0)
	for i := 0; i < len(gConf.Redistribution); i++ {
		s.logger.Info("Sources: ", gConf.Redistribution[i].Sources)
		sources := make([]string, 0)
		sources = strings.Split(gConf.Redistribution[i].Sources, ",")
		s.logger.Infof("Setting up %s as redistribution policy for source(s): ", gConf.Redistribution[i].Policy)
		for j := 0; j < len(sources); j++ {
			s.logger.Infof("%s ", sources[j])
			if sources[j] == "" {
				continue
			}
			conditions = append(conditions, &config.ConditionInfo{ConditionType: "MatchProtocol", Protocol: sources[j]})
		}
		s.logger.Info("")
		s.routeMgr.ApplyPolicy("BGP", gConf.Redistribution[i].Policy, "Redistribution", conditions)
	}
}

func (s *BGPServer) DeleteAgg(ipPrefix string) error {
	s.locRibPE.DeletePolicyDefinition(ipPrefix)
	s.locRibPE.DeletePolicyStmt(ipPrefix)
	s.locRibPE.DeletePolicyCondition(ipPrefix)
	return nil
}

func (s *BGPServer) AddOrUpdateAgg(oldConf config.BGPAggregate, newConf config.BGPAggregate, attrSet []bool) error {
	s.logger.Info("AddOrUpdateAgg")
	var err error

	if oldConf.IPPrefix != "" {
		// Delete the policy
		s.DeleteAgg(oldConf.IPPrefix)
	}

	if newConf.IPPrefix != "" {
		// Create the policy
		name := newConf.IPPrefix
		tokens := strings.Split(newConf.IPPrefix, "/")
		prefixLen := tokens[1]
		prefixLenInt, err := strconv.Atoi(prefixLen)
		if err != nil {
			s.logger.Errf("Failed to convert prefex len %s to int with error %s", prefixLen, err)
			return err
		}

		cond := utilspolicy.PolicyConditionConfig{
			Name:          name,
			ConditionType: "MatchDstIpPrefix",
			MatchDstIpPrefixConditionInfo: utilspolicy.PolicyDstIpMatchPrefixSetCondition{
				Prefix: utilspolicy.PolicyPrefix{
					IpPrefix:        newConf.IPPrefix,
					MasklengthRange: prefixLen + "-32",
				},
			},
		}

		_, err = s.locRibPE.CreatePolicyCondition(cond)
		if err != nil {
			s.logger.Errf("Failed to create policy condition for aggregate %s with error %s", name, err)
			return err
		}

		stmt := utilspolicy.PolicyStmtConfig{Name: name, MatchConditions: "all"}
		stmt.Conditions = make([]string, 1)
		stmt.Conditions[0] = name
		stmt.Actions = make([]string, 1)
		stmt.Actions[0] = "permit"
		err = s.locRibPE.CreatePolicyStmt(stmt)
		if err != nil {
			s.logger.Errf("Failed to create policy statement for aggregate %s with error %s", name, err)
			s.locRibPE.DeletePolicyCondition(name)
			return err
		}

		def := utilspolicy.PolicyDefinitionConfig{Name: name, Precedence: prefixLenInt, MatchType: "all"}
		def.PolicyDefinitionStatements = make([]utilspolicy.PolicyDefinitionStmtPrecedence, 1)
		policyDefinitionStatement := utilspolicy.PolicyDefinitionStmtPrecedence{
			Precedence: 1,
			Statement:  name,
		}
		def.PolicyDefinitionStatements[0] = policyDefinitionStatement
		def.Extensions = bgppolicy.PolicyExtensions{}
		err = s.locRibPE.CreatePolicyDefinition(def)
		if err != nil {
			s.logger.Errf("Failed to create policy definition for aggregate %s with error %s", name, err)
			s.locRibPE.DeletePolicyStmt(name)
			s.locRibPE.DeletePolicyCondition(name)
			return err
		}

		err = s.UpdateAggPolicy(name, s.locRibPE, newConf)
		return err
	}
	return err
}

func (s *BGPServer) UpdateAggPolicy(policyName string, pe bgppolicy.BGPPolicyEngine, aggConf config.BGPAggregate) error {
	s.logger.Debug("UpdateApplyPolicy")
	var err error
	var policyAction utilspolicy.PolicyAction
	conditionNameList := make([]string, 0)

	policyEngine := pe.GetPolicyEngine()
	policyDB := policyEngine.PolicyDB

	nodeGet := policyDB.Get(patriciaDB.Prefix(policyName))
	if nodeGet == nil {
		s.logger.Err("Policy ", policyName, " not defined")
		return errors.New(fmt.Sprintf("Policy %s not found in policy engine", policyName))
	}
	node := nodeGet.(utilspolicy.Policy)

	aggregateActionInfo := utilspolicy.PolicyAggregateActionInfo{aggConf.GenerateASSet, aggConf.SendSummaryOnly}
	policyAction = utilspolicy.PolicyAction{
		Name:       aggConf.IPPrefix,
		ActionType: policyCommonDefs.PolicyActionTypeAggregate,
		ActionInfo: aggregateActionInfo,
	}

	s.logger.Debug("Calling applypolicy with conditionNameList: ", conditionNameList)
	pe.UpdateApplyPolicy(utilspolicy.ApplyPolicyInfo{node, policyAction, conditionNameList}, true)
	return err
}

func (s *BGPServer) copyGlobalConf(gConf config.GlobalConfig) {
	s.BgpConfig.Global.Config.AS = gConf.AS
	s.BgpConfig.Global.Config.RouterId = gConf.RouterId
	s.BgpConfig.Global.Config.UseMultiplePaths = gConf.UseMultiplePaths
	s.BgpConfig.Global.Config.EBGPMaxPaths = gConf.EBGPMaxPaths
	s.BgpConfig.Global.Config.EBGPAllowMultipleAS = gConf.EBGPAllowMultipleAS
	s.BgpConfig.Global.Config.IBGPMaxPaths = gConf.IBGPMaxPaths
}

func (s *BGPServer) handleBfdNotifications(oper config.Operation, DestIp string,
	State bool) {
	if peer, ok := s.PeerMap[DestIp]; ok {
		if !State && peer.NeighborConf.Neighbor.State.BfdNeighborState == "up" {
			peer.NeighborConf.BfdFaultSet()
			peer.Command(int(fsm.BGPEventManualStop), fsm.BGPCmdReasonNone)
		}
		if State && peer.NeighborConf.Neighbor.State.BfdNeighborState == "down" {
			peer.NeighborConf.BfdFaultCleared()
			peer.Command(int(fsm.BGPEventManualStart), fsm.BGPCmdReasonNone)
		}
		s.logger.Info("Bfd state of peer ", peer.NeighborConf.Neighbor.NeighborAddress, " is ",
			peer.NeighborConf.Neighbor.State.BfdNeighborState)
	}
}

func (s *BGPServer) setInterfaceMapForPeer(peerIP string, peer *Peer) {
	s.logger.Info("Server: setInterfaceMapForPeer Peer", peer, "calling GetRouteReachabilityInfo")
	reachInfo, err := s.routeMgr.GetNextHopInfo(peerIP)
	s.logger.Info("Server: setInterfaceMapForPeer Peer", peer, "GetRouteReachabilityInfo returned", reachInfo)
	if err != nil {
		s.logger.Infof("Server: Peer %s is not reachable", peerIP)
	} else {
		// @TODO: jgheewala think of something better for ovsdb....
		ifIdx := s.IntfMgr.GetIfIndex(int(reachInfo.NextHopIfIndex),
			int(reachInfo.NextHopIfType))
		///		ifIdx := asicdCommonDefs.GetIfIndexFromIntfIdAndIntfType(int(reachInfo.NextHopIfIndex), int(reachInfo.NextHopIfType))
		s.logger.Infof("Server: Peer %s IfIdx %d", peerIP, ifIdx)
		if _, ok := s.IfacePeerMap[ifIdx]; !ok {
			s.IfacePeerMap[ifIdx] = make([]string, 0)
		}
		s.IfacePeerMap[ifIdx] = append(s.IfacePeerMap[ifIdx], peerIP)
		peer.setIfIdx(ifIdx)
	}
}

func (s *BGPServer) clearInterfaceMapForPeer(peerIP string, peer *Peer) {
	ifIdx := peer.getIfIdx()
	s.logger.Infof("Server: Peer %s FSM connection broken ifIdx %v", peerIP, ifIdx)
	if peerList, ok := s.IfacePeerMap[ifIdx]; ok {
		for idx, ip := range peerList {
			if ip == peerIP {
				s.IfacePeerMap[ifIdx] = append(s.IfacePeerMap[ifIdx][:idx],
					s.IfacePeerMap[ifIdx][idx+1:]...)
				if len(s.IfacePeerMap[ifIdx]) == 0 {
					delete(s.IfacePeerMap, ifIdx)
				}
				break
			}
		}
	}
	peer.setIfIdx(-1)
}

func (s *BGPServer) constructBGPGlobalState(gConf *config.GlobalConfig) {
	s.BgpConfig.Global.State.AS = gConf.AS
	s.BgpConfig.Global.State.RouterId = gConf.RouterId
	s.BgpConfig.Global.State.UseMultiplePaths = gConf.UseMultiplePaths
	s.BgpConfig.Global.State.EBGPMaxPaths = gConf.EBGPMaxPaths
	s.BgpConfig.Global.State.EBGPAllowMultipleAS = gConf.EBGPAllowMultipleAS
	s.BgpConfig.Global.State.IBGPMaxPaths = gConf.IBGPMaxPaths
}

func (s *BGPServer) listenChannelUpdates() {
	for {
		select {
		case globalUpdate := <-s.GlobalConfigCh:
			for peerIP, peer := range s.PeerMap {
				s.logger.Infof("Cleanup peer %s", peerIP)
				peer.Cleanup()
			}
			s.logger.Infof("Giving up CPU so that all peer FSMs will get cleaned up")
			runtime.Gosched()

			gConf := globalUpdate.NewConfig
			packet.SetNextHopPathAttrs(s.ConnRoutesPath.PathAttrs, gConf.RouterId)
			s.RemoveRoutesFromAllNeighbor()
			s.copyGlobalConf(gConf)
			s.constructBGPGlobalState(&gConf)
			for _, peer := range s.PeerMap {
				peer.Init()
			}
			s.SetupRedistribution(gConf)

		case peerUpdate := <-s.AddPeerCh:
			s.logger.Info("message received on AddPeerCh")
			oldPeer := peerUpdate.OldPeer
			newPeer := peerUpdate.NewPeer
			var peer *Peer
			var ok bool
			if oldPeer.NeighborAddress != nil {
				if peer, ok = s.PeerMap[oldPeer.NeighborAddress.String()]; ok {
					s.logger.Info("Clean up peer", oldPeer.NeighborAddress.String())
					peer.Cleanup()
					s.ProcessRemoveNeighbor(oldPeer.NeighborAddress.String(), peer)
					if peer.NeighborConf.RunningConf.AuthPassword != "" {
						err := netUtils.SetTCPListenerMD5(s.listener, oldPeer.NeighborAddress.String(), "")
						if err != nil {
							s.logger.Info("Failed to add MD5 authentication for old neighbor",
								newPeer.NeighborAddress.String(), "with error", err)
						}
					}
					peer.UpdateNeighborConf(newPeer, &s.BgpConfig)

					runtime.Gosched()
				} else {
					s.logger.Info("Can't find neighbor with old address", oldPeer.NeighborAddress.String())
				}
			}

			if !ok {
				_, ok = s.PeerMap[newPeer.NeighborAddress.String()]
				if ok {
					s.logger.Info("Failed to add neighbor. Neighbor at that address already exists,",
						newPeer.NeighborAddress.String())
					break
				}

				var groupConfig *config.PeerGroupConfig
				if newPeer.PeerGroup != "" {
					if group, ok :=
						s.BgpConfig.PeerGroups[newPeer.PeerGroup]; !ok {
						s.logger.Info("Peer group", newPeer.PeerGroup, "not created yet, creating peer",
							newPeer.NeighborAddress.String(), "without the group")
					} else {
						groupConfig = &group.Config
					}
				}
				s.logger.Info("Add neighbor, ip:", newPeer.NeighborAddress.String())
				peer = NewPeer(s, s.LocRib, &s.BgpConfig.Global.Config, groupConfig, newPeer)
				if peer.NeighborConf.RunningConf.AuthPassword != "" {
					err := netUtils.SetTCPListenerMD5(s.listener, newPeer.NeighborAddress.String(),
						peer.NeighborConf.RunningConf.AuthPassword)
					if err != nil {
						s.logger.Info("Failed to add MD5 authentication for neighbor",
							newPeer.NeighborAddress.String(), "with error", err)
					}
				}
				s.PeerMap[newPeer.NeighborAddress.String()] = peer
				s.NeighborMutex.Lock()
				s.addPeerToList(peer)
				s.NeighborMutex.Unlock()
			}
			peer.Init()

		case remPeer := <-s.RemPeerCh:
			s.logger.Info("Remove Peer:", remPeer)
			peer, ok := s.PeerMap[remPeer]
			if !ok {
				s.logger.Info("Failed to remove peer. Peer at that address does not exist,", remPeer)
				break
			}
			s.NeighborMutex.Lock()
			s.removePeerFromList(peer)
			s.NeighborMutex.Unlock()
			delete(s.PeerMap, remPeer)
			peer.Cleanup()
			s.ProcessRemoveNeighbor(remPeer, peer)

		case groupUpdate := <-s.AddPeerGroupCh:
			oldGroupConf := groupUpdate.OldGroup
			newGroupConf := groupUpdate.NewGroup
			s.logger.Info("Peer group update old:", oldGroupConf, "new:", newGroupConf)
			var ok bool

			if oldGroupConf.Name != "" {
				if _, ok = s.BgpConfig.PeerGroups[oldGroupConf.Name]; !ok {
					s.logger.Err("Could not find peer group", oldGroupConf.Name)
					break
				}
			}

			if _, ok = s.BgpConfig.PeerGroups[newGroupConf.Name]; !ok {
				s.logger.Info("Add new peer group with name", newGroupConf.Name)
				peerGroup := config.PeerGroup{
					Config: newGroupConf,
				}
				s.BgpConfig.PeerGroups[newGroupConf.Name] = &peerGroup
			}
			s.UpdatePeerGroupInPeers(newGroupConf.Name, &newGroupConf)

		case groupName := <-s.RemPeerGroupCh:
			s.logger.Info("Remove Peer group:", groupName)
			if _, ok := s.BgpConfig.PeerGroups[groupName]; !ok {
				s.logger.Info("Peer group", groupName, "not found")
				break
			}
			delete(s.BgpConfig.PeerGroups, groupName)
			s.UpdatePeerGroupInPeers(groupName, nil)

		case aggUpdate := <-s.AddAggCh:
			oldAgg := aggUpdate.OldAgg
			newAgg := aggUpdate.NewAgg
			if newAgg.IPPrefix != "" {
				s.AddOrUpdateAgg(oldAgg, newAgg, aggUpdate.AttrSet)
			}

		case ipPrefix := <-s.RemAggCh:
			s.DeleteAgg(ipPrefix)

		case tcpConn := <-s.acceptCh:
			s.logger.Info("Connected to", tcpConn.RemoteAddr().String())
			host, _, _ := net.SplitHostPort(tcpConn.RemoteAddr().String())
			peer, ok := s.PeerMap[host]
			if !ok {
				s.logger.Info("Can't accept connection. Peer is not configured yet", host)
				tcpConn.Close()
				s.logger.Info("Closed connection from", host)
				break
			}
			peer.AcceptConn(tcpConn)

		case peerCommand := <-s.PeerCommandCh:
			s.logger.Info("Peer Command received", peerCommand)
			peer, ok := s.PeerMap[peerCommand.IP.String()]
			if !ok {
				s.logger.Infof("Failed to apply command %s. Peer at that address does not exist, %v",
					peerCommand.Command, peerCommand.IP)
			}
			peer.Command(peerCommand.Command, fsm.BGPCmdReasonNone)

		case peerFSMConn := <-s.PeerFSMConnCh:
			s.logger.Infof("Server: Peer %s FSM established/broken channel", peerFSMConn.PeerIP)
			peer, ok := s.PeerMap[peerFSMConn.PeerIP]
			if !ok {
				s.logger.Infof("Failed to process FSM connection success, Peer %s does not exist",
					peerFSMConn.PeerIP)
				break
			}

			if peerFSMConn.Established {
				peer.PeerConnEstablished(peerFSMConn.Conn)
				addPathsMaxTx := peer.getAddPathsMaxTx()
				if addPathsMaxTx > s.AddPathCount {
					s.AddPathCount = addPathsMaxTx
				}
				s.setInterfaceMapForPeer(peerFSMConn.PeerIP, peer)
				s.SendAllRoutesToPeer(peer)
			} else {
				peer.PeerConnBroken(true)
				addPathsMaxTx := peer.getAddPathsMaxTx()
				if addPathsMaxTx < s.AddPathCount {
					s.AddPathCount = 0
					for _, otherPeer := range s.PeerMap {
						addPathsMaxTx = otherPeer.getAddPathsMaxTx()
						if addPathsMaxTx > s.AddPathCount {
							s.AddPathCount = addPathsMaxTx
						}
					}
				}
				s.clearInterfaceMapForPeer(peerFSMConn.PeerIP, peer)
				s.ProcessRemoveNeighbor(peerFSMConn.PeerIP, peer)
			}

		case peerIP := <-s.PeerConnEstCh:
			s.logger.Infof("Server: Peer %s FSM connection established", peerIP)
			peer, ok := s.PeerMap[peerIP]
			if !ok {
				s.logger.Infof("Failed to process FSM connection success, Peer %s does not exist", peerIP)
				break
			}
			reachInfo, err := s.routeMgr.GetNextHopInfo(peerIP)
			if err != nil {
				s.logger.Infof("Server: Peer %s is not reachable", peerIP)
			} else {
				// @TODO: jgheewala think of something better for ovsdb....
				ifIdx := s.IntfMgr.GetIfIndex(int(reachInfo.NextHopIfIndex),
					int(reachInfo.NextHopIfType))
				s.logger.Infof("Server: Peer %s IfIdx %d", peerIP, ifIdx)
				if _, ok := s.IfacePeerMap[ifIdx]; !ok {
					s.IfacePeerMap[ifIdx] = make([]string, 0)
					//ifIdx := asicdCommonDefs.GetIfIndexFromIntfIdAndIntfType(int(reachInfo.NextHopIfIndex), int(reachInfo.NextHopIfType))
				}
				s.IfacePeerMap[ifIdx] = append(s.IfacePeerMap[ifIdx],
					peerIP)
				peer.setIfIdx(ifIdx)
			}

			s.SendAllRoutesToPeer(peer)

		case peerIP := <-s.PeerConnBrokenCh:
			s.logger.Infof("Server: Peer %s FSM connection broken", peerIP)
			peer, ok := s.PeerMap[peerIP]
			if !ok {
				s.logger.Infof("Failed to process FSM connection failure, Peer %s does not exist", peerIP)
				break
			}
			ifIdx := peer.getIfIdx()
			s.logger.Infof("Server: Peer %s FSM connection broken ifIdx %v", peerIP, ifIdx)
			if peerList, ok := s.IfacePeerMap[ifIdx]; ok {
				for idx, ip := range peerList {
					if ip == peerIP {
						s.IfacePeerMap[ifIdx] =
							append(s.IfacePeerMap[ifIdx][:idx],
								s.IfacePeerMap[ifIdx][idx+1:]...)
						if len(s.IfacePeerMap[ifIdx]) == 0 {
							delete(s.IfacePeerMap, ifIdx)
						}
						break
					}
				}
			}
			peer.setIfIdx(-1)
			s.ProcessRemoveNeighbor(peerIP, peer)

		case pktInfo := <-s.BGPPktSrcCh:
			s.logger.Info("Received BGP message from peer %s", pktInfo.Src)
			s.ProcessUpdate(pktInfo)

		case reachabilityInfo := <-s.ReachabilityCh:
			s.logger.Info("Server: Reachability info for ip", reachabilityInfo.IP)

			_, err := s.routeMgr.GetNextHopInfo(reachabilityInfo.IP)
			if err != nil {
				reachabilityInfo.ReachableCh <- false
			} else {
				reachabilityInfo.ReachableCh <- true
			}
		case bfdNotify := <-s.BfdCh:
			s.handleBfdNotifications(bfdNotify.Oper,
				bfdNotify.DestIp, bfdNotify.State)
		case ifState := <-s.IntfCh:
			if ifState.State == config.INTF_STATE_DOWN {
				if peerList, ok := s.IfacePeerMap[ifState.Idx]; ok {
					for _, peerIP := range peerList {
						if peer, ok := s.PeerMap[peerIP]; ok {
							peer.StopFSM("Interface Down")
						}
					}
				}
			} else if ifState.State == config.INTF_CREATED {
				s.ifaceMgr.AddIface(ifState.Idx, ifState.IPAddr)
			} else if ifState.State == config.INTF_DELETED {
				s.ifaceMgr.RemoveIface(ifState.Idx, ifState.IPAddr)
			}
		case routeInfo := <-s.RoutesCh:
			s.ProcessConnectedRoutes(routeInfo.Add, routeInfo.Remove)
		}
	}

}

func (s *BGPServer) InitBGPEvent() {
	// Start DB Util
	s.eventDbHdl = dbutils.NewDBUtil(s.logger)
	err := s.eventDbHdl.Connect()
	if err != nil {
		s.logger.Errf("DB connect failed with error %s. Exiting!!", err)
		return
	}
	err = eventUtils.InitEvents("BGPD", s.eventDbHdl, s.logger, 1000)
	if err != nil {
		s.logger.Err("Unable to initialize events", err)
	}
}

func (s *BGPServer) StartServer() {
	// Initialize Event Handler
	s.InitBGPEvent()

	globalUpdate := <-s.GlobalConfigCh
	gConf := globalUpdate.NewConfig
	s.GlobalCfgDone = true
	s.logger.Info("Recieved global conf:", gConf)
	s.BgpConfig.Global.Config = gConf
	s.constructBGPGlobalState(&gConf)
	s.BgpConfig.PeerGroups = make(map[string]*config.PeerGroup)

	pathAttrs := packet.ConstructPathAttrForConnRoutes(gConf.RouterId, gConf.AS)
	s.ConnRoutesPath = bgprib.NewPath(s.LocRib, nil, pathAttrs, nil, bgprib.RouteTypeConnected)

	s.logger.Info("Setting up Peer connections")
	// channel for accepting connections
	s.acceptCh = make(chan *net.TCPConn)

	s.listener, _ = s.createListener()
	go s.listenForPeers(s.listener, s.acceptCh)

	s.logger.Info("Start all managers and initialize API Layer")
	s.IntfMgr.Start()
	s.routeMgr.Start()
	s.bfdMgr.Start()
	s.SetupRedistribution(gConf)

	/*  ALERT: StartServer is a go routine and hence do not have any other go routine where
	 *	   you are making calls to other client. FlexSwitch uses thrift for rpc and hence
	 *	   on return it will not know which go routine initiated the thrift call.
	 */
	// Get routes from the route manager
	add, remove := s.routeMgr.GetRoutes()
	if add != nil && remove != nil {
		s.ProcessConnectedRoutes(add, remove)
	}

	intfs := s.IntfMgr.GetIPv4Intfs()
	s.ProcessIntfStates(intfs)

	s.listenChannelUpdates()
}

func (s *BGPServer) GetBGPGlobalState() config.GlobalState {
	return s.BgpConfig.Global.State
}

func (s *BGPServer) GetBGPNeighborState(neighborIP string) *config.NeighborState {
	peer, ok := s.PeerMap[neighborIP]
	if !ok {
		s.logger.Errf("GetBGPNeighborState - Neighbor not found for address:%s", neighborIP)
		return nil
	}
	return &peer.NeighborConf.Neighbor.State
}

func (s *BGPServer) BulkGetBGPNeighbors(index int, count int) (int, int, []*config.NeighborState) {
	defer s.NeighborMutex.RUnlock()

	s.NeighborMutex.RLock()
	if index+count > len(s.Neighbors) {
		count = len(s.Neighbors) - index
	}

	result := make([]*config.NeighborState, count)
	for i := 0; i < count; i++ {
		result[i] = &s.Neighbors[i+index].NeighborConf.Neighbor.State
	}

	index += count
	if index >= len(s.Neighbors) {
		index = 0
	}
	return index, count, result
}

func (s *BGPServer) VerifyBgpGlobalConfig() bool {
	return s.GlobalCfgDone
}
