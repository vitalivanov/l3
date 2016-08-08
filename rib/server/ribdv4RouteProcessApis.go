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

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"l3/rib/ribdCommonDefs"
	"models/objects"
	"net"
	"reflect"
	"ribd"
	"ribdInt"
	"strconv"
	"strings"
	"utils/patriciaDB"
	//"utils/policy/policyCommonDefs"
)

var V4RouteInfoMap *patriciaDB.Trie //Routes are stored in patricia trie

/*
   Returns the longest prefix match route to reach the destination network destNet
*/
func (m RIBDServer) GetV4RouteReachabilityInfo(destNet string) (nextHopIntf *ribdInt.NextHopInfo, err error) {
	//logger.Debug("GetRouteReachabilityInfo of ", destNet)
	//t1 := time.Now()
	var retnextHopIntf ribdInt.NextHopInfo
	nextHopIntf = &retnextHopIntf
	var found bool
	destNetIp, err := getIP(destNet)
	if err != nil {
		logger.Err("getIP returned Invalid dest ip address for ", destNet)
		return nextHopIntf, errors.New("Invalid dest ip address")
	}
	lookupIp := destNetIp.To4()
	if lookupIp == nil {
		logger.Err("Incorrect ip type lookup")
		return nextHopIntf, errors.New("Incorrect ip type lookup")
	}
	destNetIp = lookupIp
	rmapInfoListItem := V4RouteInfoMap.GetLongestPrefixNode(patriciaDB.Prefix(destNetIp))
	if rmapInfoListItem != nil {
		rmapInfoList := rmapInfoListItem.(RouteInfoRecordList)
		if rmapInfoList.selectedRouteProtocol != "INVALID" {
			found = true
			routeInfoList, ok := rmapInfoList.routeInfoProtocolMap[rmapInfoList.selectedRouteProtocol]
			if !ok || len(routeInfoList) == 0 {
				logger.Err("Selected route not found")
				return nil, errors.New("dest ip address not reachable")
			}
			v := routeInfoList[0]
			nextHopIntf.NextHopIp = v.nextHopIp.String()
			nextHopIntf.NextHopIfIndex = ribdInt.Int(v.nextHopIfIndex)
			nextHopIntf.Metric = ribdInt.Int(v.metric)
			nextHopIntf.Ipaddr = v.destNetIp.String()
			nextHopIntf.Mask = v.networkMask.String()
			nextHopIntf.IsReachable = true
		}
	}

	if found == false {
		//logger.Err("dest IP", destNetIp, " not reachable ")
		err = errors.New("dest ip address not reachable")
		return nextHopIntf, err
	}
	//	duration := time.Since(t1)
	//logger.Debug("time to get longestPrefixLen = ", duration.Nanoseconds(), " ipAddr of the route: ", nextHopIntf.Ipaddr, " next hop ip of the route = ", nextHopIntf.NextHopIp, " ifIndex: ", nextHopIntf.NextHopIfIndex)
	return nextHopIntf, err
}

/*
    Function updates the route reachability status of a network. When a route is created/deleted/state changes,
	we traverse the entire route map and call this function for each of the destination network with :
	    prefix = route prefix of route being visited
		handle = routeInfoList data stored at this node
		item - reachabilityInfo data formed with route that is modified and the state
*/
func UpdateV4RouteReachabilityStatus(prefix patriciaDB.Prefix, //prefix of the node being traversed
	handle patriciaDB.Item, //data interface (routeInforRecordList) for this node
	item patriciaDB.Item) /*RouteReachabilityStatusInfo data */ (err error) {

	if handle == nil {
		logger.Err("nil handle")
		return err
	}
	routeReachabilityStatusInfo := item.(RouteReachabilityStatusInfo)
	var ipMask net.IP
	ip, ipNet, err := net.ParseCIDR(routeReachabilityStatusInfo.destNet)
	if err != nil {
		logger.Err("Error getting IP from cidr: ", routeReachabilityStatusInfo.destNet)
		return err
	}
	ipMask = make(net.IP, 4)
	copy(ipMask, ipNet.Mask)
	ipAddrStr := ip.String()
	ipMaskStr := net.IP(ipMask).String()
	destIpPrefix, err := getNetowrkPrefixFromStrings(ipAddrStr, ipMaskStr)
	if err != nil {
		logger.Err("Error getting ip prefix for ip:", ipAddrStr, " mask:", ipMaskStr)
		return err
	}
	//logger.Debug("UpdateRouteReachabilityStatus network: ", routeReachabilityStatusInfo.destNet, " status:", routeReachabilityStatusInfo.status, "ip: ", ip.String(), " destIPPrefix: ", destIpPrefix, " ipMaskStr:", ipMaskStr)
	rmapInfoRecordList := handle.(RouteInfoRecordList)
	//for each of the routes for this destination, check if the nexthop ip matches destPrefix - which is the route being modified
	for k, v := range rmapInfoRecordList.routeInfoProtocolMap {
		//logger.Debug("UpdateRouteReachabilityStatus - protocol: ", k)
		for i := 0; i < len(v); i++ {
			if v[i].nextHopIpType != routeReachabilityStatusInfo.ipType {
				logger.Debug("Skipping nexthop:", v[i].nextHopIp.String(), " since the nextHopIpType ", v[i].nextHopIpType, " not the same as ipType:", routeReachabilityStatusInfo.ipType)
				continue
			}
			vPrefix, err := getNetowrkPrefixFromStrings(v[i].nextHopIp.String(), ipMaskStr)
			if err != nil {
				logger.Err("Error getting ip prefix for v[i].nextHopIp:", v[i].nextHopIp.String(), " mask:", ipMaskStr)
				return err
			}
			nextHopIntf := ribdInt.NextHopInfo{
				NextHopIp:      v[i].nextHopIp.String(),
				NextHopIfIndex: ribdInt.Int(v[i].nextHopIfIndex),
			}
			//is the next hop same as the modified route
			if bytes.Equal(vPrefix, destIpPrefix) {
				if routeReachabilityStatusInfo.status == "Down" && v[i].resolvedNextHopIpIntf.IsReachable == true {
					v[i].resolvedNextHopIpIntf.IsReachable = false
					rmapInfoRecordList.routeInfoProtocolMap[k] = v
					V4RouteInfoMap.Set(prefix, rmapInfoRecordList)
					//logger.Debug("Adding to DBRouteCh from updateRouteReachability case 1")
					RouteServiceHandler.DBRouteCh <- RIBdServerConfig{
						OrigConfigObject: RouteDBInfo{v[i], rmapInfoRecordList},
						Op:               "add",
					}
					//RouteServiceHandler.WriteIPv4RouteStateEntryToDB(RouteDBInfo{v[i], rmapInfoRecordList})
					//logger.Debug("Bringing down route : ip: ", v[i].networkAddr)
					RouteReachabilityStatusUpdate(k, RouteReachabilityStatusInfo{v[i].networkAddr, "Down", k, nextHopIntf})
					/*
					   The reachability status for this network has been updated, now check if there are routes dependent on
					   this prefix and call reachability status
					*/
					if RouteServiceHandler.NextHopInfoMap[NextHopInfoKey{string(prefix)}].refCount > 0 {
						//logger.Debug("There are dependent routes for this ip ", v[i].networkAddr)
						V4RouteInfoMap.VisitAndUpdate(UpdateRouteReachabilityStatus, RouteReachabilityStatusInfo{v[i].networkAddr, "Down", k, nextHopIntf})
					}
				} else if routeReachabilityStatusInfo.status == "Up" && v[i].resolvedNextHopIpIntf.IsReachable == false {
					//logger.Debug("Bringing up route : ip: ", v[i].networkAddr)
					v[i].resolvedNextHopIpIntf.IsReachable = true
					rmapInfoRecordList.routeInfoProtocolMap[k] = v
					V4RouteInfoMap.Set(prefix, rmapInfoRecordList)
					//logger.Debug("Adding to DBRouteCh from updateRouteReachability case 2")
					RouteServiceHandler.DBRouteCh <- RIBdServerConfig{
						OrigConfigObject: RouteDBInfo{v[i], rmapInfoRecordList},
						Op:               "add",
					}
					//RouteServiceHandler.WriteIPv4RouteStateEntryToDB(RouteDBInfo{v[i], rmapInfoRecordList})
					RouteReachabilityStatusUpdate(k, RouteReachabilityStatusInfo{v[i].networkAddr, "Up", k, nextHopIntf})
					/*
					   The reachability status for this network has been updated, now check if there are routes dependent on
					   this prefix and call reachability status
					*/
					if RouteServiceHandler.NextHopInfoMap[NextHopInfoKey{string(prefix)}].refCount > 0 {
						//logger.Debug("There are dependent routes for this ip ", v[i].networkAddr)
						V4RouteInfoMap.VisitAndUpdate(UpdateRouteReachabilityStatus, RouteReachabilityStatusInfo{v[i].networkAddr, "Up", k, nextHopIntf})
					}
				}
			}
		}
	}
	return err
}

/*
    This function performs config parameters validation for Route update operation.
	Key validations performed by this fucntion include:
	   - Validate destinationNw. If provided in CIDR notation, convert to ip addr and mask values
*/
func (m RIBDServer) RouteConfigValidationCheckForUpdate(oldcfg *ribd.IPv4Route, cfg *ribd.IPv4Route, attrset []bool) (err error) {
	//logger.Info("RouteConfigValidationCheckForUpdate")
	isCidr := strings.Contains(cfg.DestinationNw, "/")
	if isCidr {
		/*
		   the given address is in CIDR format
		*/
		ip, ipNet, err := net.ParseCIDR(cfg.DestinationNw)
		if err != nil {
			logger.Err("Invalid Destination IP address")
			return errors.New("Invalid Desitnation IP address")
		}
		_, err = getNetworkPrefixFromCIDR(cfg.DestinationNw)
		if err != nil {
			return errors.New("Invalid destination ip/network Mask")
		}
		cfg.DestinationNw = ip.String()
		oldcfg.DestinationNw = ip.String()
		ipMask := make(net.IP, 4)
		copy(ipMask, ipNet.Mask)
		ipMaskStr := net.IP(ipMask).String()
		cfg.NetworkMask = ipMaskStr
		oldcfg.NetworkMask = ipMaskStr
	}
	_, err = validateNetworkPrefix(cfg.DestinationNw, cfg.NetworkMask)
	if err != nil {
		logger.Err(" getNetowrkPrefixFromStrings returned err ", err)
		return errors.New("Invalid destination ip address")
	}
	/*
		    Default operation for update function is to update route Info. The following
			logic deals with updating route attributes
	*/
	if attrset != nil {
		//logger.Debug("attr set not nil, set individual attributes")
		objTyp := reflect.TypeOf(*cfg)
		for i := 0; i < objTyp.NumField(); i++ {
			objName := objTyp.Field(i).Name
			if attrset[i] {
				//logger.Debug("ProcessRouteUpdateConfig (server): changed ", objName)
				if objName == "Protocol" {
					/*
					   Updating route protocol type is not allowed
					*/
					logger.Err("Cannot update Protocol value of a route")
					return errors.New("Cannot set Protocol field")
				}
				if objName == "NextHop" {
					/*
					   Next hop info is being updated
					*/
					if len(cfg.NextHop) == 0 {
						/*
						   Expects non-zero nexthop info
						*/
						logger.Err("Must specify next hop")
						return errors.New("Next hop ip not specified")
					}
					/*
					   Check if next hop IP is valid
					*/
					for i := 0; i < len(cfg.NextHop); i++ {
						_, err = getIP(cfg.NextHop[i].NextHopIp)
						if err != nil {
							logger.Err("nextHopIpAddr invalid")
							return errors.New("Invalid next hop ip address")
						}
						/*
						   Check if next hop intf is valid L3 interface
						*/
						if cfg.NextHop[i].NextHopIntRef != "" {
							//logger.Debug("IntRef before : ", cfg.NextHop[i].NextHopIntRef)
							cfg.NextHop[i].NextHopIntRef, err = m.ConvertIntfStrToIfIndexStr(cfg.NextHop[i].NextHopIntRef)
							if err != nil {
								logger.Err("Invalid NextHop IntRef ", cfg.NextHop[i].NextHopIntRef)
								return errors.New("Invalid Nexthop Intref")
							}
							//logger.Debug("IntRef after : ", cfg.NextHop[0].NextHopIntRef)
						} else {
							if len(oldcfg.NextHop) == 0 || len(oldcfg.NextHop) < i {
								logger.Err("Number of nextHops for old cfg < new cfg")
								return errors.New("number of nexthops not correct for update replace operation")
							}
							//logger.Debug("IntRef not provided, take the old value", oldcfg.NextHop[i].NextHopIntRef)
							cfg.NextHop[i].NextHopIntRef, err = m.ConvertIntfStrToIfIndexStr(oldcfg.NextHop[i].NextHopIntRef)
							if err != nil {
								logger.Err("Invalid NextHop IntRef ", oldcfg.NextHop[i].NextHopIntRef)
								return errors.New("Invalid Nexthop Intref")
							}
						}
					}
				}
			}
		}
	}
	return nil
}

func (m RIBDServer) RouteConfigValidationCheckForPatchUpdate(oldcfg *ribd.IPv4Route, cfg *ribd.IPv4Route, op []*ribd.PatchOpInfo) (err error) {
	//logger.Info("RouteConfigValidationCheckForPatchUpdate")
	isCidr := strings.Contains(cfg.DestinationNw, "/")
	if isCidr {
		/*
		   the given address is in CIDR format
		*/
		ip, ipNet, err := net.ParseCIDR(cfg.DestinationNw)
		if err != nil {
			logger.Err("Invalid Destination IP address")
			return errors.New("Invalid Desitnation IP address")
		}
		_, err = getNetworkPrefixFromCIDR(cfg.DestinationNw)
		if err != nil {
			return errors.New("Invalid destination ip/network Mask")
		}
		cfg.DestinationNw = ip.String()
		oldcfg.DestinationNw = ip.String()
		ipMask := make(net.IP, 4)
		copy(ipMask, ipNet.Mask)
		ipMaskStr := net.IP(ipMask).String()
		cfg.NetworkMask = ipMaskStr
		oldcfg.NetworkMask = ipMaskStr
	}
	_, err = validateNetworkPrefix(cfg.DestinationNw, cfg.NetworkMask)
	if err != nil {
		logger.Err(" getNetowrkPrefixFromStrings returned err ", err)
		return errors.New("Invalid destination ip address")
	}
	for idx := 0; idx < len(op); idx++ {
		//logger.Debug("patch update")
		switch op[idx].Path {
		case "NextHop":
			//logger.Debug("Patch update for next hop")
			if len(op[idx].Value) == 0 {
				/*
					If route update is trying to add next hop, non zero nextHop info is expected
				*/
				logger.Err("Must specify next hop")
				return errors.New("Next hop ip not specified")
			}
			//logger.Debug("value = ", op[idx].Value)
			valueObjArr := []ribd.NextHopInfo{}
			err = json.Unmarshal([]byte(op[idx].Value), &valueObjArr)
			if err != nil {
				logger.Err("error unmarshaling value:", err)
				return errors.New(fmt.Sprintln("error unmarshaling value:", err))
			}
			//logger.Debug("Number of nextHops:", len(valueObjArr))
			for _, val := range valueObjArr {
				/*
				   Check if the next hop ip valid
				*/
				//logger.Debug("nextHop info: ip - ", val.NextHopIp, " intf: ", val.NextHopIntRef, " wt:", val.Weight)
				_, err = getIP(val.NextHopIp)
				if err != nil {
					logger.Err("nextHopIpAddr invalid")
					return errors.New("Invalid next hop ip address")
				}

				switch op[idx].Op {
				case "add":
					/*
					   Check if the next hop ref is valid L3 interface for add operation
					*/
					//logger.Debug("IntRef before : ", val.NextHopIntRef)
					val.NextHopIntRef, err = m.ConvertIntfStrToIfIndexStr(val.NextHopIntRef)
					if err != nil {
						logger.Err("Invalid NextHop IntRef ", val.NextHopIntRef)
						return errors.New("Invalid NextHop Intref")
					}
					//logger.Debug("IntRef after : ", val.NextHopIntRef)
				case "remove":
					//logger.Debug("remove op"))
				default:
					//logger.Err("operation ", op[idx].Op, " not supported")
					return errors.New(fmt.Sprintln("operation ", op[idx].Op, " not supported"))
				}
			}
		default:
			logger.Err("Patch update for attribute:", op[idx].Path, " not supported")
			return errors.New("Invalid attribute for patch update")
		}
	}

	return nil
}

/*
    This function performs config parameters validation for op = "add" and "del" values.
	Key validations performed by this fucntion include:
	   - if the Protocol specified is valid (STATIC/CONNECTED/EBGP/OSPF)
	   - Validate destinationNw. If provided in CIDR notation, convert to ip addr and mask values
	   - In case of op == "del", check if the route is present in the DB
	   - for each of the nextHop info, check:
	       - if the next hop ip is valid
		   - if the nexthopIntf is valid L3 intf and if so, convert to string value
*/
func (m RIBDServer) RouteConfigValidationCheck(cfg *ribd.IPv4Route, op string) (err error) {
	logger.Debug("RouteConfigValidationCheck")
	isCidr := strings.Contains(cfg.DestinationNw, "/")
	if isCidr {
		/*
		   the given address is in CIDR format
		*/
		ip, ipNet, err := net.ParseCIDR(cfg.DestinationNw)
		if err != nil {
			logger.Err("Invalid Destination IP address")
			return errors.New("Invalid Desitnation IP address")
		}
		_, err = getNetworkPrefixFromCIDR(cfg.DestinationNw)
		if err != nil {
			return errors.New("Invalid destination ip/network Mask")
		}
		/*
		   Convert the CIDR format address to IP and mask strings
		*/
		cfg.DestinationNw = ip.String()
		ipMask := make(net.IP, 4)
		copy(ipMask, ipNet.Mask)
		ipMaskStr := net.IP(ipMask).String()
		cfg.NetworkMask = ipMaskStr
		/*
			In case where user provides CIDR address, the DB cannot verify if the route is present, so check here
		*/
		if m.DbHdl != nil {
			var dbObjCfg objects.IPv4Route
			dbObjCfg.DestinationNw = cfg.DestinationNw
			dbObjCfg.NetworkMask = cfg.NetworkMask
			key := "IPv4Route#" + cfg.DestinationNw + "#" + cfg.NetworkMask
			_, err := m.DbHdl.GetObjectFromDb(dbObjCfg, key)
			if err == nil {
				logger.Err("Duplicate entry")
				return errors.New("Duplicate entry")
			}
		}
	}
	_, err = validateNetworkPrefix(cfg.DestinationNw, cfg.NetworkMask)
	if err != nil {
		logger.Err(" getNetowrkPrefixFromStrings returned err ", err)
		return err
	}
	/*
	   op is to add new route
	*/
	if op == "add" {
		/*
		   check if route protocol type is valid
		*/
		_, ok := RouteProtocolTypeMapDB[cfg.Protocol]
		if !ok {
			logger.Err("route type ", cfg.Protocol, " invalid")
			err = errors.New("Invalid route protocol type")
			return err
		}
		//logger.Debug("Number of nexthops = ", len(cfg.NextHop))
		if len(cfg.NextHop) == 0 {
			/*
				Expects non-zero nexthop info
			*/
			logger.Err("Must specify next hop")
			return errors.New("Next hop ip not specified")
		}
		for i := 0; i < len(cfg.NextHop); i++ {
			/*
			   Check if the NextHop IP valid
			*/
			_, err = getIP(cfg.NextHop[i].NextHopIp)
			if err != nil {
				logger.Err("nextHopIpAddr invalid")
				return errors.New("Invalid next hop ip address")
			}
			//logger.Debug("IntRef before : ", cfg.NextHop[i].NextHopIntRef)
			/*
			   Validate if nextHopIntRef is a valid L3 interface
			*/
			if cfg.NextHop[i].NextHopIntRef == "" {
				logger.Info("NextHopIntRef not set")
				nhIntf, err := RouteServiceHandler.GetRouteReachabilityInfo(cfg.NextHop[i].NextHopIp)
				if err != nil {
					logger.Err("next hop ip ", cfg.NextHop[i].NextHopIp, " not reachable")
					return errors.New(fmt.Sprintln("next hop ip ", cfg.NextHop[i].NextHopIp, " not reachable"))
				}
				cfg.NextHop[i].NextHopIntRef = strconv.Itoa(int(nhIntf.NextHopIfIndex))
			} else {
				cfg.NextHop[i].NextHopIntRef, err = m.ConvertIntfStrToIfIndexStr(cfg.NextHop[i].NextHopIntRef)
				if err != nil {
					logger.Err("Invalid NextHop IntRef ", cfg.NextHop[i].NextHopIntRef)
					return err
				}
			}
			//logger.Debug("IntRef after : ", cfg.NextHop[i].NextHopIntRef)
		}
	}
	return nil
}

func (m RIBDServer) GetBulkIPv4EventState(fromIndex ribd.Int, rcount ribd.Int) (events *ribd.IPv4EventStateGetInfo, err error) {
	//logger.Debug("GetBulkIPv4EventState")
	var i, validCount, toIndex ribd.Int
	var tempNode []ribd.IPv4EventState = make([]ribd.IPv4EventState, rcount)
	var nextNode *ribd.IPv4EventState
	var returnNodes []*ribd.IPv4EventState
	var returnGetInfo ribd.IPv4EventStateGetInfo
	i = 0
	events = &returnGetInfo
	more := true
	if localRouteEventsDB == nil {
		//logger.Debug("localRouteEventsDB not initialized")
		return events, err
	}
	for ; ; i++ {
		if i+fromIndex >= ribd.Int(len(localRouteEventsDB)) {
			//logger.Debug("All the events fetched")
			more = false
			break
		}
		if validCount == rcount {
			//logger.Debug("Enough events fetched")
			break
		}
		//logger.Debug("Fetching event record for index ", i+fromIndex)
		nextNode = &tempNode[validCount]
		nextNode.TimeStamp = localRouteEventsDB[i+fromIndex].timeStamp
		nextNode.EventInfo = localRouteEventsDB[i+fromIndex].eventInfo
		toIndex = ribd.Int(i + fromIndex)
		if len(returnNodes) == 0 {
			returnNodes = make([]*ribd.IPv4EventState, 0)
		}
		returnNodes = append(returnNodes, nextNode)
		validCount++
	}
	//logger.Debug(fmt.Sprintf("Returning ", validCount, " list of events"))
	events.IPv4EventStateList = returnNodes
	events.StartIdx = fromIndex
	events.EndIdx = toIndex + 1
	events.More = more
	events.Count = validCount
	return events, err
}

func (m RIBDServer) GetBulkIPv4RouteState(fromIndex ribd.Int, rcount ribd.Int) (routes *ribd.IPv4RouteStateGetInfo, err error) { //(routes []*ribdInt.Routes, err error) {
	//logger.Debug("GetBulkIPv4RouteState")
	var i, validCount ribd.Int
	var toIndex ribd.Int
	var temproute []ribd.IPv4RouteState = make([]ribd.IPv4RouteState, rcount)
	var nextRoute *ribd.IPv4RouteState
	var returnRoutes []*ribd.IPv4RouteState
	var returnRouteGetInfo ribd.IPv4RouteStateGetInfo
	var prefixNodeRouteList RouteInfoRecordList
	var prefixNodeRoute RouteInfoRecord
	i = 0
	sel := 0
	found := false
	routes = &returnRouteGetInfo
	moreRoutes := true
	if destNetSlice == nil {
		//logger.Debug("destNetSlice not initialized: No Routes installed in RIB")
		return routes, err
	}
	for ; ; i++ {
		found = false
		if i+fromIndex >= ribd.Int(len(destNetSlice)) {
			//logger.Debug("All the routes fetched")
			moreRoutes = false
			break
		}
		/*		if destNetSlice[i+fromIndex].isValid == false {
				//logger.Debug("Invalid route")
				continue
			}*/
		if validCount == rcount {
			//logger.Debug("Enough routes fetched")
			break
		}
		prefixNode := RouteInfoMap.Get(destNetSlice[i+fromIndex].prefix)
		if prefixNode != nil {
			prefixNodeRouteList = prefixNode.(RouteInfoRecordList)
			if prefixNodeRouteList.isPolicyBasedStateValid == false {
				continue
			}
			//logger.Debug("selectedRouteProtocol = ", prefixNodeRouteList.selectedRouteProtocol)
			if prefixNodeRouteList.routeInfoProtocolMap == nil || prefixNodeRouteList.selectedRouteProtocol == "INVALID" || prefixNodeRouteList.routeInfoProtocolMap[prefixNodeRouteList.selectedRouteProtocol] == nil {
				//logger.Debug("selected route not valid")
				continue
			}
			routeInfoList := prefixNodeRouteList.routeInfoProtocolMap[prefixNodeRouteList.selectedRouteProtocol]
			for sel = 0; sel < len(routeInfoList); sel++ {
				if routeInfoList[sel].nextHopIp.String() == destNetSlice[i+fromIndex].nextHopIp {
					//logger.Debug("Found the entry corresponding to the nextHop ip")
					found = true
					break
				}
			}
			if !found {
				//logger.Debug("The corresponding route with nextHopIP was not found in the record DB")
				continue
			}
			prefixNodeRoute = routeInfoList[sel] //prefixNodeRouteList.routeInfoList[prefixNodeRouteList.selectedRouteIdx]
			nextRoute = &temproute[validCount]
			nextRoute.DestinationNw = prefixNodeRoute.networkAddr
			nextRoute.RouteCreatedTime = prefixNodeRoute.routeCreatedTime
			nextRoute.RouteUpdatedTime = prefixNodeRoute.routeUpdatedTime
			nextRoute.IsNetworkReachable = prefixNodeRoute.resolvedNextHopIpIntf.IsReachable
			nextRoute.PolicyList = make([]string, 0)
			routePolicyListInfo := ""
			if prefixNodeRouteList.policyList != nil {
				for k := 0; k < len(prefixNodeRouteList.policyList); k++ {
					routePolicyListInfo = "policy " + prefixNodeRouteList.policyList[k] + "["
					policyRouteIndex := PolicyRouteIndex{destNetIP: prefixNodeRoute.networkAddr, policy: prefixNodeRouteList.policyList[k]}
					policyStmtMap, ok := PolicyEngineDB.PolicyEntityMap[policyRouteIndex]
					if !ok || policyStmtMap.PolicyStmtMap == nil {
						continue
					}
					routePolicyListInfo = routePolicyListInfo + " stmtlist[["
					for stmt, conditionsAndActionsList := range policyStmtMap.PolicyStmtMap {
						routePolicyListInfo = routePolicyListInfo + stmt + ":[conditions:"
						for c := 0; c < len(conditionsAndActionsList.ConditionList); c++ {
							routePolicyListInfo = routePolicyListInfo + conditionsAndActionsList.ConditionList[c].Name + ","
						}
						routePolicyListInfo = routePolicyListInfo + "],[actions:"
						for a := 0; a < len(conditionsAndActionsList.ActionList); a++ {
							routePolicyListInfo = routePolicyListInfo + conditionsAndActionsList.ActionList[a].Name + ","
						}
						routePolicyListInfo = routePolicyListInfo + "]]"
					}
					routePolicyListInfo = routePolicyListInfo + "]"
					nextRoute.PolicyList = append(nextRoute.PolicyList, routePolicyListInfo)
				}
			}
			toIndex = ribd.Int(i + fromIndex)
			if len(returnRoutes) == 0 {
				returnRoutes = make([]*ribd.IPv4RouteState, 0)
			}
			returnRoutes = append(returnRoutes, nextRoute)
			validCount++
		}
	}
	routes.IPv4RouteStateList = returnRoutes
	routes.StartIdx = fromIndex
	routes.EndIdx = toIndex + 1
	routes.More = moreRoutes
	routes.Count = validCount
	return routes, err
}

func (m RIBDServer) Getv4Route(destNetIp string) (route *ribdInt.IPv4RouteState, err error) {
	var returnRoute ribdInt.IPv4RouteState
	route = &returnRoute
	/*
	   the given address is in CIDR format
	*/
	destNet, err := getNetworkPrefixFromCIDR(destNetIp)
	if err != nil {
		return route, errors.New("Invalid destination ip/network Mask")
	}
	routeInfoRecordListItem := RouteInfoMap.Get(destNet)
	if routeInfoRecordListItem == nil {
		logger.Err("No such route")
		err = errors.New("Route does not exist")
		return route, err
	}
	routeInfoRecordList := routeInfoRecordListItem.(RouteInfoRecordList) //RouteInfoMap.Get(destNet).(RouteInfoRecordList)
	if routeInfoRecordList.selectedRouteProtocol == "INVALID" {
		logger.Err("No selected route for this network")
		err = errors.New("No selected route for this network")
		return route, err
	}
	routeInfoList := routeInfoRecordList.routeInfoProtocolMap[routeInfoRecordList.selectedRouteProtocol]
	nextHopInfo := make([]ribdInt.RouteNextHopInfo, len(routeInfoList))
	route.NextHopList = make([]*ribdInt.RouteNextHopInfo, 0)
	i := 0
	for _, nh := range routeInfoList {
		routeInfoRecord := nh
		nextHopInfo[i].NextHopIp = routeInfoRecord.nextHopIp.String()
		nextHopInfo[i].NextHopIntRef = strconv.Itoa(int(routeInfoRecord.nextHopIfIndex))
		intfEntry, ok := IntfIdNameMap[int32(routeInfoRecord.nextHopIfIndex)]
		if ok {
			//logger.Debug("Map found for ifndex : ", routeInfoRecord.nextHopIfIndex, "Name = ", intfEntry.name)
			nextHopInfo[i].NextHopIntRef = intfEntry.name
		}
		//logger.Debug("IntfRef = ", nextHopInfo[i].NextHopIntRef)
		nextHopInfo[i].Weight = int32(routeInfoRecord.weight)
		route.NextHopList = append(route.NextHopList, &nextHopInfo[i])
		i++

	}
	routeInfoRecord := routeInfoList[0]
	route.DestinationNw = routeInfoRecord.networkAddr
	route.Protocol = routeInfoRecordList.selectedRouteProtocol
	route.RouteCreatedTime = routeInfoRecord.routeCreatedTime
	route.RouteUpdatedTime = routeInfoRecord.routeUpdatedTime
	return route, err
}
func (m RIBDServer) GetTotalv4RouteCount() (number int, err error) {
	return v4rtCount, err
}
func (m RIBDServer) Getv4RouteCreatedTime(number int) (time string, err error) {
	_, ok := v4routeCreatedTimeMap[number]
	if !ok {
		logger.Info(number, " number of  v4 routes not created yet")
		return "", errors.New("Not enough v4 routes")
	}
	return v4routeCreatedTimeMap[number], err
}

/**
   This function is called when :
 - a user/routing protocol installs a new route. In that case, addType will be RIBAndFIB
 - when a operationally down link comes up. In this case, the addType will be FIBOnly because on a link down, the route is still preserved in the RIB database and only deleted from FIB (Asic)
**/
func createV4Route(routeInfo RouteParams) (rc ribd.Int, err error) {

	ipType := routeInfo.ipType
	destNetIp := routeInfo.destNetIp
	networkMask := routeInfo.networkMask
	metric := routeInfo.metric
	weight := routeInfo.weight
	nextHopIp := routeInfo.nextHopIp
	nextHopIfIndex := routeInfo.nextHopIfIndex
	routeType := routeInfo.routeType
	addType := routeInfo.createType
	policyStateChange := ribdCommonDefs.RoutePolicyStateChangetoValid
	sliceIdx := routeInfo.sliceIdx
	callSelectRoute := false
	destNetIpAddr, err := getIP(destNetIp)
	if err != nil {
		logger.Err("destNetIpAddr invalid")
		return 0, err
	}
	networkMaskAddr, err := getIP(networkMask)
	if err != nil {
		logger.Err("networkMaskAddr invalid")
		return 0, err
	}
	nextHopIpAddr, err := getIP(nextHopIp)
	if err != nil {
		logger.Err("nextHopIpAddr invalid")
		return 0, err
	}
	nextHopIpType := ribdCommonDefs.IPv4
	nextHopIpNet := nextHopIpAddr.To4()
	if nextHopIpNet == nil {
		nextHopIpType = ribdCommonDefs.IPv6
	}
	destNet, nwAddr, err := getNetworkPrefix(destNetIpAddr, networkMaskAddr)
	if err != nil {
		return -1, err
	}
	routePrototype := int8(routeType)
	//nwAddr := (destNetIpAddr.Mask(net.IPMask(networkMaskAddr))).String() + "/" + strconv.Itoa(prefixLen)
	routeInfoRecord := RouteInfoRecord{
		ipType:         ipType,
		destNetIp:      destNetIpAddr,
		networkMask:    networkMaskAddr,
		protocol:       routePrototype,
		nextHopIpType:  nextHopIpType,
		nextHopIp:      nextHopIpAddr,
		networkAddr:    nwAddr,
		nextHopIfIndex: nextHopIfIndex,
		metric:         metric,
		sliceIdx:       int(sliceIdx),
		weight:         weight,
	}

	policyRoute := ribdInt.Routes{Ipaddr: destNetIp, Mask: networkMask, NextHopIp: nextHopIp, IfIndex: ribdInt.Int(nextHopIfIndex), Metric: ribdInt.Int(metric), Prototype: ribdInt.Int(routeType), Weight: ribdInt.Int(weight)}
	routeInfoRecord.resolvedNextHopIpIntf.NextHopIp = routeInfoRecord.nextHopIp.String()
	routeInfoRecord.resolvedNextHopIpIntf.NextHopIfIndex = ribdInt.Int(routeInfoRecord.nextHopIfIndex)

	nhIntf, resolvedNextHopIntf, res_err := ResolveNextHop(routeInfoRecord.nextHopIp.String())
	//_, resolvedNextHopIntf, _ := ResolveNextHop(routeInfoRecord.nextHopIp.String())
	routeInfoRecord.resolvedNextHopIpIntf = resolvedNextHopIntf
	//logger.Info("nhIntf ipaddr/mask: ", nhIntf.Ipaddr, ":", nhIntf.Mask, " resolvedNex ", resolvedNextHopIntf.NextHopIp, " nexthop ", nextHopIp, " reachable:", resolvedNextHopIntf.IsReachable)

	routeInfoRecord.routeCreatedTime = time.Now().String()
	v4rtCount++
	v4routeCreatedTimeMap[v4rtCount] = routeInfoRecord.routeCreatedTime
	routeInfoRecordListItem := V4RouteInfoMap.Get(destNet)
	if routeInfoRecordListItem == nil {
		/*
		   no routes for this destination are currently configured
		*/
		if addType == FIBOnly {
			logger.Debug("route record list not found in RIB")
			err = errors.New("Unexpected: route record list not found in RIB")
			return 0, err
		}
		var newRouteInfoRecordList RouteInfoRecordList
		newRouteInfoRecordList.routeInfoProtocolMap = make(map[string][]RouteInfoRecord)
		newRouteInfoRecordList.routeInfoProtocolMap[ReverseRouteProtoTypeMapDB[int(routeType)]] = make([]RouteInfoRecord, 0)
		newRouteInfoRecordList.routeInfoProtocolMap[ReverseRouteProtoTypeMapDB[int(routeType)]] = append(newRouteInfoRecordList.routeInfoProtocolMap[ReverseRouteProtoTypeMapDB[int(routeType)]], routeInfoRecord)
		newRouteInfoRecordList.selectedRouteProtocol = ReverseRouteProtoTypeMapDB[int(routeType)]

		if policyStateChange == ribdCommonDefs.RoutePolicyStateChangetoInValid {
			newRouteInfoRecordList.isPolicyBasedStateValid = false
		} else if policyStateChange == ribdCommonDefs.RoutePolicyStateChangetoValid {
			newRouteInfoRecordList.isPolicyBasedStateValid = true
		}
		if ok := V4RouteInfoMap.Insert(destNet, newRouteInfoRecordList); ok != true {
			logger.Err("Route map insert return value not ok")
			return 0, err
		}
		UpdateProtocolRouteMap(ReverseRouteProtoTypeMapDB[int(routeType)], "add", string(destNet))
		localDBRecord := localDB{prefix: destNet, isValid: true, nextHopIp: nextHopIp}
		if destNetSlice == nil {
			destNetSlice = make([]localDB, 0)
		}
		destNetSlice = append(destNetSlice, localDBRecord)
		//call asicd
		//		if asicdclnt.IsConnected {
		//logger.Debug("New route selected, call asicd to install a new route - ip", routeInfoRecord.destNetIp.String(), " mask ", routeInfoRecord.networkMask.String(), " nextHopIP ", routeInfoRecord.resolvedNextHopIpIntf.NextHopIp)
		RouteServiceHandler.AsicdRouteCh <- RIBdServerConfig{OrigConfigObject: routeInfoRecord, Op: "add", Bulk: routeInfo.bulk, BulkEnd: routeInfo.bulkEnd}
		//		}
		//if arpdclnt.IsConnected &&
		if routeInfoRecord.protocol != ribdCommonDefs.CONNECTED {
			if !arpResolveCalled(NextHopInfoKey{routeInfoRecord.resolvedNextHopIpIntf.NextHopIp}) {
				//call arpd to resolve the ip
				//logger.Debug("Adding ", routeInfoRecord.resolvedNextHopIpIntf.NextHopIp, " to ArpdRouteCh")
				RouteServiceHandler.ArpdRouteCh <- RIBdServerConfig{OrigConfigObject: routeInfoRecord, Op: "add"}
			}
			//update the ref count for the resolved next hop ip
			updateNextHopMap(NextHopInfoKey{routeInfoRecord.resolvedNextHopIpIntf.NextHopIp}, add)
		}
		//logger.Debug("Adding to DBRouteCh from createv4Route")
		RouteServiceHandler.DBRouteCh <- RIBdServerConfig{
			OrigConfigObject: RouteDBInfo{routeInfoRecord, newRouteInfoRecordList},
			Op:               "add",
		}
		//update in the event log
		eventInfo := "Installed " + ReverseRouteProtoTypeMapDB[int(policyRoute.Prototype)] + " route " + policyRoute.Ipaddr + ":" + policyRoute.Mask + " nextHopIp :" + routeInfoRecord.nextHopIp.String() + " in Hardware and RIB "
		routeEventInfo := RouteEventInfo{timeStamp: routeInfoRecord.routeCreatedTime, eventInfo: eventInfo}
		localRouteEventsDB = append(localRouteEventsDB, routeEventInfo)

		//update the ref count for the next hop ip
		if res_err == nil {
			nhPrefix, err := getNetowrkPrefixFromStrings(nhIntf.Ipaddr, nhIntf.Mask)
			if err == nil {
				//logger.Debug("network address of the nh route: ", nhPrefix)
				updateNextHopMap(NextHopInfoKey{string(nhPrefix)}, add)
			}
		}
		if routeInfoRecord.resolvedNextHopIpIntf.IsReachable {
			//logger.Debug(("Mark this network reachable"))
			nextHopIntf := ribdInt.NextHopInfo{
				NextHopIp:      routeInfoRecord.nextHopIp.String(),
				NextHopIfIndex: ribdInt.Int(routeInfoRecord.nextHopIfIndex),
			}
			if RouteServiceHandler.NextHopInfoMap[NextHopInfoKey{string(destNet)}].refCount > 0 {
				routeReachabilityStatusInfo := RouteReachabilityStatusInfo{routeInfoRecord.networkAddr, "Up", ReverseRouteProtoTypeMapDB[int(routeInfoRecord.protocol)], nextHopIntf}
				RouteReachabilityStatusUpdate(routeReachabilityStatusInfo.protocol, routeReachabilityStatusInfo)
				//If there are dependent routes for this ip, then bring them up
				V4RouteInfoMap.VisitAndUpdate(UpdateV4RouteReachabilityStatus, routeReachabilityStatusInfo)
			}
		}
		var params RouteParams
		params = BuildRouteParamsFromRouteInoRecord(routeInfoRecord)
		params.createType = addType
		params.deleteType = Invalid
		policyRoute.IsPolicyBasedStateValid = newRouteInfoRecordList.isPolicyBasedStateValid
		PolicyEngineFilter(policyRoute, policyCommonDefs.PolicyPath_Export, params)
	} else {
		logger.Debug("routeInfoRecordListItem not nil")
		routeInfoRecordList := routeInfoRecordListItem.(RouteInfoRecordList) //RouteInfoMap.Get(destNet).(RouteInfoRecordList)
		found := IsRoutePresent(routeInfoRecordList, ReverseRouteProtoTypeMapDB[int(routeType)])
		if found && (addType == FIBAndRIB) {
			routeInfoList := routeInfoRecordList.routeInfoProtocolMap[ReverseRouteProtoTypeMapDB[int(routePrototype)]]
			logger.Debug("Trying to create a duplicate route of protocol type ", ReverseRouteProtoTypeMapDB[int(routePrototype)])
			if routeInfoList[0].metric > metric {
				callSelectRoute = true
			} else if routeInfoList[0].metric == metric {
				if !newNextHopIP(nextHopIpType, nextHopIp, routeInfoList) {
					logger.Debug("same cost and next hop ip, so reject this route")
					err = errors.New("Duplicate route creation")
					return 0, err
				}
				//adding equal cost route
				logger.Debug("Adding a equal cost route for the selected route")
				callSelectRoute = true
				//}
			} else { //if metric > routeInfoRecordList.routeInfoList[idx].metric
				logger.Debug("Duplicate route creation with higher cost, rejecting the route")
				err = errors.New("Duplicate route creation with higher cost, rejecting the route")
				return 0, err
			}
		} else if !found {
			if addType != FIBOnly {
				callSelectRoute = true
			}
		} else {
			callSelectRoute = true
		}
		if policyStateChange == ribdCommonDefs.RoutePolicyStateChangetoInValid {
			routeInfoRecordList.isPolicyBasedStateValid = false
		} else if policyStateChange == ribdCommonDefs.RoutePolicyStateChangetoValid {
			routeInfoRecordList.isPolicyBasedStateValid = true
		}
		if callSelectRoute {
			err = SelectRoute(destNet, routeInfoRecordList, routeInfoRecord, add, int(addType)) //, len(routeInfoRecordList.routeInfoList)-1)
		}
	}
	if addType != FIBOnly && routePrototype == ribdCommonDefs.CONNECTED { //PROTOCOL_CONNECTED {
		updateConnectedRoutes(destNetIp, networkMask, nextHopIp, nextHopIfIndex, add, sliceIdx)
	}
	return 0, err

}

func (m RIBDServer) ProcessV4RouteCreateConfig(cfg *ribd.IPv4Route) (val bool, err error) {
	logger.Debug("ProcessRouteCreateConfig: Received create route request for ip ", cfg.DestinationNw, " mask ", cfg.NetworkMask, " number of next hops: ", len(cfg.NextHop))
	newCfg := ribd.IPv4Route{
		DestinationNw: cfg.DestinationNw,
		NetworkMask:   cfg.NetworkMask,
		Protocol:      cfg.Protocol,
		Cost:          cfg.Cost,
		NullRoute:     cfg.NullRoute,
	}
	for i := 0; i < len(cfg.NextHop); i++ {
		logger.Debug("nexthop info: ip: ", cfg.NextHop[i].NextHopIp, " intref: ", cfg.NextHop[i].NextHopIntRef)
		nh := ribd.NextHopInfo{
			NextHopIp:     cfg.NextHop[i].NextHopIp,
			NextHopIntRef: cfg.NextHop[i].NextHopIntRef,
			Weight:        cfg.NextHop[i].Weight,
		}
		newCfg.NextHop = make([]*ribd.NextHopInfo, 0)
		newCfg.NextHop = append(newCfg.NextHop, &nh)
		//policyRoute := BuildPolicyRouteFromribdIPv4Route(&newCfg)
		params := BuildRouteParamsFromribdIPv4Route(&newCfg, FIBAndRIB, Invalid, len(destNetSlice))
		_, err = createV4Route(params)
		//PolicyEngineFilter(policyRoute, policyCommonDefs.PolicyPath_Import, params)
		//policyEngineActionAcceptRoute(params)
		/*		nextHopIp := newCfg.NextHop[0].NextHopIp
				if cfg.NullRoute == true { //commonDefs.IfTypeNull {
					//logger.Info("null route create request")
					nextHopIp = "255.255.255.255"
				}
				nextHopIntRef, _ := strconv.Atoi(newCfg.NextHop[0].NextHopIntRef)
				_, err = createRoute(ipv4,
					newCfg.DestinationNw,
					newCfg.NetworkMask,
					ribd.Int(cfg.Cost),
					ribd.Int(newCfg.NextHop[0].Weight),
					nextHopIp,
					ribd.Int(nextHopIntRef),
					ribd.Int(RouteProtocolTypeMapDB[newCfg.Protocol]),
					FIBAndRIB,
					ribdCommonDefs.RoutePolicyStateChangetoValid,
					ribd.Int(len(destNetSlice)))*/

	}

	return true, err
}

func (m RIBDServer) ProcessBulkRouteCreateConfig(bulkCfg []*ribdInt.IPv4RouteConfig) (val bool, err error) {
	logger.Debug("ProcessBulkRouteCreateConfig: Received create route request for  ", len(bulkCfg), " number of routes")
	index := 0
	for _, cfg := range bulkCfg {

		newCfg := ribd.IPv4Route{
			DestinationNw: cfg.DestinationNw,
			NetworkMask:   cfg.NetworkMask,
			Protocol:      cfg.Protocol,
			Cost:          cfg.Cost,
			NullRoute:     cfg.NullRoute,
		}
		for i := 0; i < len(cfg.NextHop); i++ {
			logger.Debug("nexthop info: ip: ", cfg.NextHop[i].NextHopIp, " intref: ", cfg.NextHop[i].NextHopIntRef)
			nh := ribd.NextHopInfo{
				NextHopIp:     cfg.NextHop[i].NextHopIp,
				NextHopIntRef: cfg.NextHop[i].NextHopIntRef,
				Weight:        cfg.NextHop[i].Weight,
			}
			newCfg.NextHop = make([]*ribd.NextHopInfo, 0)
			newCfg.NextHop = append(newCfg.NextHop, &nh)
		}

		//policyRoute := BuildPolicyRouteFromribdIPv4Route(&newCfg)
		params := BuildRouteParamsFromribdIPv4Route(&newCfg, FIBAndRIB, Invalid, len(destNetSlice))
		params.bulk = true
		index++
		if index == len(bulkCfg) {
			params.bulkEnd = true
		}
		//logger.Debug("createType = ", params.createType, "deleteType = ", params.deleteType, "index:", index, " bulk:", params.bulk, " bulkEnd:", params.bulkEnd))
		//PolicyEngineFilter(policyRoute, policyCommonDefs.PolicyPath_Import, params)
		_, err = createRoute(params)
	}

	return true, err
}

func (m RIBDServer) ProcessV4RouteDeleteConfig(cfg *ribd.IPv4Route) (val bool, err error) {
	logger.Debug("ProcessV4RouteDeleteConfig:Received Route Delete request for ", cfg.DestinationNw, ":", cfg.NetworkMask, "number of nextHops:", len(cfg.NextHop), "Protocol ", cfg.Protocol)
	if !RouteServiceHandler.AcceptConfig {
		logger.Debug("Not ready to accept config")
		//return 0,err
	}
	for i := 0; i < len(cfg.NextHop); i++ {
		logger.Debug("nexthop info: ip: ", cfg.NextHop[i].NextHopIp, " intref: ", cfg.NextHop[i].NextHopIntRef)
		_, err = deleteIPRoute(cfg.DestinationNw, cfg.NetworkMask, cfg.Protocol, cfg.NextHop[i].NextHopIp, FIBAndRIB, ribdCommonDefs.RoutePolicyStateChangetoInValid)
	}
	return true, err
}

func (m RIBDServer) Processv4RoutePatchUpdateConfig(origconfig *ribd.IPv4Route, newconfig *ribd.IPv4Route, op []*ribd.PatchOpInfo) (ret bool, err error) {
	logger.Debug("Processv4RoutePatchUpdateConfig:Received update route request with number of patch ops: ", len(op))
	if !RouteServiceHandler.AcceptConfig {
		logger.Debug("Not ready to accept config")
		//return err
	}
	destNet, err := getNetowrkPrefixFromStrings(origconfig.DestinationNw, origconfig.NetworkMask)
	if err != nil {
		logger.Err(" getNetowrkPrefixFromStrings returned err ", err)
		return ret, err
	}
	ok := RouteInfoMap.Match(destNet)
	if !ok {
		err = errors.New("No route found")
		return ret, err
	}
	for idx := 0; idx < len(op); idx++ {
		switch op[idx].Path {
		case "NextHop":
			//logger.Debug("Patch update for next hop")
			/*newconfig should only have the next hops that have to be added or deleted*/
			newconfig.NextHop = make([]*ribd.NextHopInfo, 0)
			//logger.Debug("value = ", op[idx].Value)
			valueObjArr := []ribd.NextHopInfo{}
			err = json.Unmarshal([]byte(op[idx].Value), &valueObjArr)
			if err != nil {
				//logger.Debug("error unmarshaling value:", err))
				return ret, errors.New(fmt.Sprintln("error unmarshaling value:", err))
			}
			//logger.Debug("Number of nextHops:", len(valueObjArr)))
			for _, val := range valueObjArr {
				//logger.Debug("nextHop info: ip - ", val.NextHopIp, " intf: ", val.NextHopIntRef, " wt:", val.Weight)
				//wt,_ := strconv.Atoi((op[idx].Value[j]["Weight"]))
				//logger.Debug("IntRef before : ", val.NextHopIntRef)
				val.NextHopIntRef, err = m.ConvertIntfStrToIfIndexStr(val.NextHopIntRef)
				if err != nil {
					logger.Err("Invalid NextHop IntRef ", val.NextHopIntRef)
					return ret, errors.New("Invalid NextHop Intref")
				}
				//logger.Debug("IntRef after : ", val.NextHopIntRef)
				nh := ribd.NextHopInfo{
					NextHopIp:     val.NextHopIp,
					NextHopIntRef: val.NextHopIntRef,
					Weight:        val.Weight,
				}
				newconfig.NextHop = append(newconfig.NextHop, &nh)
			}
			switch op[idx].Op {
			case "add":
				m.ProcessV4RouteCreateConfig(newconfig)
			case "remove":
				m.ProcessV4RouteDeleteConfig(newconfig)
			default:
				logger.Err("Operation ", op[idx].Op, " not supported")
			}
		default:
			logger.Err("Patch update for attribute:", op[idx].Path, " not supported")
			err = errors.New(fmt.Sprintln("Operation ", op[idx].Op, " not supported"))
		}
	}
	return ret, err
}

func (m RIBDServer) Processv4RouteUpdateConfig(origconfig *ribd.IPv4Route, newconfig *ribd.IPv4Route, attrset []bool) (val bool, err error) {
	logger.Debug("Processv4RouteUpdateConfig:Received update route request ")
	if !RouteServiceHandler.AcceptConfig {
		logger.Debug("Not ready to accept config")
		//return err
	}
	destNet, err := getNetowrkPrefixFromStrings(origconfig.DestinationNw, origconfig.NetworkMask)
	if err != nil {
		logger.Err(" getNetowrkPrefixFromStrings returned err ", err)
		return val, err
	}
	ok := RouteInfoMap.Match(destNet)
	if !ok {
		err = errors.New(fmt.Sprintln("No route found for ip ", destNet))
		return val, err
	}
	routeInfoRecordListItem := RouteInfoMap.Get(destNet)
	if routeInfoRecordListItem == nil {
		logger.Err("No route for destination network", destNet)
		return val, err
	}
	routeInfoRecordList := routeInfoRecordListItem.(RouteInfoRecordList)
	callUpdate := true
	if attrset != nil {
		found, routeInfoRecord, index := findRouteWithNextHop(routeInfoRecordList.routeInfoProtocolMap[origconfig.Protocol], origconfig.NextHop[0].NextHopIp)
		if !found || index == -1 {
			logger.Err("Invalid nextHopIP")
			return val, errors.New(fmt.Sprintln("Invalid Next Hop IP:", origconfig.NextHop[0].NextHopIp))
		}
		objTyp := reflect.TypeOf(*origconfig)
		for i := 0; i < objTyp.NumField(); i++ {
			objName := objTyp.Field(i).Name
			if attrset[i] {
				//logger.Debug(fmt.Sprintf("ProcessRouteUpdateConfig (server): changed ", objName)
				if objName == "NextHop" {
					if len(newconfig.NextHop) == 0 {
						logger.Err("Must specify next hop")
						return val, err
					} else {
						nextHopIpAddr, err := getIP(newconfig.NextHop[0].NextHopIp)
						if err != nil {
							logger.Err("nextHopIpAddr invalid")
							return val, errors.New("Invalid next hop")
						}
						//logger.Debug("Update the next hop info old ip: ", origconfig.NextHop[0].NextHopIp, " new value: ", newconfig.NextHop[0].NextHopIp, " weight : ", newconfig.NextHop[0].Weight)
						routeInfoRecord.nextHopIp = nextHopIpAddr
						routeInfoRecord.weight = ribd.Int(newconfig.NextHop[0].Weight)
						if newconfig.NextHop[0].NextHopIntRef != "" {
							nextHopIntRef, _ := strconv.Atoi(newconfig.NextHop[0].NextHopIntRef)
							routeInfoRecord.nextHopIfIndex = ribd.Int(nextHopIntRef)
						}
					}
				}
				if objName == "Cost" {
					routeInfoRecord.metric = ribd.Int(newconfig.Cost)
				}
				/*				if objName == "OutgoingInterface" {
								nextHopIfIndex, _ := strconv.Atoi(newconfig.OutgoingInterface)
								routeInfoRecord.nextHopIfIndex = ribd.Int(nextHopIfIndex)
								callUpdate = false
							}*/
			}
		}
		routeInfoRecordList.routeInfoProtocolMap[origconfig.Protocol][index] = routeInfoRecord
		RouteInfoMap.Set(destNet, routeInfoRecordList)
		//logger.Debug("Adding to DBRouteCh from processRouteUpdateConfig")
		RouteServiceHandler.DBRouteCh <- RIBdServerConfig{
			OrigConfigObject: RouteDBInfo{routeInfoRecord, routeInfoRecordList},
			Op:               "add",
		}
		if callUpdate == false {
			return val, err
		}
	}
	updateBestRoute(destNet, routeInfoRecordList)
	return val, err
}
