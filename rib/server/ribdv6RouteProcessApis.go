// ribdv6RouteProcessApis.go
package server

import (
	"fmt"
	//	"encoding/json"
	"l3/rib/ribdCommonDefs"
	"ribd"
	"utils/policy/policyCommonDefs"
	//		"patricia"
	//"asicd/asicdCommonDefs"
	"errors"
	//	"github.com/op/go-nanomsg"
	"encoding/json"
	"reflect"
	"strconv"
)

func (m RIBDServer) ProcessV6RouteCreateConfig(cfg *ribd.IPv6Route) (val bool, err error) {
	logger.Debug(fmt.Sprintln("ProcessV6RouteCreate: Received create route request for ip: ", cfg.DestinationNw, " mask ", cfg.NetworkMask, " number of next hops: ", len(cfg.NextHop)))
	newCfg := ribd.IPv6Route{
		DestinationNw: cfg.DestinationNw,
		NetworkMask:   cfg.NetworkMask,
		Protocol:      cfg.Protocol,
		Cost:          cfg.Cost,
		NullRoute:     cfg.NullRoute,
	}
	for i := 0; i < len(cfg.NextHop); i++ {
		logger.Debug(fmt.Sprintln("nexthop info: ip: ", cfg.NextHop[i].NextHopIp, " intref: ", cfg.NextHop[i].NextHopIntRef))
		nh := ribd.NextHopInfo{
			NextHopIp:     cfg.NextHop[i].NextHopIp,
			NextHopIntRef: cfg.NextHop[i].NextHopIntRef,
			Weight:        cfg.NextHop[i].Weight,
		}
		newCfg.NextHop = make([]*ribd.NextHopInfo, 0)
		newCfg.NextHop = append(newCfg.NextHop, &nh)
	}

	policyRoute := BuildPolicyRouteFromribdIPv6Route(&newCfg)
	params := BuildRouteParamsFromribdIPv6Route(&newCfg, FIBAndRIB, Invalid, len(destNetSlice))

	logger.Debug(fmt.Sprintln("createType = ", params.createType, "deleteType = ", params.deleteType))
	PolicyEngineFilter(policyRoute, policyCommonDefs.PolicyPath_Import, params)

	return true, err
}

func (m RIBDServer) ProcessV6RouteDeleteConfig(cfg *ribd.IPv6Route) (val bool, err error) {
	logger.Debug(fmt.Sprintln("ProcessRoutev6DeleteConfig:Received Route Delete request for ", cfg.DestinationNw, ":", cfg.NetworkMask, "number of nextHops:", len(cfg.NextHop), "Protocol ", cfg.Protocol))
	if !RouteServiceHandler.AcceptConfig {
		logger.Debug("Not ready to accept config")
		//return 0,err
	}
	for i := 0; i < len(cfg.NextHop); i++ {
		logger.Debug(fmt.Sprintln("nexthop info: ip: ", cfg.NextHop[i].NextHopIp, " intref: ", cfg.NextHop[i].NextHopIntRef))
		_, err = deleteIPRoute(cfg.DestinationNw, cfg.NetworkMask, cfg.Protocol, cfg.NextHop[i].NextHopIp, FIBAndRIB, ribdCommonDefs.RoutePolicyStateChangetoInValid)
	}
	return true, err
}

func (m RIBDServer) Processv6RoutePatchUpdateConfig(origconfig *ribd.IPv6Route, newconfig *ribd.IPv6Route, op []*ribd.PatchOpInfo) (ret bool, err error) {
	logger.Debug(fmt.Sprintln("Processv6RoutePatchUpdateConfig:Received update route request with number of patch ops: ", len(op)))
	if !RouteServiceHandler.AcceptConfig {
		logger.Debug("Not ready to accept config")
		//return err
	}
	destNet, err := getNetowrkPrefixFromStrings(origconfig.DestinationNw, origconfig.NetworkMask)
	if err != nil {
		logger.Debug(fmt.Sprintln(" getNetowrkPrefixFromStrings returned err ", err))
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
			logger.Debug("Patch update for next hop")
			/*newconfig should only have the next hops that have to be added or deleted*/
			newconfig.NextHop = make([]*ribd.NextHopInfo, 0)
			logger.Debug(fmt.Sprintln("value = ", op[idx].Value))
			valueObjArr := []ribd.NextHopInfo{}
			err = json.Unmarshal([]byte(op[idx].Value), &valueObjArr)
			if err != nil {
				logger.Debug(fmt.Sprintln("error unmarshaling value:", err))
				return ret, errors.New(fmt.Sprintln("error unmarshaling value:", err))
			}
			logger.Debug(fmt.Sprintln("Number of nextHops:", len(valueObjArr)))
			for _, val := range valueObjArr {
				logger.Debug(fmt.Sprintln("nextHop info: ip - ", val.NextHopIp, " intf: ", val.NextHopIntRef, " wt:", val.Weight))
				//wt,_ := strconv.Atoi((op[idx].Value[j]["Weight"]))
				logger.Debug(fmt.Sprintln("IntRef before : ", val.NextHopIntRef))
				val.NextHopIntRef, err = m.ConvertIntfStrToIfIndexStr(val.NextHopIntRef)
				if err != nil {
					logger.Err(fmt.Sprintln("Invalid NextHop IntRef ", val.NextHopIntRef))
					return ret, errors.New("Invalid NextHop Intref")
				}
				logger.Debug(fmt.Sprintln("IntRef after : ", val.NextHopIntRef))
				nh := ribd.NextHopInfo{
					NextHopIp:     val.NextHopIp,
					NextHopIntRef: val.NextHopIntRef,
					Weight:        val.Weight,
				}
				newconfig.NextHop = append(newconfig.NextHop, &nh)
			}
			switch op[idx].Op {
			case "add":
				m.ProcessV6RouteCreateConfig(newconfig)
			case "remove":
				m.ProcessV6RouteDeleteConfig(newconfig)
			default:
				logger.Err(fmt.Sprintln("Operation ", op[idx].Op, " not supported"))
			}
		default:
			logger.Err(fmt.Sprintln("Patch update for attribute:", op[idx].Path, " not supported"))
		}
	}
	return ret, err
}

func (m RIBDServer) Processv6RouteUpdateConfig(origconfig *ribd.IPv6Route, newconfig *ribd.IPv6Route, attrset []bool) (val bool, err error) {
	logger.Debug(fmt.Sprintln("Processv6RouteUpdateConfig:Received update route request "))
	if !RouteServiceHandler.AcceptConfig {
		logger.Debug("Not ready to accept config")
		//return err
	}
	destNet, err := getNetowrkPrefixFromStrings(origconfig.DestinationNw, origconfig.NetworkMask)
	if err != nil {
		logger.Debug(fmt.Sprintln(" getNetowrkPrefixFromStrings returned err ", err))
		return val, err
	}
	ok := RouteInfoMap.Match(destNet)
	if !ok {
		err = errors.New(fmt.Sprintln("No route found for ip ", destNet))
		return val, err
	}
	routeInfoRecordListItem := RouteInfoMap.Get(destNet)
	if routeInfoRecordListItem == nil {
		logger.Debug(fmt.Sprintln("No route for destination network", destNet))
		return val, err
	}
	routeInfoRecordList := routeInfoRecordListItem.(RouteInfoRecordList)
	callUpdate := true
	if attrset != nil {
		found, routeInfoRecord, index := findRouteWithNextHop(routeInfoRecordList.routeInfoProtocolMap[origconfig.Protocol], origconfig.NextHop[0].NextHopIp)
		if !found || index == -1 {
			logger.Debug("Invalid nextHopIP")
			return val, err
		}
		objTyp := reflect.TypeOf(*origconfig)
		for i := 0; i < objTyp.NumField(); i++ {
			objName := objTyp.Field(i).Name
			if attrset[i] {
				logger.Debug(fmt.Sprintf("ProcessRouteUpdateConfig (server): changed ", objName))
				if objName == "NextHop" {
					if len(newconfig.NextHop) == 0 {
						logger.Err("Must specify next hop")
						return val, err
					} else {
						nextHopIpAddr, err := getIP(newconfig.NextHop[0].NextHopIp)
						if err != nil {
							logger.Debug("nextHopIpAddr invalid")
							return val, errors.New("Invalid next hop")
						}
						logger.Debug(fmt.Sprintln("Update the next hop info old ip: ", origconfig.NextHop[0].NextHopIp, " new value: ", newconfig.NextHop[0].NextHopIp, " weight : ", newconfig.NextHop[0].Weight))
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
		logger.Debug("Adding to DBRouteCh from processRouteUpdateConfig")
		RouteServiceHandler.DBRouteCh <- RIBdServerConfig{
			OrigConfigObject: RouteDBInfo{routeInfoRecord, routeInfoRecordList},
			Op:               "add",
		}
		//RouteServiceHandler.WriteIPv4RouteStateEntryToDB(RouteDBInfo{routeInfoRecord, routeInfoRecordList})
		if callUpdate == false {
			return val, err
		}
	}
	updateBestRoute(destNet, routeInfoRecordList)
	return val, err
}
