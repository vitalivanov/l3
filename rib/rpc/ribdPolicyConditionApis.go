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

// ribdPolicyConditionApis.go
package rpc

import (
	"l3/rib/server"
	"ribd"
	"utils/policy"
)

func (m RIBDServicesHandler) CreatePolicyPrefixSet(cfg *ribd.PolicyPrefixSet) (val bool, err error) {
	logger.Debug("CreatePolicyPrefixSet: ", cfg.Name)
	prefixList := make([]policy.PolicyPrefix, 0)
	for _, ribdPrefix := range cfg.PrefixList {
		prefix := policy.PolicyPrefix{
			IpPrefix:        ribdPrefix.Prefix,
			MasklengthRange: ribdPrefix.MaskLengthRange,
		}
		prefixList = append(prefixList, prefix)
	}
	newPolicyPrefixSet := policy.PolicyPrefixSetConfig{Name: cfg.Name, PrefixList: prefixList}
	err = m.server.GlobalPolicyEngineDB.ValidatePolicyPrefixSetCreate(newPolicyPrefixSet)
	if err != nil {
		logger.Err("PolicyEngine validation failed for prefix Set ", cfg.Name, " with err:", err)
		return false, err
	}
	m.server.PolicyConfCh <- server.RIBdServerConfig{
		OrigConfigObject: cfg,
		Op:               "addPolicyPrefixSet",
	}
	return true, err
}
func (m RIBDServicesHandler) UpdatePolicyPrefixSet(origconfig *ribd.PolicyPrefixSet, newconfig *ribd.PolicyPrefixSet, attrset []bool, op []*ribd.PatchOpInfo) (val bool, err error) {
	return val, err
}
func (m RIBDServicesHandler) DeletePolicyPrefixSet(cfg *ribd.PolicyPrefixSet) (val bool, err error) {
	logger.Debug("DeletePolicyPrefixSet: ", cfg.Name)
	err = m.server.GlobalPolicyEngineDB.ValidatePolicyPrefixSetDelete(policy.PolicyPrefixSetConfig{Name: cfg.Name})
	if err != nil {
		logger.Err("PolicyEngine validation for prefix set delete failed with err: ", err)
		return false, err
	}
	m.server.PolicyConfCh <- server.RIBdServerConfig{
		OrigConfigObject: cfg,
		Op:               "delPolicyPrefixSet",
	}
	return true, err
}
func (m RIBDServicesHandler) GetBulkPolicyPrefixSetState(fromIndex ribd.Int, count ribd.Int) (state *ribd.PolicyPrefixSetStateGetInfo, err error) {
	logger.Debug("GetBulkPolicyPrefixSetState")
	ret, err := m.server.GetBulkPolicyPrefixSetState(fromIndex, count, m.server.GlobalPolicyEngineDB)
	return ret, err
}
func (m RIBDServicesHandler) GetPolicyPrefixSetState(name string) (state *ribd.PolicyPrefixSetState, err error) {
	state = ribd.NewPolicyPrefixSetState()
	return state, err
}

func (m RIBDServicesHandler) CreatePolicyCondition(cfg *ribd.PolicyCondition) (val bool, err error) {
	logger.Debug("CreatePolicyConditioncfg: ", cfg.Name)
	newPolicy := policy.PolicyConditionConfig{Name: cfg.Name, ConditionType: cfg.ConditionType, MatchProtocolConditionInfo: cfg.Protocol}
	matchPrefix := policy.PolicyPrefix{IpPrefix: cfg.IpPrefix, MasklengthRange: cfg.MaskLengthRange}
	logger.Info("CreatePolicyCondition:,cfg.PrefixSet:", cfg.PrefixSet)
	newPolicy.MatchDstIpPrefixConditionInfo = policy.PolicyDstIpMatchPrefixSetCondition{Prefix: matchPrefix, PrefixSet: cfg.PrefixSet}
	err = m.server.GlobalPolicyEngineDB.ValidateConditionConfigCreate(newPolicy)
	if err != nil {
		logger.Err("PolicyEngine validation failed with err: ", err)
		return false, err
	}
	m.server.PolicyConfCh <- server.RIBdServerConfig{
		OrigConfigObject: cfg,
		Op:               "addPolicyCondition",
	}
	return true, err
}
func (m RIBDServicesHandler) DeletePolicyCondition(cfg *ribd.PolicyCondition) (val bool, err error) {
	logger.Debug("DeletePolicyConditionConfig: ", cfg.Name)
	err = m.server.GlobalPolicyEngineDB.ValidateConditionConfigDelete(policy.PolicyConditionConfig{Name: cfg.Name})
	if err != nil {
		logger.Err("PolicyEngine validation failed with err: ", err)
		return false, err
	}
	m.server.PolicyConfCh <- server.RIBdServerConfig{
		OrigConfigObject: cfg,
		Op:               "delPolicyCondition",
	}
	return true, err
}
func (m RIBDServicesHandler) UpdatePolicyCondition(origconfig *ribd.PolicyCondition, newconfig *ribd.PolicyCondition, attrset []bool, op []*ribd.PatchOpInfo) (val bool, err error) {
	logger.Debug("UpdatePolicyConditionConfig:UpdatePolicyCondition: ", newconfig.Name)
	return true, err
}
func (m RIBDServicesHandler) GetPolicyConditionState(name string) (*ribd.PolicyConditionState, error) {
	logger.Debug("Get state for Policy Condition")
	retState := ribd.NewPolicyConditionState()
	return retState, nil
}
func (m RIBDServicesHandler) GetBulkPolicyConditionState(fromIndex ribd.Int, rcount ribd.Int) (policyConditions *ribd.PolicyConditionStateGetInfo, err error) { //(routes []*ribd.Routes, err error) {
	logger.Debug("GetBulkPolicyConditionState")
	ret, err := m.server.GetBulkPolicyConditionState(fromIndex, rcount, m.server.GlobalPolicyEngineDB)
	return ret, err
}
