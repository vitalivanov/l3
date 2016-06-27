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
package flexswitch

import (
	"ndpd"
)

func NewConfigHandler() *NDPDServicesProcessor {
	handler := &ConfigHandler{}
	processor := ndpd.NewNDPDServicesProcessor(handler)
	return processor
}

/*
func getClient(fileName string, process string) (*ClientJson, error) {
	var allClients []ClientJson

	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	json.Unmarshal(data, &allClients)
	for _, client := range allClients {
		if client.Name == process {
			return &client, nil
		}
	}
	return nil, errors.New("couldn't find " + process + " port info")
}

// Client RPC Listener code..
func (dmn *FSDaemon) StartListener(processor interface{}) error {
	fileName := dmn.FSBaseDmn.ParamsDir + CLIENTS_FILE_NAME

	clientJson, err := getClient(fileName, dmn.FSBaseDmn.DmnName)
	if err != nil || clientJson == nil {
		return err
	}
	dmn.FSBaseDmn.Logger.Info(fmt.Sprintln("Got Client Info for", clientJson.Name, " port", clientJson.Port))
	// create processor, transport and protocol for server
	//processor := lldpd.NewLLDPDServicesProcessor(handler)
	transportFactory := thrift.NewTBufferedTransportFactory(8192)
	protocolFactory := thrift.NewTBinaryProtocolFactoryDefault()
	transport, err := thrift.NewTServerSocket("localhost:" + strconv.Itoa(clientJson.Port))
	if err != nil {
		dmn.FSBaseDmn.Logger.Info(fmt.Sprintln("StartServer: NewTServerSocket failed with error:", err))
		return err
	}
	server := thrift.NewTSimpleServer4(processor, transport, transportFactory, protocolFactory)
	err = server.Serve()
	if err != nil {
		dmn.FSBaseDmn.Logger.Err(fmt.Sprintln("Failed to start the listener, err:", err))
		return err
	}
	return nil
}


func CreateNDGlobal(config *NDGlobal) (bool, err) {
	return true, nil
}

func UpdateNDGlobal(orgCfg *NDGlobal, newCfg *NDGlobal, attrset []bool, op []*ndpd.PatchOpInfo) (bool, error) {
	return true, nil
}

func DeleteNDGlobal(config *NDGlobal) (bool, error) {
	return true, nil
}
*/
