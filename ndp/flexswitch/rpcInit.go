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
	"encoding/json"
	"errors"
	"fmt"
	"git.apache.org/thrift.git/lib/go/thrift"
	"io/ioutil"
	"ndpd"
	"strconv"
	"utils/logging"
)

//func NewConfigHandler() *NDPDServicesProcessor {
func NewConfigHandler() *ConfigHandler {
	handler := &ConfigHandler{}
	//	processor := ndpd.NewNDPDServicesProcessor(handler)
	//	return processor
	return handler
}

func NewConfigPlugin(handler *ConfigHandler, fileName string, logger *logging.Writer) *ConfigPlugin {
	l := &ConfigPlugin{handler, fileName, logger}
	return l
}

func (cfg *ConfigPlugin) Start() error {
	fileName := cfg.fileName + "clients.json"

	clientJson, err := getClient(fileName, "ndpd")
	if err != nil || clientJson == nil {
		return err
	}
	cfg.logger.Info(fmt.Sprintln("Got Client Info for", clientJson.Name, " port", clientJson.Port))
	// create processor, transport and protocol for server
	processor := ndpd.NewNDPDServicesProcessor(cfg.handler)
	transportFactory := thrift.NewTBufferedTransportFactory(8192)
	protocolFactory := thrift.NewTBinaryProtocolFactoryDefault()
	transport, err := thrift.NewTServerSocket("localhost:" + strconv.Itoa(clientJson.Port))
	if err != nil {
		cfg.logger.Info(fmt.Sprintln("StartServer: NewTServerSocket failed with error:", err))
		return err
	}
	server := thrift.NewTSimpleServer4(processor, transport, transportFactory, protocolFactory)
	err = server.Serve()
	if err != nil {
		cfg.logger.Err(fmt.Sprintln("Failed to start the listener, err:", err))
		return err
	}
	return nil

}

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
