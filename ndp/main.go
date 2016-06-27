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
package main

import (
	"fmt"
	"l3/ndp/flexswitch"
	"l3/ndp/server"
	_ "utils/asicdClient"
	"utils/dmnBase"
)

func main() {
	// @TODO: read plugin from json file
	plugin := "Flexswitch"
	fmt.Println("NDP: initializing neighbor discovery base information")

	/* Steps before starting client
	 *   1) Init Switch Plugin
	 *   2) Create new ndp server
	 *   3) Connect to Clients/Ovsdb
	 *   4) Start the server
	 *   5) Start keepAlive
	 *   6) Start ClientHdl
	 */
	// Step 1
	var ndpBase dmnBase.FSDaemon
	status := ndpBase.Init("ndpd", "NDP")
	if status == false {
		fmt.Println("Init failed")
		return
	}
	ndpBase.Logger.Info(fmt.Sprintln("Init done"))
	// Step 2
	ndpServer := server.NDPNewServer(&ndpBase)
	switch plugin {
	case "OvsDB":

	default:
		lPlugin := flexswitch.NewConfigPlugin(flexswitch.NewConfigHandler(),
			ndpServer.DmnBase.FSBaseDmn.ParamsDir, ndpServer.DmnBase.FSBaseDmn.Logger)

		// Step 3
		ndpServer.DmnBase.ConnectToServers()
		// Step 4
		ndpServer.NDPStartServer()
		// Step 5
		ndpServer.DmnBase.StartKeepAlive()
		// Step 6
		lPlugin.Start()
	}
}
