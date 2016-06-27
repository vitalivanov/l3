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
	 *   3) Start the server
	 *   4) Start keepAlive
	 *   5) Start ClientHdl
	 */
	// Step 1
	switchPlugin := dmnBase.InitPlugin("ndpd", "NDP", plugin)
	switchPlugin.Log(dmnBase.INFO, "Init done")
	// Step 2
	_ = server.NDPNewServer(switchPlugin)
	// Step 4
	switchPlugin.StartKeepAlive()
	// Step 5
	//cfgHandler := flexswitch.NewConfigHandler()
	/*
		processor := flexswitch.NewConfigHandler()
		err := ndpSvr.switchPlugin.StartListener(processor)
		if err != nil {
			ndpSvr.switchPlugin.Log(dmnBase.ERR, fmt.Sprintln("failed to start listener, Error:", err))
			return
		}
	*/
}
