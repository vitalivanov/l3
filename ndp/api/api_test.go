//
//Copyright [2016] [SnapRoute Inc]
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//       Unless required by applicable law or agreed to in writing, software
//       distributed under the License is distributed on an "AS IS" BASIS,
//       WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//       See the License for the specific language governing permissions and
//       limitations under the License.
//
// _______  __       __________   ___      _______.____    __    ____  __  .___________.  ______  __    __
// |   ____||  |     |   ____\  \ /  /     /       |\   \  /  \  /   / |  | |           | /      ||  |  |  |
// |  |__   |  |     |  |__   \  V  /     |   (----` \   \/    \/   /  |  | `---|  |----`|  ,----'|  |__|  |
// |   __|  |  |     |   __|   >   <       \   \      \            /   |  |     |  |     |  |     |   __   |
// |  |     |  `----.|  |____ /  .  \  .----)   |      \    /\    /    |  |     |  |     |  `----.|  |  |  |
// |__|     |_______||_______/__/ \__\ |_______/        \__/  \__/     |__|     |__|      \______||__|  |__|
//
package api

import (
	"fmt"
	"infra/sysd/sysdCommonDefs"
	"l3/ndp/debug"
	"l3/ndp/server"
	"log/syslog"
	"testing"
	"time"
	asicdmock "utils/asicdClient/mock"
	"utils/logging"
)

var testApiIfIndex = int32(100)
var testApiState = "UP"
var testApiIpAddr = "2192::1/64"
var testVlanId = int32(1234)
var testVlanName = "vlan1234"

func initApiBasic() {
	t := &testing.T{}
	logger, err := NDPTestNewLogger("ndpd", "NDPTEST", true)
	if err != nil {
		t.Error("creating logger failed")
	}
	debug.NDPSetLogger(logger)
}

func NDPTestNewLogger(name string, tag string, listenToConfig bool) (*logging.Writer, error) {
	var err error
	srLogger := new(logging.Writer)
	srLogger.MyComponentName = name

	srLogger.SysLogger, err = syslog.New(syslog.LOG_DEBUG|syslog.LOG_DAEMON, tag)
	if err != nil {
		fmt.Println("Failed to initialize syslog - ", err)
		return srLogger, err
	}

	srLogger.GlobalLogging = true
	srLogger.MyLogLevel = sysdCommonDefs.INFO
	return srLogger, err
}

func baseApiTest() *server.NDPServer {
	time.Sleep(1)
	initApiBasic()
	testServer := server.NDPNewServer(&asicdmock.MockAsicdClientMgr{})
	testServer.NDPStartServer()
	return testServer
}

func TestApiInit(t *testing.T) {
	Init(baseApiTest())
}

func TestL2PortNotification(t *testing.T) {
	TestApiInit(t)
	SendL2PortNotification(testApiIfIndex, testApiState)
}

func TestL3PortNotification(t *testing.T) {
	TestApiInit(t)
	SendL3PortNotification(testApiIfIndex, testApiState, testApiIpAddr)
}

func TestIpNotification(t *testing.T) {
	TestApiInit(t)
	SendIPIntfNotfication(testApiIfIndex, testApiIpAddr, testVlanName, testApiState)
}

func TestGetBulkNeigbhorEntries(t *testing.T) {
	TestApiInit(t)
	_, _, result := GetAllNeigborEntries(0, 100)
	if len(result) > 0 {
		t.Error("There should not be any neigbhor Entries")
		return
	}
}

func TestGetNeighborEntry(t *testing.T) {
	TestApiInit(t)
	result := GetNeighborEntry(testApiIpAddr)
	if result != nil {
		t.Error("There should not be any neigbhor Entries")
		return
	}
}

func TestVlanNotification(t *testing.T) {
	TestApiInit(t)
	SendVlanNotification(testApiState, testVlanId, testVlanName, make([]int32, 0))
}
