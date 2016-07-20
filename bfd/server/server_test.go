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
	"fmt"
	"infra/sysd/sysdCommonDefs"
	"log/syslog"
	"testing"
	"utils/logging"
)

var bfdTestServer *BFDServer
var bfdTestSession *BfdSession
var bfdTestSessionParam *BfdSessionParam
var bfdTestControlPacket *BfdControlPacket

func BfdTestNewLogger() *logging.Writer {
	logger := new(logging.Writer)
	logger.SysLogger, _ = syslog.New(syslog.LOG_DEBUG|syslog.LOG_DAEMON, "BFDTEST")
	logger.GlobalLogging = true
	logger.MyLogLevel = sysdCommonDefs.DEBUG
	return logger
}

func initTestServer() {
	var paramFile string
	fmt.Println("Initializing BFD UT params")
	logger := BfdTestNewLogger()
	bfdTestServer = NewBFDServer(logger)
	bfdTestServer.InitServer(paramFile)
	initSessionHandlingChans()
	return
}

func initSessionHandlingChans() {
	bfdTestServer.CreateSessionCh = make(chan BfdSessionMgmt)
	bfdTestServer.DeleteSessionCh = make(chan BfdSessionMgmt)
	bfdTestServer.AdminUpSessionCh = make(chan BfdSessionMgmt)
	bfdTestServer.AdminDownSessionCh = make(chan BfdSessionMgmt)
	bfdTestServer.CreatedSessionCh = make(chan int32, MAX_NUM_SESSIONS)
	bfdTestServer.FailedSessionClientCh = make(chan int32, MAX_NUM_SESSIONS)
	bfdTestServer.tobeCreatedSessions = make(map[string]BfdSessionMgmt)
}

func startTestServerChans() {
	for {
		select {
		case <-bfdTestServer.ServerStartedCh:
		case <-bfdTestServer.GlobalConfigCh:
		case <-bfdTestServer.asicdSubSocketCh:
		case <-bfdTestServer.asicdSubSocketErrCh:
		case <-bfdTestServer.ribdSubSocketCh:
		case <-bfdTestServer.ribdSubSocketErrCh:
		case <-bfdTestServer.CreateSessionCh:
		case <-bfdTestServer.DeleteSessionCh:
		case <-bfdTestServer.AdminUpSessionCh:
		case <-bfdTestServer.AdminDownSessionCh:
		case <-bfdTestServer.SessionConfigCh:
		case <-bfdTestServer.CreatedSessionCh:
		case <-bfdTestServer.notificationCh:
		case <-bfdTestServer.FailedSessionClientCh:
		case <-bfdTestServer.BfdPacketRecvCh:
		case <-bfdTestServer.SessionParamConfigCh:
		case <-bfdTestServer.SessionParamDeleteCh:
		}
	}
}

func TestCreateBfdServer(t *testing.T) {
	initTestServer()
	go startTestServerChans()
}

func TestBuildPortPropertyMap(t *testing.T) {
	bfdTestServer.BuildPortPropertyMap()
}

func TestCreateASICdSubscriber(t *testing.T) {
	go bfdTestServer.CreateASICdSubscriber()
}

func TestCreateRIBdSubscriber(t *testing.T) {
	go bfdTestServer.CreateRIBdSubscriber()
}

func TestNewNormalBfdSession(t *testing.T) {
	bfdTestServer.createDefaultSessionParam()
	fmt.Println("Creating BFD session to 10.1.1.1")
	bfdTestSession = bfdTestServer.NewNormalBfdSession(0, "10.1.1.1", "default", false, 2)
}

func TestStartSessionServer(t *testing.T) {
	go bfdTestSession.StartSessionServer()
}

func TestStartSessionClient(t *testing.T) {
	go bfdTestSession.StartSessionClient(bfdTestServer)
}

func TestFindBfdSession(t *testing.T) {
	sessionId, found := bfdTestServer.FindBfdSession("10.1.1.1")
	if found {
		fmt.Println("Found session: ", sessionId)
	}
}

func TestEventHandler(t *testing.T) {
	bfdTestSession.EventHandler(REMOTE_DOWN)
	bfdTestSession.EventHandler(REMOTE_INIT)
	bfdTestSession.EventHandler(TIMEOUT)
	bfdTestSession.EventHandler(REMOTE_ADMIN_DOWN)
	bfdTestSession.EventHandler(ADMIN_UP)
	bfdTestSession.EventHandler(REMOTE_UP)
}

func TestUpdateBfdSessionControlPacket(t *testing.T) {
	bfdTestSession.UpdateBfdSessionControlPacket()
}

func TestCheckIfAnyProtocolRegistered(t *testing.T) {
	bfdTestSession.CheckIfAnyProtocolRegistered()
}

func TestAdminDownBfdSession(t *testing.T) {
	sessionMgmt := BfdSessionMgmt{
		DestIp:   "10.1.1.1",
		Protocol: 2,
	}
	bfdTestServer.AdminDownBfdSession(sessionMgmt)
}

func TestAdminUpBfdSession(t *testing.T) {
	sessionMgmt := BfdSessionMgmt{
		DestIp:   "10.1.1.1",
		Protocol: 2,
	}
	bfdTestServer.AdminUpBfdSession(sessionMgmt)
}

func TestSendBfdNotification(t *testing.T) {
	bfdTestSession.SendBfdNotification()
}

func TestSendPeriodicControlPackets(t *testing.T) {
	bfdTestSession.SendPeriodicControlPackets()
}

func TestHandleSessionTimeout(t *testing.T) {
	bfdTestSession.HandleSessionTimeout()
}

func TestProcessBfdPacket(t *testing.T) {
	bfdTestSession.ProcessBfdPacket(bfdTestSession.bfdPacket)
}

func TestInitiatePollSequence(t *testing.T) {
	bfdTestSession.InitiatePollSequence()
}

func TestDecodeBfdControlPacket(t *testing.T) {
	bfdPacketBuf, _ := bfdTestSession.bfdPacket.CreateBfdControlPacket()
	DecodeBfdControlPacket(bfdPacketBuf)
}
