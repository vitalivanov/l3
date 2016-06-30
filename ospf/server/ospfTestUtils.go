package server

import (
	"fmt"
	"infra/sysd/sysdCommonDefs"
	"log/syslog"
	"utils/logging"
)

func OSPFNewLogger(name string, tag string, listenToConfig bool) (*logging.Writer, error) {
	var err error
	srLogger := new(logging.Writer)
	srLogger.MyComponentName = name

	srLogger.SysLogger, err = syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, tag)
	if err != nil {
		fmt.Println("Failed to initialize syslog - ", err)
		return srLogger, err
	}

	srLogger.GlobalLogging = true
	srLogger.MyLogLevel = sysdCommonDefs.INFO
	return srLogger, err
}

func startDummyChannels(server *OSPFServer) {
	//	server.neighborDBDEventCh = make(chan ospfNeighborDBDMsg)
	for {
		select {
		case data := <-server.neighborDBDEventCh:
			fmt.Println("Receieved data from neighbor DBD : ", data)
		}
	}

}

func getServerObject() *OSPFServer {
	logger, err := OSPFNewLogger("ospfd", "OSPFTEST", true)
	if err != nil {
		fmt.Println("ospftest: creating logger failed")
	}
	ospfServer := NewOSPFServer(logger)
	if ospfServer == nil {
		fmt.Sprintln("ospf server object is null ")
	}
	return ospfServer
}
