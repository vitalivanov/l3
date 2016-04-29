// main
package main

import (
	"flag"
	"fmt"
	"l3/tunnel/vxlan/clients/snapclient"
	vxlan "l3/tunnel/vxlan/protocol"
	"l3/tunnel/vxlan/rpc"
	"utils/keepalive"
	"utils/logging"
)

func main() {

	// lookup port
	paramsDir := flag.String("params", "./params", "Params directory")
	flag.Parse()
	path := *paramsDir
	if path[len(path)-1] != '/' {
		path = path + "/"
	}

	fmt.Println("Start logger")
	logger, err := logging.NewLogger("vxland", "VXLAN", true)
	if err != nil {
		fmt.Println("Failed to start the logger. Exiting!!")
		return
	}
	logger.Info("Started the logger successfully.")

	// Start keepalive routine
	go keepalive.InitKeepAlive("vxland", path)

	// Order of calls here matters as the logger
	// needs to exist before clients are registerd
	// and before the server is created.  Similarly
	// the clients need to exist before the server
	// is created as they are connected at time
	// of server creation
	vxlan.SetLogger(logger)

	// register all appropriate clients for use by server
	// TODO add logic to read a param file which contains
	// which client interface to use
	client := snapclient.NewVXLANSnapClient(logger)
	vxlan.RegisterClients(*client)

	// create a new vxlan server
	server := vxlan.NewVXLANServer(logger, path)
	handler := rpc.NewVXLANDServiceHandler(server, logger)

	// blocking call
	handler.StartThriftServer()
}
