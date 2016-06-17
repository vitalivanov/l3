package main

import (
	"fmt"
	"l3/rib/test/testthrift"
	"l3/rib/testutils"
	"os"
)

func main() {
	ribdClient := testutils.GetRIBdClient()
	if ribdClient == nil {
		fmt.Println("RIBd client nil")
		return
	}

	routeThriftTest.Createv4RouteList()

	route_ops := os.Args[1:]

	for _, op := range route_ops {
		switch op {
		case "createv4":
			fmt.Println("Create v4 route test")
			routeThriftTest.Createv4Routes(ribdClient)
		case "verify":
			fmt.Println("Verify reachability info")
			routeThriftTest.CheckRouteReachability(ribdClient)
		case "deletev4":
			fmt.Println("Delete v4 route test")
			routeThriftTest.Deletev4Routes(ribdClient)
		}
	}
}
