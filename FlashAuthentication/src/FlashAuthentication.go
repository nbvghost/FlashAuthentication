package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"runtime"
	"strings"
)

var CrossdomainStr string = "<?xml version=\"1.0\"?><!DOCTYPE cross-domain-policy SYSTEM \"http://www.adobe.com/xml/dtds/cross-domain-policy.dtd\"><cross-domain-policy>" +
	"<allow-access-from domain=\"*\" to-ports=\"8000-9000\" />" +
	"<allow-access-from domain=\"*\" to-ports=\"3306\" />" +
	"<allow-access-from domain=\"*.example.com\" to-ports=\"507,516\" />" +
	"<allow-access-from domain=\"*.example2.com\" to-ports=\"516-523\" />" +
	"<allow-access-from domain=\"www.example2.com\" to-ports=\"507,516-523\" />" +
	"<allow-access-from domain=\"www.example3.com\" to-ports=\"*\" />" +
	"</cross-domain-policy>"

func main() {
	var err error
	
	fmt.Println("-----------read me----------")
	fmt.Println("                        date:2014-6-6")
	fmt.Println("FlashAuthentication.exe will caeate fac.ini and crossdomain.xml files.if it's not exist.you can delete and edit it.if you create new it.named fac.ini and crossdomain.xml.see more:http://www.adobe.com/devnet-docs/acrobatetk/tools/AppSec/CrossDomain_PolicyFile_Specification.pdf")
	fmt.Println("----------------------------")
	fmt.Println("\r\n")

	_, err = os.Stat("fac.ini")

	if err != nil {
		//panic(err)
		fout, err := os.Create("fac.ini")
		defer fout.Close()
		if err != nil {
			panic(err)
		} else {
			fout.WriteString(":843")
			fout.Sync()
			fout.Close()

		}
	}

	_, err = os.Stat("crossdomain.xml")
	if err != nil {
		fout, err := os.Create("crossdomain.xml")
		defer fout.Close()
		if err != nil {
			panic(err)
		} else {
			fout.WriteString(CrossdomainStr)
			fout.Sync()
			fout.Close()

		}
	}

	var fileBytes []byte

	fileBytes, err = ioutil.ReadFile("crossdomain.xml")
	if err != nil {
		panic(err)
	}

	CrossdomainStr = string(fileBytes)
	fmt.Println("-----------crossdomain.xml----------")
	fmt.Println(CrossdomainStr)
	fmt.Println("-----------crossdomain.xml----------")

	fileBytes, err = ioutil.ReadFile("fac.ini")
	if err != nil {
		panic(err)
	}
	fmt.Println("-----------fac.ini----------")
	fmt.Println(string(fileBytes))
	fmt.Println("-----------fac.ini----------")

	var address []string = strings.Split(string(fileBytes), ":")

	if len(address) != 2 {
		fmt.Println("ip address format is error!")
		return
	}
	ip, port := address[0], address[1]

	runtime.GOMAXPROCS(runtime.NumCPU())

	listener, err := net.Listen("tcp", ip+":"+port)

	if err != nil {
		panic(err)
		return
	}
	fmt.Println("start authentication server:", listener.Addr())
	for {
		conn, listenErr := listener.Accept()
		if listenErr != nil {
			fmt.Println("error:", listenErr)
		} else {
			go onDataHandler(conn)
		}
	}
}

func onDataHandler(conn net.Conn) {
	buf := make([]byte, 1024)
	conn.Read(buf)
	isRequest := strings.Index(string(buf), "<policy-file-request/>")

	if isRequest != -1 {
		conn.Write([]byte(CrossdomainStr))

		fmt.Println("authentication success:", conn.RemoteAddr())
	}
	conn.Close()
}
