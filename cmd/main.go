package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/projectdiscovery/go-smb2"
)

var (
	WarningLog *log.Logger
	InfoLog    *log.Logger
	ErrorLog   *log.Logger
)

func ListSMBShares(server string, port uint, username string, password string) (shares []string, err error) {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", server, port))
	if err != nil {
		return []string{}, err
	}
	defer conn.Close()

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     username,
			Password: password,
		},
	}

	s, err := d.Dial(conn)
	if err != nil {
		return []string{}, err
	}
	defer s.Logoff()

	shares, err = s.ListSharenames()
	if err != nil {
		return []string{}, err
	}

	return shares, err
}

func main() {
	InfoLog = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime)
	WarningLog = log.New(os.Stdout, "WARNING: ", log.Ldate|log.Ltime)
	ErrorLog = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime)

	serverAddress := flag.String("server", "", "Server address")
	tcpPort := flag.Uint("port", 445, "TCP port")
	userName := flag.String("username", "", "SMB username")
	userPassword := flag.String("password", "", "SMB password")

	flag.Parse()

	if *serverAddress == "" {
		flag.Usage()
		return
	}

	if *userName == "" {
		flag.Usage()
		return
	}

	if *userPassword == "" {
		flag.Usage()
		return
	}

	shares, err := ListSMBShares(*serverAddress, *tcpPort, *userName, *userPassword)
	if err != nil {
		ErrorLog.Printf("Error listing shares: %s\n", err)
	} else {
		fmt.Printf("List of shares on SMB server %s:\n", *serverAddress)

		for _, s := range shares {
			fmt.Printf("\t- %s\n", s)
		}
	}
}
