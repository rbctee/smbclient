package main

import (
	"errors"
	"flag"
	"log"
	"os"

	"github.com/projectdiscovery/go-smb2"
)

type SmbAuthenticationType struct {
	IsLocal bool
}

type smbConfiguration struct {
	Server             string
	TcpPort            uint16
	Username           string
	Password           string
	Domain             string
	Authenticated      bool
	AuthenticationType SmbAuthenticationType
	Session            *smb2.Session
}

func NewSmbConfiguration() smbConfiguration {
	smbConf := smbConfiguration{}
	smbConf.TcpPort = 445
	smbConf.Server = "127.0.0.1"
	smbConf.Authenticated = false
	smbConf.AuthenticationType = SmbAuthenticationType{
		IsLocal: true,
	}

	return smbConf
}

func (smbConf *smbConfiguration) ListSMBShares() (shares []string, err error) {
	if !smbConf.Authenticated {
		return []string{}, errors.New("NULL Binding not implemented yet")
	}

	shares, err = smbConf.Session.ListSharenames()
	if err != nil {
		return []string{}, err
	}

	return shares, err

}

var (
	WarningLog *log.Logger
	InfoLog    *log.Logger
	ErrorLog   *log.Logger
)

func main() {
	smbConf := NewSmbConfiguration()

	InfoLog = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime)
	WarningLog = log.New(os.Stdout, "WARNING: ", log.Ldate|log.Ltime)
	ErrorLog = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime)

	serverAddress := flag.String("server", "", "Server address")
	tcpPort := flag.Uint("port", 445, "TCP port")
	smbUsername := flag.String("username", "", "SMB username")
	smbPassword := flag.String("password", "", "SMB password")

	flag.Parse()

	if *serverAddress == "" {
		ErrorLog.Println("Missing server parameter")
		flag.Usage()

		return
	} else {
		smbConf.Server = *serverAddress
	}

	smbConf.TcpPort = uint16(*tcpPort)

	if *smbUsername != "" || *smbPassword != "" {
		if *smbUsername != "" && *smbPassword != "" {
			smbConf.Username = *smbUsername
			smbConf.Password = *smbPassword
		} else {
			if *smbUsername == "" {
				ErrorLog.Println("Password set but username missing")
			} else {
				ErrorLog.Println("Username set but password missing")
			}
		}

	}

	menu(&smbConf)
}
