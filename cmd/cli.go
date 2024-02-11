package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/projectdiscovery/go-smb2"
)

func checkCommand(str1 string, str2 string) bool {
	return strings.EqualFold(str1, str2)
}

func menu(smbConf *smbConfiguration) {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Printf("\n> ")
		text, _ := reader.ReadString('\n')
		text = strings.Replace(text, "\n", "", -1)

		s := strings.Split(text, " ")

		if checkCommand(s[0], "auth") {
			manageAuthentication(smbConf, s)
		} else if checkCommand(s[0], "exit") || checkCommand(s[0], "quit") {
			return
		} else if checkCommand(s[0], "help") {
			usage([]string{})
		} else if checkCommand(s[0], "info") {
			manageInfoCommand(s)
		} else if checkCommand(s[0], "logout") {
			manageLogoutCommand(smbConf)
		} else if checkCommand(s[0], "shares") {
			ListSmbShares(smbConf)
		} else if checkCommand(s[0], "status") {
			ShowConnectionStatus(smbConf)
		} else if checkCommand(s[0], "usage") {
			manageUsageCommand(s)
		}
	}

}

func usage(s []string) {
	if len(s) == 0 {
		fmt.Printf("Available commands:\n\n")
		fmt.Println("auth\t\t\tAuthenticate (local or domain)")
		fmt.Println("help\t\t\tShow help message")
		fmt.Println("info\t\t\tGet server info from NTLM handshake")
		fmt.Println("logout\t\t\tLog out of the SMB session")
		fmt.Println("shares\t\t\tList SMB shares")
		fmt.Println("status\t\t\tShow connection status")
		fmt.Println("usage\t\t\tShow some useful examples")
		return
	}

	if checkCommand(s[0], "auth") {
		if len(s) == 1 {
			fmt.Printf("Usage: auth COMMAND\n\n")
			fmt.Printf("Commands:\n")
			fmt.Println("local")
			fmt.Println("domain")
			return
		}

		if checkCommand(s[1], "local") {
			if len(s) == 2 {
				fmt.Printf("Usage: auth local USERNAME PASSWORD\n")
				return
			}
		}
	}
}

func ShowConnectionStatus(smbConf *smbConfiguration) {
	ErrorLog.Println("Command not implemented yet")
}

func manageInfoCommand(s []string) {
	ErrorLog.Println("Command not implemented yet")
}

func manageUsageCommand(s []string) {
	ErrorLog.Println("Command not implemented yet")
}

func manageLogoutCommand(smbConf *smbConfiguration) {
	if smbConf.Session != nil {
		err := smbConf.Session.Logoff()
		if err != nil {
			ErrorLog.Printf("Failed to log out: %s\n", err)
		} else {
			InfoLog.Println("Logged out of the SMB session")
		}
	} else {
		ErrorLog.Println("The current session is not authenticated, can't log out")
	}
}

func manageAuthentication(smbConf *smbConfiguration, s []string) {
	if len(s) == 1 {
		usage([]string{"auth"})
		return
	}

	if checkCommand(s[1], "local") {
		manageLocalAuthentication(smbConf, s)
	} else if checkCommand(s[1], "domain") {
		manageDomainAuthentication(smbConf, s)
	}
}

func manageLocalAuthentication(smbConf *smbConfiguration, s []string) {
	if len(s) == 2 {
		usage([]string{"auth", "local"})
		return
	}

	if len(s) < 4 {
		usage([]string{"auth", "local"})
		return
	} else {
		smbConf.Username = s[2]
		smbConf.Password = s[3]

		isAuthenticated, err := performLocalAuthentication(smbConf)
		if err != nil {
			ErrorLog.Printf("Failed to authenticated: %s\n", err)
		} else {
			if isAuthenticated {
				InfoLog.Println("Authentication performed successfully")
			} else {
				ErrorLog.Println("Failed to authenticated due to an unknown error")
			}
		}
	}

}

func performLocalAuthentication(smbConf *smbConfiguration) (isAuthenticated bool, err error) {
	remoteServer := fmt.Sprintf("%s:%d", smbConf.Server, smbConf.TcpPort)
	conn, err := net.Dial("tcp", remoteServer)
	if err != nil {
		return false, err
	}

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     smbConf.Username,
			Password: smbConf.Password,
		},
	}

	s, err := d.Dial(conn)
	if err != nil {
		return false, err
	}
	smbConf.Session = s
	smbConf.Authenticated = true
	smbConf.AuthenticationType.IsLocal = true
	return true, nil
}

func manageDomainAuthentication(smbConf *smbConfiguration, s []string) {
	if len(s) == 2 {
		usage([]string{"auth", "domain"})
		return
	}

	if len(s) < 4 {
		usage([]string{"auth", "local"})
		return
	} else {
		smbConf.Domain = s[2]
		smbConf.Username = s[3]
		smbConf.Password = s[4]
		performDomainAuthentication(smbConf)
	}
}

func performDomainAuthentication(smbConf *smbConfiguration) {
	ErrorLog.Println("Command not implemented yet")
}

func ListSmbShares(smbConf *smbConfiguration) {
	shares, err := smbConf.ListSMBShares()
	if err != nil {
		ErrorLog.Printf("Error listing shares: %s\n", err)
	} else {
		fmt.Printf("List of shares on SMB server %s:\n", smbConf.Server)

		for _, s := range shares {
			fmt.Printf("\t- %s\n", s)
		}
	}
}
