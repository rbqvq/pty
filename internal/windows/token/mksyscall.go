package token

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_windows.go mksyscall.go

//sys allocateLocallyUniqueId(luid *windows.LUID) (err error) [int32(failretval)==0] = advapi32.AllocateLocallyUniqueId
//sys logonUserW(username *uint16, domain *uint16, password *uint16, logonType uint32, logonProvider uint32, token *windows.Token) (err error) [int32(failretval)==0] = advapi32.LogonUserW
//sys changeAccountPasswordW(packageName *uint16, domainName *uint16, accountName *uint16, oldPassword *uint16, newPassword *uint16, impersonating bool, reserved uint32, output *secBufferDesc) (status uint32) = secur32.ChangeAccountPasswordW
//sys lsaRegisterLogonProcess(logonProcessName *lsaString, lsaHandle *_LSAHANDLE, securityMode *_LSA_OPERATIONAL_MODE) (ret windows.NTStatus) = secur32.LsaRegisterLogonProcess
//sys lsaDeregisterLogonProcess(lsaHandle _LSAHANDLE) (ret windows.NTStatus) = secur32.LsaDeregisterLogonProcess
//sys lsaLookupAuthenticationPackage(lsaHandle _LSAHANDLE, packageName *lsaString, authenticationPackage *uint32) (ret windows.NTStatus) = secur32.LsaLookupAuthenticationPackage
//sys lsaFreeReturnBuffer(buffer uintptr) (ret windows.NTStatus) = secur32.LsaFreeReturnBuffer
//sys lsaLogonUser(lsaHandle _LSAHANDLE, originName *lsaString, logonType _SECURITY_LOGON_TYPE, authenticationPackage uint32, authenticationInformation unsafe.Pointer, authenticationInformationLength uint32, localGroups unsafe.Pointer, sourceContext *tokenSource, profileBuffer *uintptr, profileBufferLength *uint32, logonID *windows.LUID, token *windows.Token, quotas *quotaLimits, subStatus *uint32) (ret windows.NTStatus) = secur32.LsaLogonUser
//sys getUserNameEx(nameFormat uint32, name *uint16, nameSize *uint32) (err error) [int32(failretval)==0] = secur32.GetUserNameExW
//sys netGetJoinInformation(server *uint16, nameBuffer **uint16, bufferType *int32) (status uint32) = netapi32.NetGetJoinInformation
//sys netApiBufferFree(buffer *uint16) (status uint32) = netapi32.NetApiBufferFree
//sys netUserChangePassword(domainName *uint16, username *uint16, oldPassword *uint16, newPassword *uint16) (status uint32) = netapi32.NetUserChangePassword
