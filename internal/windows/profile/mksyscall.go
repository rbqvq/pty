//go:build windows

package profile

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_windows.go mksyscall.go

//sys loadUserProfile(token windows.Token, profileInfo *profileInfo) (err error) [int32(failretval)==0] = userenv.LoadUserProfileW
//sys unloadUserProfile(token windows.Token, profile windows.Handle) (err error) [int32(failretval)==0] = userenv.UnloadUserProfile
//sys createEnvironmentBlock(block **uint16, token windows.Token, inherit bool) (err error) [int32(failretval)==0] = userenv.CreateEnvironmentBlock
//sys destroyEnvironmentBlock(block *uint16) (err error) [int32(failretval)==0] = userenv.DestroyEnvironmentBlock
//sys getUserProfileDirectory(token windows.Token, profileDir *uint16, size *uint32) (err error) [int32(failretval)==0] = userenv.GetUserProfileDirectoryW
