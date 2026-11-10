# pty

Cross-platform pseudo-terminal for Go, with interactive login support on Windows.

## Features

- A single `Pty` interface: `Read` / `Write` / `Setsize` / `Close`
- **Unix** — spawns a shell via [creack/pty](https://github.com/creack/pty), optionally routed through `login(1)`
- **Windows** — spawns a shell via a bundled ConPTY implementation, with three session modes:
  - current process identity
  - another user via MSV1_0 S4U (passwordless, requires `LocalSystem`)
  - interactive username/password login that emulates `/sbin/login`

## Platform support

| Feature                 | Unix             | Windows                |
| ----------------------- | ---------------- | ---------------------- |
| Direct Shell            | yes              | yes                    |
| `WithUser(name)`        | `login -f name`  | S4U                    |
| `WithUser(CurrentUser)` | `login -f $USER` | dup token              |
| `WithInteractiveLogin`  | `login(1)`       | emulated `/sbin/login` |

Windows requires **Windows 10 version 1809 (build 17763)** or **Windows Server 2019** or later. This is the minimum for `CreatePseudoConsole`; it is stricter than Go 1.21's own "Windows 10" baseline.

The Windows build depends on `golang.org/x/sys` and `golang.org/x/term`.

## Install

```
go get gitlab.com/CoiaPrant/pty
```

## Usage

### Default shell as the current process identity

```go
p, err := pty.New()
if err != nil {
    return err
}
defer p.Close()

io.Copy(os.Stdout, p)
```

### Run as another user

```go
p, err := pty.New(pty.WithUser("alice"))
```

- On Unix this invokes `login -f alice`, which requires root privileges.
- On Windows it uses MSV1_0 S4U, which requires the calling process to run as
  `LocalSystem`.

  If `alice` is already the process identity, the current token is duplicated instead of going through S4U.

### Current-user sentinel

```go
p, err := pty.New(pty.WithUser(pty.CurrentUser))
```

Always resolves to the calling process identity, on both platforms.

### Interactive login

```go
p, err := pty.New(pty.WithInteractiveLogin())
```

On Unix this runs `login(1)`. On Windows it presents a `/sbin/login`-style prompt:

```
Hostname login: alice
Password:
```

- Up to **3** failed attempts, with a **3-second delay** after each failure
- **60-second timeout** per prompt, then the session is closed
- Backspace and Ctrl+C handled at the prompt layer, before any shell exists
- Password echo suppressed
- After successful authentication the connection transparently hands off to the shell started under the authenticated user

Example session:

```
Hostname login: Administrator
Password:

Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> whoami
workstation\administrator
```

## Requirements

### Windows service privileges

S4U requires `SeTcbPrivilege`, and starting the shell as another user via
`CreateProcessAsUser` requires `SeAssignPrimaryTokenPrivilege`. Profile
loading additionally needs `SeBackupPrivilege` and `SeRestorePrivilege`, and
`SeImpersonatePrivilege` is required by some auth paths. This matches the
privilege set Win32-OpenSSH grants to `sshd`.

The simplest way is to run the service as `LocalSystem`, which holds all of
them:

    sc config YourServiceName obj= "LocalSystem"

If a dedicated service account must be used, grant them explicitly:

    sc privs YourServiceName SeAssignPrimaryTokenPrivilege/SeTcbPrivilege/SeBackupPrivilege/SeRestorePrivilege/SeImpersonatePrivilege

Verify with:

    sc qprivs YourServiceName

## License

MIT

## Credits

- **[creack/pty](https://github.com/creack/pty)** — Unix pty implementation. MIT.
- **[UserExistsError/conpty](https://github.com/UserExistsError/conpty)** — Windows ConPTY base. MIT.
- **[Tailscale](https://github.com/tailscale/tailscale)** — S4U token acquisition in `internal/windows/token`, adapted from `util/winutil/s4u`. BSD-3-Clause.
- **[PowerShell/Win32-OpenSSH](https://github.com/PowerShell/OpenSSH-Portable)** — MSV1_0 S4U reference and the fake-login workaround in `internal/windows/token/s4u_windows.go`. MIT.

The combined work is MIT and BSD-3-Clause-compatible. Keep this README (or a `THIRD_PARTY_LICENSES.md` derived from it) alongside any binary distribution to satisfy the attribution requirements of these permissive licenses.
