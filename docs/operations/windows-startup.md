# Windows startup and minimizing

In **Settings**, enable **Open at Windows sign-in**, then choose:

- **Open app only**: display Veld without automatically starting a node or the
  saved pool worker for this Windows startup. Manual launches retain ordinary
  saved pool resume behavior.
- **Solo mining**: start the normal signed node with CPU mining and saved worker
  settings. Synchronization and work admission still apply.
- **Pool mining**: start the existing saved pool configuration and account.
  Configure and successfully use the Pool tab first. Startup never substitutes
  an endpoint or payout address and never creates an account silently.
- **Node only**: run the normal validating node without CPU mining. Existing
  eligibility requirements continue to govern endorsement work.

Startup is off by default. The current user's Windows Run entry is used; no
administrator permission, Windows service or scheduled task is needed. Windows
Startup Apps can also disable it. Choose a shorter installation/data path if
Windows cannot store its bounded startup command. Changing a startup choice does
not stop or switch a currently running miner.

Solo and node-only startup normally ask for the identity unlock. To run
unattended, start and unlock the node once, then explicitly enable **Remember
startup unlock**. This saves only the confirmed node passphrase in Windows
Credential Manager, scoped to this Windows account, installation and data
directory. It is also bound to the encrypted identity file. Programs running as
the same Windows account can access that credential. No wallet seed or key is
copied. Changing the identity invalidates the saved unlock. Turning Remember
startup unlock off deletes it; uninstalling or moving an installation should
include removing its matching `Veld/StartupUnlock/v1/` credential in Windows
Credential Manager. Disabling startup alone keeps the optional credential until
Remember startup unlock is turned off. Pool mining needs no saved unlock.

**Minimize to system tray** is off by default. Off retains the taskbar entry.
On hides a minimized window behind its Veld icon beside the clock; double-click
the icon or choose **Open Veld Node** to restore it. If the tray is unavailable,
Veld stays on the taskbar. Closing the window still exits rather than silently
hiding it. These preferences are independent of Windows startup.

# Update diagnostics

The updater now waits for the commit helper's private, current-user readiness
event before approving client shutdown. Download cleanup occurs first. This
prevents a slow cleanup from exhausting the helper's installation-lock timeout
while the installer still reports a successful handoff. Helper failure and
timeout fail the installation attempt and retain the client. Signature checks,
durable rollback, relaunch verification and exact signed payloads are unchanged.

`pkg/Collect-VeldDiagnostics.ps1` may run without administrator privileges:

```powershell
powershell -NoProfile -File .\Collect-VeldDiagnostics.ps1 -InstallRoot 'C:\Path\Veld Node'
```

It writes a timestamped JSON file to the Desktop, or an explicitly supplied
existing `-OutputDirectory`. Review the file before sharing it. It reads only
named package/updater files, recognized updater messages, process summaries and
Veld application crash/hang plus Windows sleep/restart event metadata. It does
not include raw logs, configuration, wallet material, keys, viewing tokens,
machine names or IP addresses; it sends nothing and changes no Veld settings.
