# Windows operator file boundary

The shared operator reader now uses Windows file handles when running on
Windows. It refuses directories, reparse points, hard links, ambiguous or remote
paths, oversized files, unexpected resolved paths and changes observed during
the read. It opens without write/delete sharing and checks ownership and DACL
permissions on that same handle before reading bytes.

Public policy/manifest files may be readable by others. Only the current user,
SYSTEM and Administrators may own or have write/policy authority over them.
Private files require current-user ownership and a protected owner-only DACL,
matching the existing node's private-channel policy. These controls do not claim
protection from Windows administrators, kernel compromise or compromised code
running as the same user.

This implementation follows the handle semantics of Microsoft's
[GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo)
and [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew).
Unix handling retains its existing `O_NOFOLLOW`, owner/mode and bounded-read
requirements. Windows deployments of these Python modules must bundle
`windows_protected_file.py` alongside `rpc_url_policy.py`; Linux does not import it.

17 actual Windows checks cover protected/public reads, byte limits, ACL refusal,
links, path aliases, replacement/missing files and full descriptor/manifest
loading. Disposable fixtures receive explicit ACLs: inherited write grants are
not accepted merely to make the tests pass. No existing operator file, credential,
wallet or system-wide permissions were changed.

This is one prerequisite for the integrated signer, not an implemented custody
worker. Python `fcntl`, process-group/pipe supervision, OS key isolation, durable
commitment recovery, constrained broker transport, native finalized-intent
verification, packaging, upgrade/rollback and independent operator qualification
remain open. The future worker must be automatically managed by Veld Node and
independent of the mining switch. Mining-resume credentials grant no custody
authority, and candidate enrollment grants no authority over existing funds.
