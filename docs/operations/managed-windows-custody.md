# Managed Windows custody implementation boundary

The managed custody signer is not complete or activated. The selected product
remains one Veld Node client with an automatically managed internal worker,
exactly three-of-five community custody keys and no fleet custody authority.

## Implemented process component

`swap/windows_managed_process.py` starts a local executable suspended, assigns it
to a Windows Job Object, and only then resumes its first thread. The job closes
its processes when its final handle closes, bounds child count and committed
memory, and enforces the caller's deadline and input/output limits. Only the
three intended pipe handles are inherited. A failed job assignment terminates
the suspended child. Primary exit terminates remaining descendants before return.

The shared operator runner uses this component on Windows. Actual Windows tests
cover child-job membership at startup, inherited-handle exclusion, descendant
termination, timeout, output flooding, UTF-8 failure, exit codes and pipe pressure.
Production-profile keygen builds performed actual RTP1/C1 evidence, intent and
input-signature verification through this runner with disposable keys.

A job is a lifetime/resource mechanism. It is not a sandbox or key-access policy.
The worker currently runs as its caller. Same-user processes, administrators,
software updates and external process brokers remain trust-boundary concerns.
Mining-resume credentials do not authorize custody operations.

## Still required for the Node product

- Installer-managed dedicated key principal, protected executable/configuration
  paths and non-exportable or separately protected custody key access.
- An authenticated constrained request interface whose only signing authority
  comes from independently verified finalized native intent and full descriptor
  membership; candidate enrollment must grant no existing custody authority.
- Client lifecycle, role status, internal Bitcoin dependency management and
  automatic recovery independent of the mining switch.
- Durable commitments and reconciliation across restart, backup restoration,
  partial signatures, updates and rollback; no timeout-based signature release.
- Full five-member test-network service qualification, Windows/Linux installers,
  measured resource requirements and independent operator enrollment evidence.

The production payout guard stays closed until those controls and the isolated
native authority proposal are qualified. Process tests do not establish custody
readiness or quorum-preserving update availability.

Windows API references: [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects),
[explicit inherited handles](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute),
and [process creation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw).
