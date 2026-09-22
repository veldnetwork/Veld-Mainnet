# Veld 3.2.3 qualification

This maintenance candidate combines the pool worker allocation and request
scheduling improvements with the reviewed gateway and journal recovery changes.
It preserves the existing consensus and economic rules.

Production controllers must build the Windows node, wallet and GUI from one
clean commit and tree. The release identity and signed package manifest record
the exact source and binary hashes. Passing earlier standalone worker tests does
not qualify a later complete package.

Required release checks include unchanged VeldHash vectors, transport admission
and retry boundaries, gateway authorization, journal recovery, native Windows
pool ownership and resume, signed update repair and rollback, and the actual
packaged client restarting with its existing pool account and mining settings.
Automatic updates are opt-in and check hourly while Veld Node is open.

Performance varies with hardware, work availability and network conditions.
Allocation and connection improvements do not guarantee a hashrate increase or
any number of block wins. Historical benchmark results are not a promise.

Funded issuer/witness migration and the integrated custody service have their
own qualification. This release does not claim custody activation, comprehensive
security clearance, or completion of those separate tests.
