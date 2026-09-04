VELD TERMINAL CLIENT - RELEASE INTEGRITY
========================================

This separately signed archive preserves the original command-line mining and
validator workflow. It uses the same Veld 3.0.4 client code as Veld Node,
but has its own signed manifest and authenticated update feed.

Start Mining.bat uses Tor-only networking. Start Mining (Clearnet).bat uses a
direct connection and exposes your IP to peers. Start Validator.bat runs an
endorse-only node and does not mine. Do not run more than one launcher from the
same folder at the same time.

Every launcher verifies SHA256SUMS.txt.sig against the ML-DSA-65 release key
pinned in bin\veld-node.exe, then verifies every file named by the manifest.
Missing signatures, missing files, extra files, or hash mismatches stop launch.

For a first installation, compare VeldTerminalClient-Windows-x64.zip with the
SHA-256 digest published at https://veld.network and in the signed release
announcement. Later updates are authenticated by the already trusted node
binary and the terminal-specific signed feed.

The SHA-256 fingerprint of the decoded 1,952-byte ML-DSA-65 release public key
is:

  d08731f74b27b61ecbecd54785adbbf918732b06af39978b4b88894821a8771d
