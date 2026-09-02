@echo off
REM ==================================================================
REM   VELD DESKTOP MINING CLIENT - CLEARNET (opt out of Tor)
REM
REM   Runs the EXACT same client as "Start Mining.bat" but WITHOUT Tor:
REM   your node connects over clearnet and auto-opens its P2P port
REM   (NAT-PMP/PCP). This is faster, but it PUBLISHES YOUR IP to peers.
REM
REM   For private mining (recommended) - your IP never exposed, reachable
REM   only as a .onion - just use "Start Mining.bat" instead.
REM ==================================================================
setlocal
set "VELD_CLEARNET=1"
call "%~dp0Start Mining.bat"
