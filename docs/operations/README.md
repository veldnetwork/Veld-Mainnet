# Running Veld

## Windows client

Download the complete signed package from [veld.network](https://veld.network/),
extract it into its own directory, and run `Start Veld Node.bat`. This starts
the graphical client on clearnet and performs package verification.

The terminal launchers have separate behavior:

| Launcher | Purpose |
| --- | --- |
| `Start Veld Node.bat` | Graphical client on clearnet |
| `Start Mining.bat` | Terminal miner, Tor by default |
| `Start Mining (Clearnet).bat` | Terminal miner with explicit clearnet selection |
| `Start Validator.bat` | Node endorsement mode |

Keep encrypted wallet backups and the client data directory when updating.
Use the signed update path; retain all files in the package together.

## Linux and source builds

Follow [BUILDING.md](../../BUILDING.md) to select a role. The fleet role
disables mining. The standalone validator uses authenticated node RPC.
The portal provides controls for explicitly paired machines.

Configure exposed services and authentication for the deployment. Node RPC
credentials, wallet keys, and release-signing material belong outside source
control. Example reverse-proxy files are in [pkg/reverse-proxy/](../../pkg/reverse-proxy/).

## Synchronization and updates

An eligible node can import an official signed snapshot. It independently
validates from genesis before leaving bootstrap quarantine. If no snapshot is
eligible, synchronization proceeds from genesis. Matching height alone does
not establish complete synchronization.

Check [node health](node-health.md) and compare independent peers after an
update. Use [release notes](../release-notes.md) for activation requirements.
Hosted web updates and signed native client releases follow separate paths.
