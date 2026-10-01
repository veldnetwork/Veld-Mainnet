# Linux wallet

Veld's Linux wallet uses a graphical interface in your default web browser.
The packaged wallet backend serves it on this computer's loopback interface.
Wallet mode connects to Veld's public infrastructure without downloading a chain.

## Open the wallet

Verify and extract the complete Linux package into a permanent directory.
Run **Install Wallet.sh** once, then choose **Veld Wallet** in your application
menu. Installation is for your current user and needs no administrator access.
You can also run **Start Wallet.sh** directly from the extracted package.

Python 3, a graphical Linux desktop and a default web browser are required.
Install your distribution's `xdg-utils` package if browser opening is unavailable.
From a terminal, the equivalent setup is:

```sh
sh './Install Wallet.sh'
sh './Start Wallet.sh'
```

Opening the shortcut again reopens the same wallet service. Closing a browser
tab leaves the local wallet service running; use the shortcut's **Stop Wallet**
action or `./bin/veld-wallet stop` to stop it. A wallet launched separately from
the command line is not controlled by the shortcut. Stop that instance before
opening the app-menu wallet if it uses the same UI port.

The launcher authorizes your default browser with a fresh, one-time local
session. If you clear browser cookies, switch browsers, or the session expires,
stop the wallet and reopen it from the shortcut to authorize a new session.

Keep the package directory in place. After installing a verified update in a
different directory, stop the wallet and run that package's installer to update
the shortcut. `./bin/veld-wallet uninstall` removes only the shortcut. It does
not remove wallet data or browser storage. Keep encrypted wallet backups.

## Terminal and headless use

`./bin/veld-desktop --wallet` serves a wallet view without automatically opening
a browser or authorizing its signer. Use **Veld Wallet** on a graphical desktop
for wallet creation, import and signing. Do not expose the wallet listener to
other machines.

For mining, run `./bin/veld-node` and use its setup menu. See
[pool mining](pool-mining.md) for the Linux pool worker.
