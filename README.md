# spotify-win-adblock
Adblocker for the Windows desktop Spotify client. Works by blocking DNS lookups (by hooking WS2's getaddrinfo function) to hostnames that aren't necessary for the client to (mostly) function.

## Usage
 - Build project (debug builds write logs)
 - Copy `whitelist.txt` to your build folder
 - Start `injector.exe`
