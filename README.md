# spotify-win-adblock
Adblocker for the Windows desktop Spotify client. Works by blocking DNS lookups (by hooking WS2's getaddrinfo function) to hostnames known for serving advertisements.

## Usage
 - Build project (debug builds write logs)
 - Create a `blacklist.txt` file containing all the hostnames you want to block (one per line)
 - Start `injector.exe`
