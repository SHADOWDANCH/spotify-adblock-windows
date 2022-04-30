# spotify-adblock-windows
Adblocker for the Windows desktop Spotify client. Works by blocking DNS lookups and url request to not whitelisted URLs
## Usage
 - Install NuGet packages
 - Build project (debug builds write logs)
 - Copy `packages\EasyHookNativePackage.redist.2.7.7097\build\native\bin\x64\v141\Release\EasyHook64.dll` to build directory (Release/)
 - Run `injector.exe` or `injector.exe path/to/Spotify.exe`
 ## Thanks to
 - [csprl](https://github.com/csprl) for [original project](https://github.com/csprl/spotify-win-adblock)
 - [abba23](https://github.com/abba23) for [list of spotify ad hosts](https://github.com/abba23/spotify-adblock)
