#include <iostream>
#include <fstream>
#include <string>
#include <easyhook.h>

int FailWait()
{
	std::wcout << "Press Enter to exit";
	std::wstring input;
	std::getline(std::wcin, input);

	return 0;
}

int main(int argc, char* argv[])
{
	std::string spotifyPath;
	
	if (argc == 2)
	{
		std::string ws(argv[1]);
		spotifyPath = std::string(ws.begin(), ws.end());
	}
	else
	{
		// Attempt to locate Spotify
		std::string appDataPath = std::string(getenv("APPDATA"));
		std::ifstream spot(appDataPath + "\\Spotify\\Spotify.exe");
		if (!spot.good())
		{
			std::cout << "Automatic detection failed. Launch with injector.exe <path to Spotify.exe>" << std::endl;
			return FailWait();
		}

		spotifyPath = appDataPath + "\\Spotify\\Spotify.exe";
	}

	// Start Spotify
	PROCESS_INFORMATION pi;
	STARTUPINFOA si = {sizeof(si)};
	bool bSuccess = CreateProcessA(spotifyPath.c_str(), NULL, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
	if (!bSuccess)
	{
		std::cout << "Couldn't launch Spotify!" << std::endl;
		
		return FailWait();
	}

	// Get PID
	DWORD processId = pi.dwProcessId;
	WCHAR* dllToInject = (WCHAR*)L"hooks.dll";

	// Inject hooks.dll into Spotify
	NTSTATUS nt = RhInjectLibrary(processId, 0, EASYHOOK_INJECT_DEFAULT, NULL, dllToInject, NULL, NULL);
	if (nt != 0)
	{
		printf("RhInjectLibrary failed with error code = %d\n", nt);
		PWCHAR err = RtlGetLastErrorString();
		std::wcout << err << "\n";

		return FailWait();
	}
	
	std::cout << "Injected successfully!" << std::endl;

	return 0;
}

#if !_DEBUG
int _stdcall WinMain(struct HINSTANCE__* hInstance, struct HINSTANCE__* hPrevInstance, char* lpszCmdLine, int nCmdShow)
{
	return main(__argc, __argv);
}
#endif
