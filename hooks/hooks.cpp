#include "stdafx.h"
#include <easyhook.h>
#include <fstream>
#include <string>
#include <list>
#include <stdio.h>
#include <time.h>
#include <WS2tcpip.h>

std::list<std::string> blacklist = {};

void Log(const std::string& severity, const std::string& text)
{
#ifdef _DEBUG
	// Get date
	char timeBuff[20];
	struct tm *sTm;
	time_t now = time(0);
	sTm = localtime(&now);
	strftime(timeBuff, sizeof(timeBuff), "%Y-%m-%d %H:%M:%S", sTm);

	// Write to file
	std::ofstream logfile("adblock_log.txt", std::ios_base::out | std::ios_base::app);
	logfile << "[" << timeBuff << "][" << severity << "] " << text << std::endl;

	//MessageBoxA(NULL, text.c_str(), "Adblocker", MB_OK);
#endif
}

INT WSAAPI getaddrinfoHook(const char* pNodeName, const char* pServiceName, const ADDRINFOA* pHints, PADDRINFOA* ppResult)
{
	if (std::find(blacklist.begin(), blacklist.end(), pNodeName) != blacklist.end())
	{
		Log("INFO", "Blocking " + std::string(pNodeName));
		pNodeName = "0.0.0.0";
	}
	else
	{
		Log("INFO", "Allowing " + std::string(pNodeName));
	}

	return getaddrinfo(pNodeName, pServiceName, pHints, ppResult);
}

extern "C" void __declspec(dllexport) __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo);
void __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo)
{
	// Init logging
	std::remove("adblock_log.txt");
	Log("INFO", "NativeInjectionEntryPoint called");

	// Read blacklist file
	std::ifstream infile("blacklist.txt");
	for (std::string line; std::getline(infile, line);)
	{
		blacklist.push_back(line);
	}
	Log("INFO", "Read " + std::to_string(blacklist.size()) + " entries from blacklist");

	// Perform hooking
	HOOK_TRACE_INFO hHook = { NULL };

	// Install the hook
	NTSTATUS result = LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("ws2_32")), "getaddrinfo"), getaddrinfoHook, NULL, &hHook);
	if (FAILED(result))
	{
		std::wstring err(RtlGetLastErrorString());
		Log("ERROR", "Failed to install hook: " + std::string(err.begin(), err.end()));
	}
	else
	{
		Log("INFO", "Hook installed successfully");
	}

	// If the threadId in the ACL is set to 0, then internally EasyHook uses GetCurrentThreadId()
	ULONG ACLEntries[1] = { 0 };

	// Disable the hook for the provided threadIds, enable for all others
	LhSetExclusiveACL(ACLEntries, 1, &hHook);

	return;
}