#include "stdafx.h"
#include <easyhook.h>
#include <fstream>
#include <WS2tcpip.h>
#include <include/capi/cef_urlrequest_capi.h>
#include <shlwapi.h>

#include "blacklist.h"
#include "whitelist.h"

const size_t whitelist_size = sizeof(whitelist) / sizeof(whitelist[0]);
const size_t blacklist_size = sizeof(blacklist) / sizeof(blacklist[0]);

#if _DEBUG
void printlog(const std::string& text) {
	// Write to file
	std::ofstream logfile("adblock_log.txt", std::ios_base::out | std::ios_base::app);
	logfile << text << std::endl;
}
#endif

bool listed(const char* item, const char* list[], size_t list_size) {
	for (size_t i = 0; i < list_size; i++) {
		if (PathMatchSpecExA(item, list[i], PMSF_NORMAL) == S_OK) {
			return true;
		}
	}
	return false;
}

INT WSAAPI getaddrinfoHook(const char* pNodeName, const char* pServiceName, const ADDRINFOA* pHints, PADDRINFOA* ppResult) {
	if (listed(pNodeName, whitelist, whitelist_size)) {
#if _DEBUG
		printlog(std::string("[+] getaddrinfo:\t\t").append(pNodeName));
#endif
		return getaddrinfo(pNodeName, pServiceName, pHints, ppResult);
	}
#if _DEBUG
	printlog(std::string("[-] getaddrinfo:\t\t").append(pNodeName));
#endif
	return EAI_FAIL;
}

cef_urlrequest_t* cef_urlrequest_createHook(_cef_request_t* request, struct _cef_urlrequest_client_t* client, struct _cef_request_context_t* request_context) {
	cef_string_userfree_utf16_t url_utf16 = request->get_url(request);
	char* url = new char[url_utf16->length + 1];
	url[url_utf16->length] = '\0';
	for (int i = 0; i < url_utf16->length; i++) url[i] = *(url_utf16->str + i);
	cef_string_userfree_utf16_free(url_utf16);
	if (listed(url, blacklist, blacklist_size)) {
#if _DEBUG
		printlog(std::string("[-] cef_urlrequest_create:\t").append(url));
#endif
		return NULL;
	}
#if _DEBUG
	printlog(std::string("[+] cef_urlrequest_create:\t").append(url));
#endif
	return cef_urlrequest_create(request, client, request_context);
}

extern "C" void __declspec(dllexport) __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo);
void __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo) {
#if _DEBUG
	// Init logging
	std::remove("adblock_log.txt");
	printlog("NativeInjectionEntryPoint called");
#endif

	HMODULE ws2_32 = GetModuleHandle(TEXT("ws2_32"));
	HMODULE libcef = GetModuleHandle(TEXT("libcef"));

	// If the threadId in the ACL is set to 0, then internally EasyHook uses GetCurrentThreadId()
	ULONG ACLEntries[1] = { 0 };

	bool fail = false;

	// Install the hook
	if (ws2_32 != NULL) {
		HOOK_TRACE_INFO hGetAddrInfoHook = { NULL };
		NTSTATUS resultGetAddrInfo = LhInstallHook(GetProcAddress(ws2_32, "getaddrinfo"), getaddrinfoHook, NULL, &hGetAddrInfoHook);
		// Disable the hook for the provided threadIds, enable for all others
		LhSetExclusiveACL(ACLEntries, 1, &hGetAddrInfoHook);

		fail = FAILED(resultGetAddrInfo);
	}

	// Install the hook
	if (libcef != NULL) {
		HOOK_TRACE_INFO hUrlRequestHook = { NULL };
		NTSTATUS resultUrlrequest = LhInstallHook(GetProcAddress(libcef, "cef_urlrequest_create"), cef_urlrequest_createHook, NULL, &hUrlRequestHook);
		// Disable the hook for the provided threadIds, enable for all others
		LhSetExclusiveACL(ACLEntries, 1, &hUrlRequestHook);

		fail = FAILED(resultUrlrequest);
	}

#if _DEBUG
	if (fail){
		std::wstring err(RtlGetLastErrorString());
		printlog("Failed to install hook: " + std::string(err.begin(), err.end()));
	} else {
		printlog("Hook installed successfully");
	}
#endif

	return;
}
