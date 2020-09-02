#include<windows.h>
#include<iostream>
#include<CONIO.H>
#include<tchar.h>
#include <TlHelp32.h>
using std::cout;
using std::endl;

typedef struct _HOOK_DATA {
	char szApiName[128];			//Hook的api函数名
	char szModuleName[64];	//Hook的模块
	int HookCodeLen;		//Hook的指令长度
	BYTE oldEntry[16];		//api原始的初始化指令
	BYTE newEntry[16];		//用于Hook的指令
	ULONG_PTR HookPoint;	//Hook的位置
	ULONG_PTR JmpBackAddr;	//会跳的地址
	ULONG_PTR pfnTrampolineFun;//TrampolineFun
	ULONG_PTR pfnDetourFun;	//Hook过滤函数
}HOOK_DATA,*PHOOK_DATA;

#define HOOKLEN 5
HOOK_DATA MsgBoxHookData;

DWORD ProcesstoPid(char* Processname);
ULONG_PTR SkipJmpAddress(ULONG_PTR uAddress);
LPVOID GetAddress(char*,char*);

int WINAPI My_messageBoxA(HWND hWnd,LPCTSTR lpText,LPCTSTR lpCaption,UINT uTyoe);//Hook函数
int WINAPI OringinalMessageBox(HWND hWnd,LPCTSTR lpText,LPCTSTR lpCaption,UINT uType);
BOOL Inline_InstallHook(void);
BOOL InstallCodeHook(PHOOK_DATA pHookData);
void InitHookEntry(PHOOK_DATA pHookData);

int main() {
	Inline_InstallHook();
	system("pause");
}


DWORD ProcesstoPid(char* Processname) {
	HANDLE hProcessSnap = NULL;
	DWORD ProcessId = 0;
	PROCESSENTRY32 pe32 = { 0 };
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //打开进程快照
	if (hProcessSnap == (HANDLE)-1) {
		printf("\nCreateToolhelp32Snapshot() Error: %d", GetLastError());
		return 0;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hProcessSnap, &pe32)) //开始枚举进程
	{
		do
		{
			if (!stricmp(Processname, pe32.szExeFile)) //判断是否和提供的进程名相等，是，返回进程的ID
			{
				ProcessId = pe32.th32ProcessID;
				break;
			}
		} while (Process32Next(hProcessSnap, &pe32)); //继续枚举进程
	}
	else
	{
		printf("\nProcess32First() Error: %d", GetLastError());
		return 0;
	}
	CloseHandle(hProcessSnap); //关闭系统进程快照的句柄
	return ProcessId;
}

void InitHookEntry(PHOOK_DATA pHookData)
{
	if (pHookData == NULL
		|| pHookData->pfnDetourFun == NULL
		|| pHookData->HookPoint == NULL)
	{
		return;
	}

	pHookData->newEntry[0] = 0xE9; //Jmp 
	//计算跳转偏移并写入
	*(ULONG*)(pHookData->newEntry + 1) = (ULONG)pHookData->pfnDetourFun - (ULONG)pHookData->HookPoint - 5;//0xE9 式jmp的计算 5 byte


}


ULONG_PTR SkipJmpAddress(ULONG_PTR uAddress)
{
	ULONG_PTR TrueAddress = 0;
	PBYTE pFn = (PBYTE)uAddress;

	//IAT表类型的call FF 15 api_ptr
	if (memcmp(pFn, "\xFF\x15", 2) == 0) {
		TrueAddress = *(ULONG_PTR*)(pFn + 2);
		return TrueAddress;
	}

	//5 byte长跳转
	if (pFn[0] == 0xE9) {
		TrueAddress = (ULONG_PTR)pFn + *(ULONG_PTR*)(pFn + 1) + 5;
		return TrueAddress;
	}

	//3 byte短跳转
	if (pFn[0] == 0xEB) {
		TrueAddress = (ULONG_PTR)pFn + *(ULONG_PTR*)(pFn + 1) + 2;
		return TrueAddress;
	}
	
	return (ULONG_PTR)uAddress;
}

//获取指定模块api地址
LPVOID GetAddress(char* dllname, char* apiname)
{
	HMODULE hMod = 0;
	if (hMod = GetModuleHandle(dllname)) {
		return GetProcAddress(hMod, apiname);
	}
	else {
		hMod = LoadLibrary(dllname);
		return GetProcAddress(hMod, apiname);
	}
}

int __stdcall My_messageBoxA(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uTyoe)
{
	cout << "hook succeed!" << endl;
	return 0;
}

__declspec(naked)
int WINAPI OringinalMessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType)
{
	__asm {
		mov edi,edi
		push ebp
		mov ebp,esp
		jmp MsgBoxHookData.JmpBackAddr
	}
}

BOOL Inline_InstallHook(void)
{
	ZeroMemory(&MsgBoxHookData,sizeof(HOOK_DATA));
	strcpy(MsgBoxHookData.szApiName, "MessageBoxA"); 
	strcpy(MsgBoxHookData.szModuleName,"user32.dll");
	MsgBoxHookData.HookCodeLen = 5;
	MsgBoxHookData.HookPoint = (ULONG_PTR)GetAddress(MsgBoxHookData.szModuleName,MsgBoxHookData.szApiName);
	MsgBoxHookData.pfnTrampolineFun = (ULONG_PTR)OringinalMessageBox;
	MsgBoxHookData.pfnDetourFun = (ULONG_PTR)My_messageBoxA;

	return InstallCodeHook(&MsgBoxHookData);
}

BOOL InstallCodeHook(PHOOK_DATA pHookData)
{
	DWORD dwByteReturned = 0;
	DWORD dwPid = ProcesstoPid("message_box_test.exe");
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	BOOL bResult = FALSE;
	if (pHookData == NULL
		|| pHookData->HookPoint == 0
		|| pHookData->pfnDetourFun == NULL
		|| pHookData->pfnTrampolineFun == NULL)
	{
		return FALSE;
	}
	pHookData->pfnTrampolineFun = SkipJmpAddress(pHookData->pfnTrampolineFun);
	pHookData->HookPoint = SkipJmpAddress(pHookData->HookPoint);
	pHookData->JmpBackAddr = pHookData->HookPoint + pHookData->HookCodeLen;
	LPVOID OriginalAddr = (LPVOID)pHookData->HookPoint;
	printf("Address To HOOK=0x%08X\n", OriginalAddr);
	InitHookEntry(pHookData);//填充Inline Hook代码

	if (ReadProcessMemory(hProcess, OriginalAddr, pHookData->oldEntry, pHookData->HookCodeLen, &dwByteReturned))
	{
		if (WriteProcessMemory(hProcess, OriginalAddr, pHookData->newEntry, pHookData->HookCodeLen, &dwByteReturned))
		{
			printf("Install Hook write oK! WrittenCnt=%d\n", dwByteReturned);
			bResult = TRUE;
		}
	}
	return bResult;
}

