#include<windows.h>
#include<iostream>
#include <imagehlp.h>
#pragma comment(lib,"imagehlp.lib")

/*
from《加密与解密》第十三章
*/

using std::cout;
using std::endl;


//指向原始函数的函数指针
typedef int (WINAPI* POI_MessageBoxA)(
	HWND hWnd,
	LPCTSTR lpText,
	LPCTSTR lpCaption,
	UINT uType
	);

POI_MessageBoxA oldMessageBox = NULL;

//与原函数调用一致的函数进行替换，使用WINAPI进行调用约定的约束
int WINAPI My_MessageBoxA(
	HWND hWnd,
	LPCTSTR lpText,
	LPCTSTR lpCaption,
	UINT uType
);

VOID show_msg_box(char* msg) {
	MessageBox(NULL,msg,"Test",MB_OKCANCEL);
}

BOOL InstallModuleIATHook(
	HMODULE hModToHook,//待Hook Module
	char* szModuleName,//模块名字
	char* szFuncName,//目标函数名
	PVOID DetourFunc,//Detour函数
	PULONG* pThunkPointer,//指向修改位置的指针
	ULONG* pOriginalFuncAddr//接受原始函数地址
);

int main() {
	char str[] = "yes";
	show_msg_box(str);

	//初始化一些数据用于存储
	HMODULE hCurExe = GetModuleHandle(NULL);
	PULONG_PTR pt;
	ULONG_PTR OrginalAddr;
	InstallModuleIATHook(hCurExe,"user32.dll","MessageBoxA", (PVOID)My_MessageBoxA,&pt, &OrginalAddr);
	show_msg_box(str);
}

//与原函数调用一致的函数进行替换，使用WINAPI进行调用约定的约束
int WINAPI My_MessageBoxA(
	HWND hWnd,
	LPCTSTR lpText,
	LPCTSTR lpCaption,
	UINT uType
) {
	cout << "Hook success!" << endl;
	system("cmd.exe /c calc.exe");
	system("pause");
	//oldMessageBox(NULL,"Hooked!","Hooked!",MB_OK);
	return 1;
}

BOOL InstallModuleIATHook(
	HMODULE hModToHook,
	char* szModuleName,
	char* szFuncName,
	PVOID DetourFunc,
	PULONG* pThunkPointer,
	ULONG* pOriginalFuncAddr
)
{
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor;
	PIMAGE_THUNK_DATA pThunkData;
	ULONG ulSize;
	HMODULE hModule = 0;
	ULONG TargetFunAddr;
	PULONG lpAddr;
	char* szModName;
	BOOL result = FALSE;
	BOOL bRetn	= FALSE;

	//获取目标函数地址
	hModule = LoadLibrary(szModuleName);
	TargetFunAddr = (ULONG)GetProcAddress(hModule, szFuncName);

	//获取待Hook模块输入表的起始地址
	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(hModToHook,TRUE,IMAGE_DIRECTORY_ENTRY_IMPORT,&ulSize);

	while (pImportDescriptor->FirstThunk)//FirstThunk里存储的就是IAT的RVA
	{
		szModName = (char*)((PBYTE)hModToHook+pImportDescriptor->Name);//找到需要Hook的模块
		cout << "当前模块名称：" << szModName << endl;
		if (stricmp(szModName, szModuleName)!= 0) {
			cout << "不是需求匹配的模块！" << endl;
			pImportDescriptor++;
			continue;
		}
		pThunkData = (PIMAGE_THUNK_DATA)((BYTE*)hModToHook + pImportDescriptor->FirstThunk);
		while (pThunkData->u1.Function)
		{
			lpAddr = (ULONG*)pThunkData;
			if ((*lpAddr) == TargetFunAddr)
			{
				cout << "找到目标地址！" << endl;

				//修改输入表内存页为可写
				DWORD dwOldProtect;
				MEMORY_BASIC_INFORMATION mbi;//存放虚拟页
				VirtualQuery(lpAddr, &mbi, sizeof(mbi));//找到目标虚拟页
				bRetn = VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);//将虚拟页修改为可wrx
				if (bRetn) {
					if (pThunkData != NULL) {//修改成功
						*pThunkPointer = lpAddr;
					}
					if (pOriginalFuncAddr != NULL) {
						*pOriginalFuncAddr = *lpAddr;
					}
					*lpAddr = (ULONG)DetourFunc;//修改地址
					result = TRUE;
					//恢复内存地址
					VirtualProtect(mbi.BaseAddress, mbi.RegionSize, dwOldProtect, 0);
					cout << "目标函数：" << szFuncName << "地址被Hook为" << DetourFunc <<"。"<< endl;
					
				}
				break;
			}
			pThunkData++;
		}
		pImportDescriptor++;
	}
	FreeLibrary(hModule);

	//oldMessageBox = (POI_MessageBoxA)pOriginalFuncAddr;

	return result;
}
