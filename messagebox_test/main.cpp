#include"windows.h"
#include<iostream>
using std::cout;
using std::endl;
using std::cin;

void show_msg();
void show_several_bytes();
void show_byte(ULONG addr,int length = 1);

int main() {
	while (1){
		cout << "TEST YOUR HOOK" << endl;
		cout << "1.show messagebox;"<<endl;
		cout << "2.show several bytes of the api;"<<endl;
		cout << "input the index:" << endl;
		char input;
		cin >> input;
		if (input == '1') {
			show_msg();
		}
		else if (input == '2') {
			show_several_bytes();
		}
		else {
			cout << "WRONG INPUT!\n";
		}
		cout << endl;
	}
}

void show_msg() {
	MessageBox(NULL, "pop-ups","pop-ups", MB_OK);
}

void show_several_bytes() {
	HMODULE user32_mod = GetModuleHandle("user32.dll");
	ULONG msgbox_addr = (ULONG)GetProcAddress(user32_mod,"MessageBoxA");
	show_byte(msgbox_addr,5);
}

void show_byte(ULONG addr,int length) {
	printf("0x%p 开始的 %d 个字节：", addr, length);
	for (int i = 0; i < length; i++) {
		BYTE t;
		__asm {
			mov		eax, addr
			mov		al, byte ptr[eax]
			mov		t, al
		}
		printf("%x ",t);
		addr = addr + 1;
	}
	cout << endl;
}