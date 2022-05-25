// GTA 3 Skin filter ASI by Sergeanur
// 06/10/2014

#include <iostream>
#include <Windows.h>

#define PATCH_NOTHING	0x00
#define PATCH_CALL		0xE8
#define PATCH_JUMP		0xE9

static void call (DWORD address, void * function, BYTE type) {
	BYTE * patch = (BYTE *)address;
	if (type) *patch = type;	// JMP
	*(DWORD *)(patch+1) = ((DWORD)function-(address+5));	
}

enum
{
	VER_RETAIL_10 = 0,
	VER_RETAIL_11,
	VER_STEAM
};

int GetEXEVersion()
{
	if (*(DWORD*)0x59BACE == 0x5FB8158B) return VER_RETAIL_10;
	if (*(DWORD*)0x59BD8E == 0x606C158B) return VER_RETAIL_11;
	if (*(DWORD*)0x598E7E == 0x61AC158B) return VER_STEAM;
	return -1;
}

int ret = 0;
int some_unk_address = 0;

void __declspec(naked) ApplyFilter()
{
	// [ebx].filterAddressing = [ebx].filterAddressing & 0xFFFFFF00 | 2;
	__asm
	{
		mov     edx, [ebx+0x50]
		and     edx, 0xFFFFFF00
		or      edx, 2
		mov     [ebx+0x50], edx
		mov     edx, some_unk_address
		mov     edx, ds:[edx]
		jmp     ret
	}

}

void EnablePatch(int patch_addr, int _ret, int _some_unk_address)
{
	ret = _ret;
	some_unk_address = _some_unk_address;

	register DWORD dwValue;
	if (!VirtualProtect ((LPVOID)patch_addr, 5, PAGE_EXECUTE_READWRITE, &dwValue))
		return;

	call(patch_addr, &ApplyFilter, PATCH_JUMP);
	VirtualProtect ((LPVOID)patch_addr, 5, dwValue, NULL);
}

void Patch()
{
	switch (GetEXEVersion())
	{
	case VER_RETAIL_10:
		EnablePatch(0x59BACE, 0x59BAD4, 0x8F5FB8);
		break;
	case VER_RETAIL_11:
		EnablePatch(0x59BD8E, 0x59BD94, 0x8F606C);
		break;
	case VER_STEAM:
		EnablePatch(0x598E7E, 0x598E84, 0x9061AC);
		break;
	}
}

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved )
{
	//	TURN OFF DLL_THREAD_ATTACH & DLL_THREAD_DETACH
	DisableThreadLibraryCalls( hModule );
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		Patch();
		break;
	case DLL_PROCESS_DETACH:
		break;
	}

	return TRUE;
}