#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>

#define MAKELONG2(a,b) ((LONG)(((WORD)(a))|((DWORD)((WORD)(b)))<<16))
#define ALLPROCESSORS(x) {KAFFINITY cpuAffinity;int i=0;cpuAffinity=KeQueryActiveProcessors();for(;i<KeNumberProcessors;i++){KAFFINITY curAffinity=cpuAffinity&(1<<i);if(curAffinity==0)break;KeSetSystemAffinityThread(curAffinity);x;}KeSetSystemAffinityThread(cpuAffinity);}

NTSTATUS NTAPI userspace_memory_read(PVOID dest,PVOID src,SIZE_T size);

typedef struct
{
	WORD LowOffset;
	WORD selector;
	BYTE unused_lo;
	BYTE unused_hi:5;
	BYTE DPL:2; 
	BYTE P:1;
	WORD HiOffset;
}IDTENTRY;
typedef struct
{
	WORD IDTLimit;
	WORD LowIDTbase;
	WORD HiIDTbase;
}IDTINFO;

INT NTAPI ZwSumar(INT a,INT b)
{
	return a+b;
}

INT NTAPI ZwRestar(INT a,INT b)
{
	return a-b;
}

INT NTAPI ZwMultiplicar(INT a,INT b)
{
	return a*b;
}

INT NTAPI ZwDividir(INT a,INT b)
{
	return a/b;
}

INT NTAPI ZwLeerPuntero(INT *a)
{
	//return *a;
	INT c;
	userspace_memory_read(&c,a,4);
	return c;
}

NTSTATUS NTAPI userspace_memory_read(PVOID dest,PVOID src,SIZE_T size)
{
	KAPC_STATE kapc;
	KeStackAttachProcess(PsGetCurrentProcess(),&kapc);
	RtlCopyMemory(dest,src,size);
	KeUnstackDetachProcess(&kapc);
	return 0;
}

DWORD dwRetVal,dwCurrentStack,dwCallerAddress;
__declspec(naked) VOID CustomDispatchs()//(DWORD dwIndex,DWORD dwStack)
{
	__asm
	{
		push ebp;
		mov ebp,esp;

		mov dwCurrentStack,esp;
		mov esp,[ebp+0xC];

		sub [ebp+0x8],0x80860000;
		cmp [ebp+0x8],0x1;
		jz gotoSuma;
		cmp [ebp+0x8],0x2;
		jz gotoResta;
		cmp [ebp+0x8],0x3;
		jz gotoProducto;
		cmp [ebp+0x8],0x4;
		jz gotoDivision;
		cmp [ebp+0x8],0x5;
		jz gotoLeerPunteros;
		jmp fin;

	gotoSuma:
		call ZwSumar;
		jmp fin;
	gotoResta:
		call ZwRestar;
		jmp fin;
	gotoProducto:
		call ZwMultiplicar;
		jmp fin;
	gotoDivision:
		call ZwDividir;
		jmp fin;
	gotoLeerPunteros:
		call ZwLeerPuntero;
		//jmp fin;
	fin:
		mov dwRetVal,eax;
		mov esp,dwCurrentStack;
		pop ebp;
		ret 0x8;
	}
}

DWORD pOrig_KiSystemGetTickCount;
__declspec(naked) VOID HOOK_KiSystemGetTickCount()
{
	__asm
	{
		pushad;
		pushfd;
		push fs;
		mov bx,0x30;
		mov fs,bx;
		push ds;
		push es;

		cmp eax,ecx;
		jnz NoEsMiFuncion;
		cmp eax,0x80860000;
		js NoEsMiFuncion;
		cmp eax,0x80860007;
		jns NoEsMiFuncion;

		push eax;
		mov eax,[edx-0x4];
		mov dwCallerAddress,eax;
		pop eax;
		//mov dwCallerAddress,[edx-0x4];

		push edx;
		push edx;
		push eax;
		call CustomDispatchs;
		pop edx;

		push eax;
		mov eax,dwCallerAddress;
		mov [edx-0x4],eax;
		pop eax;
		//mov [edx-0x4],dwCallerAddress;

		pop es;
		pop ds;
		pop fs;
		popfd;
		popad;

		mov eax,dwRetVal;
		iretd;

	NoEsMiFuncion:
		pop es;
		pop ds;
		pop fs;
		popfd;
		popad;
		popfd;
		popad;
		jmp pOrig_KiSystemGetTickCount;
	}
}

VOID HookInterrupts()
{
	IDTINFO idt_info;
	IDTENTRY* idt_entries;
	IDTENTRY* int2e_entry;
	__asm sidt idt_info;
	idt_entries=(IDTENTRY*)MAKELONG2(idt_info.LowIDTbase,idt_info.HiIDTbase);
	pOrig_KiSystemGetTickCount = MAKELONG2(idt_entries[0x2A].LowOffset,idt_entries[0x2A].HiOffset);
	int2e_entry = &(idt_entries[0x2A]);
	__asm
	{
		cli;
		lea eax,HOOK_KiSystemGetTickCount;
		mov ebx, int2e_entry;
		mov [ebx],ax;
		shr eax,16;
		mov [ebx+6],ax;
		lidt idt_info;
		sti;
	}
}
VOID UnhookInterrupts()
{
	IDTINFO idt_info;
	IDTENTRY* idt_entries;
	IDTENTRY* int2e_entry;
	__asm sidt idt_info;
	idt_entries = (IDTENTRY*)MAKELONG2(idt_info.LowIDTbase,idt_info.HiIDTbase);
	int2e_entry = &(idt_entries[0x2A]);
	__asm
	{
		cli;
		mov eax,pOrig_KiSystemGetTickCount;
		mov ebx,int2e_entry;
		mov [ebx],ax;
		shr eax,16;
		mov [ebx+6],ax;
		lidt idt_info;
		sti;
	}
}

VOID DriverUnload(IN PDRIVER_OBJECT pDriverObject)
{
	ALLPROCESSORS(UnhookInterrupts())
}

EXTERN_C NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject,IN PUNICODE_STRING RegistryPath)
{
	pDriverObject->DriverUnload=DriverUnload;
	ALLPROCESSORS(HookInterrupts())
	return STATUS_SUCCESS;
}