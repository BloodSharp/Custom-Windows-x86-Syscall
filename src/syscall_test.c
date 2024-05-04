#include <stdio.h>
#include <conio.h>

_declspec(naked) void MyKiSystemDispatch()
{
	_asm
	{
		lea edx,[esp+0x8];
		int 0x2A;
		ret;
	}
}


_declspec(naked) int _stdcall NtSumar(int a,int b)
{
	_asm
	{
		mov eax,0x80860001;
		mov ecx,eax;
		call MyKiSystemDispatch;
		ret 0x8;
	}
}

_declspec(naked) int _stdcall NtRestar(int a,int b)
{
	_asm
	{
		mov eax,0x80860002;
		mov ecx,eax;
		call MyKiSystemDispatch;
		ret 0x8;
	}
}

_declspec(naked) int _stdcall NtMultiplicar(int a,int b)
{
	_asm
	{
		mov eax,0x80860003;
		mov ecx,eax;
		call MyKiSystemDispatch;
		ret 0x8;
	}
}

_declspec(naked) int _stdcall NtDividir(int a,int b)
{
	_asm
	{
		mov eax,0x80860004;
		mov ecx,eax;
		call MyKiSystemDispatch;
		ret 0x8;
	}
}

_declspec(naked) int _stdcall NtLeerPuntero(int *a)
{
	_asm
	{
		mov eax,0x80860005;
		mov ecx,eax;
		call MyKiSystemDispatch;
		ret 0x4;
	}
}

int main(void)
{
	int a=10,b=2;
	printf("NtSumar (10+2)=%i\n",NtSumar(a,b));
	printf("NtRestar (10-2)=%i\n",NtRestar(a,b));
	printf("NtMultiplicar (10x2)=%i\n",NtMultiplicar(a,b));
	printf("NtDividir (10/2)=%i\n",NtDividir(a,b));
	printf("NtLeerPunteros (10)=%i\n",NtLeerPuntero(&a));
	getch();
	return 0;
}