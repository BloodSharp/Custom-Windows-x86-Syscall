#ifndef _DRIVER_H_
#define _DRIVER_H_

#include <ddk/ntddk.h>
#include <ddk/ntapi.h>

#ifndef OBJ_KERNEL_HANDLE
#define OBJ_KERNEL_HANDLE 0x00000200
#endif //OBJ_KERNEL_HANDLE

typedef NTSTATUS (NTAPI * NTPROC) ();
typedef NTPROC * PNTPROC;

typedef struct tag_SYSTEM_SERVICE_TABLE {
  PNTPROC	ServiceTable; // array of entry points to the calls
	PDWORD	CounterTable; // array of usage counters
  ULONG ServiceLimit; // number of table entries
  PCHAR ArgumentTable; // array of argument counts
} SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE, **PPSYSTEM_SERVICE_TABLE;

typedef struct tag_SERVICE_DESCRIPTOR_TABLE {
  SYSTEM_SERVICE_TABLE ntoskrnl; // main native API table
  SYSTEM_SERVICE_TABLE win32k; // win subsystem, in shadow table
  SYSTEM_SERVICE_TABLE sst3;
  SYSTEM_SERVICE_TABLE sst4;
} SERVICE_DESCRIPTOR_TABLE, *PSERVICE_DESCRIPTOR_TABLE, **PPSERVICE_DESCRIPTOR_TABLE;

extern NTOSAPI SYSTEM_SERVICE_TABLE KeServiceDescriptorTable;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX{
	ULONG Count;
	SYSTEM_HANDLE_INFORMATION Handle[1];
}SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

//remove if is defined for you :P
NTSTATUS NTAPI PsLookupProcessByProcessId (/*IN*/ PVOID ProcessId,/*OUT*/ PEPROCESS *Process);

#endif //_DRIVER_H_