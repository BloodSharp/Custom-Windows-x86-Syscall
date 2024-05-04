#include "driver.h"

PSERVICE_DESCRIPTOR_TABLE DDKAPI GetServiceDescriptorShadowTableAddress(){
  PBYTE check=(PBYTE)KeAddSystemServiceTable;
	PSERVICE_DESCRIPTOR_TABLE rc=NULL;UINT i;
	for(i=0;i<1024;i++){
	  rc=*(PPSERVICE_DESCRIPTOR_TABLE)check;
		if(!MmIsAddressValid(rc)||((PVOID)rc==(PVOID)&KeServiceDescriptorTable)
		||(memcmp(rc,&KeServiceDescriptorTable,sizeof(SYSTEM_SERVICE_TABLE)))){
			check++;rc=NULL;
		}
		if(rc)
			break;
	}
	return rc;
}

PSYSTEM_MODULE_INFORMATION GetSystemModuleInformation(){
  PSYSTEM_MODULE_INFORMATION pSMInfo=NULL;
  NTSTATUS Status=STATUS_NO_MEMORY;
  ULONG SMInfoLen=1000;
  do{
    pSMInfo=ExAllocatePoolWithTag(PagedPool,SMInfoLen,0);
    if(!pSMInfo)
      break;
    Status=ZwQuerySystemInformation(SystemModuleInformation,pSMInfo,SMInfoLen,&SMInfoLen);
    if(!NT_SUCCESS(Status)){
      ExFreePoolWithTag(pSMInfo,0);
      pSMInfo=NULL;
    }
  }while(Status==STATUS_INFO_LENGTH_MISMATCH);
  return pSMInfo;
}

PSYSTEM_HANDLE_INFORMATION_EX GetSystemHandleInformation(){
  PSYSTEM_HANDLE_INFORMATION_EX pSHInfo=NULL;
  NTSTATUS Status=STATUS_NO_MEMORY;
  ULONG SMInfoLen=0x1000;
  do{
    pSHInfo=ExAllocatePoolWithTag(PagedPool,SMInfoLen,0);
    if(!pSHInfo)
      break;
    Status=ZwQuerySystemInformation(SystemHandleInformation,pSHInfo,SMInfoLen,&SMInfoLen);
    if(!NT_SUCCESS(Status)){
      ExFreePoolWithTag(pSHInfo,0);
      pSHInfo=NULL;
    }
  }while(Status==STATUS_INFO_LENGTH_MISMATCH);
  return pSHInfo;
}

PVOID GetKernelBaseAddressByAddress(PSYSTEM_MODULE_INFORMATION pSMInfo,PVOID pAddress,PVOID* pKernelAddr){
  if(pSMInfo){
    UINT i;
    for(i=0;i<pSMInfo->Count;i++){
      if(pAddress>=pSMInfo->Module[i].Base&&pAddress<=(pSMInfo->Module[i].Base+pSMInfo->Module[i].Size)){
        if(pKernelAddr)
          *pKernelAddr=(PVOID)pSMInfo->Module[i].Base;
        return &pSMInfo->Module[i].ImageName[pSMInfo->Module[i].PathLength];
      }
    }
  }
  return NULL;
}

ULONG RVAToRaw(PVOID lpBase,ULONG VirtualAddress,PULONG pImageBase){
  PIMAGE_DOS_HEADER pDosHeader=(PIMAGE_DOS_HEADER)lpBase;
  if(pDosHeader->e_magic!=IMAGE_DOS_SIGNATURE)
    return 0;
  PIMAGE_NT_HEADERS pNtHeader=(PIMAGE_NT_HEADERS)((PBYTE)lpBase+pDosHeader->e_lfanew);
  if(pNtHeader->Signature!=IMAGE_NT_SIGNATURE)
    return 0;
  if(pImageBase)
    *pImageBase=pNtHeader->OptionalHeader.ImageBase;
  UINT i;
  for(i=0;i<pNtHeader->FileHeader.NumberOfSections;i++){
    IMAGE_SECTION_HEADER *pSectionHeader=(PIMAGE_SECTION_HEADER)((LPBYTE)&pNtHeader->OptionalHeader+pNtHeader->FileHeader.SizeOfOptionalHeader+(i*sizeof(IMAGE_SECTION_HEADER)));
    if(VirtualAddress>=pSectionHeader->VirtualAddress&&VirtualAddress<=(pSectionHeader->VirtualAddress+pSectionHeader->SizeOfRawData))
      return VirtualAddress-pSectionHeader->VirtualAddress+pSectionHeader->PointerToRawData;
  }
  return 0;
}

HANDLE GetCsrssPid(){
  HANDLE CsrId=(HANDLE)0;
  PSYSTEM_HANDLE_INFORMATION_EX pHandles=GetSystemHandleInformation();
  if(pHandles){
    UINT i;
    for(i=0;i<pHandles->Count&&!CsrId;i++){
      OBJECT_ATTRIBUTES obj;CLIENT_ID cid;
      HANDLE Process,hObject;
      InitializeObjectAttributes(&obj,NULL,OBJ_KERNEL_HANDLE,NULL,NULL);
      cid.UniqueProcess=(HANDLE)pHandles->Handle[i].ProcessId;
      cid.UniqueThread=0;
      if(NT_SUCCESS(NtOpenProcess(&Process,PROCESS_DUP_HANDLE,&obj,&cid))){
        if(NT_SUCCESS(ZwDuplicateObject(Process,(PHANDLE)(pHandles->Handle[i].Handle),NtCurrentProcess(),&hObject,0,FALSE,DUPLICATE_SAME_ACCESS))){
          UCHAR Buff[0x200];
          POBJECT_NAME_INFORMATION ObjName=(PVOID)&Buff;
          if(NT_SUCCESS(ZwQueryObject(hObject,ObjectTypeInformation,ObjName,sizeof(Buff),NULL))){
            if(ObjName->Name.Buffer&&(!wcsncmp(L"Port",ObjName->Name.Buffer,4)||!wcsncmp(L"ALPC Port",ObjName->Name.Buffer,9))){
              if(NT_SUCCESS(ZwQueryObject(hObject,ObjectNameInformation,ObjName,sizeof(Buff),NULL))){
                if(ObjName->Name.Buffer&&!wcsncmp(L"\\\\Windows\\\\ApiPort",ObjName->Name.Buffer,20))
                  CsrId=(HANDLE)pHandles->Handle[i].ProcessId;
              }
            }
          }
          ZwClose(hObject);
        }
        NtClose(Process);
      }
    }
    ExFreePoolWithTag(pHandles,0);
  }
  return CsrId;
}

VOID RestoreHooks(PSYSTEM_MODULE_INFORMATION pSMInfo,PSYSTEM_SERVICE_TABLE pTable){
  CHAR sKernelPath[1024]={0};PVOID pKernelAddres=NULL;
  PCHAR pKrnlMod=GetKernelBaseAddressByAddress(pSMInfo,pTable->ServiceTable,&pKernelAddres);
  if(pKrnlMod&&pKernelAddres){
    ULONG uImageBase=0;
    ULONG uSSDTRaw=RVAToRaw(pKernelAddres,(ULONG)pTable->ServiceTable-(ULONG)pKernelAddres,&uImageBase);
    if(uSSDTRaw!=0&&uImageBase!=0){
      ANSI_STRING aFileName;UNICODE_STRING uFileName;
      sprintf(sKernelPath,"\\\\SystemRoot\\\\System32\\\\%s",pKrnlMod);
      RtlInitAnsiString(&aFileName,sKernelPath);
      if(NT_SUCCESS(RtlAnsiStringToUnicodeString(&uFileName,&aFileName,TRUE))){
        OBJECT_ATTRIBUTES ObjAttr;HANDLE hFile;IO_STATUS_BLOCK ioStatus;
        InitializeObjectAttributes(&ObjAttr,&uFileName,OBJ_CASE_INSENSITIVE,NULL,NULL);
        if(NT_SUCCESS(ZwOpenFile(&hFile,FILE_READ_DATA,&ObjAttr,&ioStatus,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,FILE_SYNCHRONOUS_IO_NONALERT))){
          PULONG lpArraySSDT=ExAllocatePool(PagedPool,pTable->ServiceLimit*sizeof(ULONG));
          if(lpArraySSDT!=NULL){
            FILE_POSITION_INFORMATION FilePos={{{uSSDTRaw,0}}};
            if(NT_SUCCESS(ZwSetInformationFile(hFile,&ioStatus,&FilePos,sizeof(FILE_POSITION_INFORMATION),FilePositionInformation))){
              if(NT_SUCCESS(ZwReadFile(hFile,NULL,NULL,NULL,&ioStatus,lpArraySSDT,pTable->ServiceLimit*sizeof(ULONG),NULL,NULL))){
                asm(
                  "cli;\\r\\n" /*dissable interrupt*/
                  "mov %cr0,%eax;\\r\\n" /*mov CR0 register into EAX*/
                  "and $0xfffeffff,%eax;\\r\\n" /*disable WP bit*/
                  "mov %eax,%cr0;\\r\\n" /*update register*/
                  "sti" /*enable interrupt*/
                );
                UINT i=0;
                for(i=0;i<pTable->ServiceLimit;i++){
                  NTPROC pOrigAddress=(NTPROC)(lpArraySSDT[i]-uImageBase+pKernelAddres);
                  if(pTable->ServiceTable[i]!=pOrigAddress){
                    LPCSTR sHooker=GetKernelBaseAddressByAddress(pSMInfo,pTable->ServiceTable[i],NULL);
                    if(!sHooker)sHooker="Unknown";
                    DbgPrint("Func %d Hooked by %s! Current: %p - Original: %p",i,sHooker,pTable->ServiceTable[i],pOrigAddress);
                    pTable->ServiceTable[i]=pOrigAddress;
                    DbgPrint("Func %d Unhook %s",i,(pTable->ServiceTable[i]==pOrigAddress?"OK":"FAIL"));
                  }
                }
                asm(
                  "cli;\\r\\n" /*dissable interrupt*/
                  "mov %cr0,%eax;\\r\\n" /*mov CR0 register into EAX*/
                  "or $0x00010000,%eax;\\r\\n" /*enable WP bit*/
                  "mov %eax,%cr0;\\r\\n" /*update register*/
                  "sti" /*enable interrupt*/
                );
              }else
                DbgPrint("Error: Can't Read Kernel File");
            }else
              DbgPrint("Error: Can't Change Kernel File Position");
            ExFreePool(lpArraySSDT);
          }else
            DbgPrint("Error: Can't Alloc Memory!\\n");
          NtClose(hFile);
        }else
          DbgPrint("Error: Can't Open Kernel File");
        RtlFreeUnicodeString(&uFileName);
      }else
        DbgPrint("Error: Can't Convert to Unicode");
    }else
      DbgPrint("Error: Can't Get SSDT RAW Address");
  }else
    DbgPrint("Error: Can't Get Kernel Address!\\n");
}

VOID FindHooks(){
  DbgPrint("Start Finding Hooks in SSDT!\\n");
  PSYSTEM_MODULE_INFORMATION pSMInfo=GetSystemModuleInformation();
  if(pSMInfo){
    //ntoskrnl
    DbgPrint("Finding Hooks in NTOSKrnl!\\n");
    RestoreHooks(pSMInfo,&KeServiceDescriptorTable);
    DbgPrint("Find Hooks in NTOSKrnl Complete!\\n");
    //win32k
    PSERVICE_DESCRIPTOR_TABLE pShadow=GetServiceDescriptorShadowTableAddress();
    if(pShadow){
      PEPROCESS EProcess;
      HANDLE hCsrssPid=GetCsrssPid();
      //we need to do this to have access to win32k memory...
      if(hCsrssPid&&NT_SUCCESS(PsLookupProcessByProcessId(hCsrssPid,&EProcess))){
        KeAttachProcess(EProcess);
        DbgPrint("Finding Hooks in Win32k!\\n");
        RestoreHooks(pSMInfo,&pShadow->win32k);
        DbgPrint("Find Hooks in Win32k Complete!\\n");
        KeDetachProcess();
        ObDereferenceObject(EProcess);
      }else
        DbgPrint("Error: Can't get CSRSS Process Id!\\n");
    }else
      DbgPrint("Error: Can't get Win32k Address!\\n");
    ExFreePoolWithTag(pSMInfo,0);
  }else
    DbgPrint("Error: GetSystemModuleInformation Fail!\\n");
  DbgPrint("End Finding Hooks in SSDT!\\n");
}

VOID DDKAPI DriverUnload(IN PDRIVER_OBJECT DriverObject) {
  DbgPrint("DriverUnload()!\\n");
  return;
}

__declspec (dllexport) NTSTATUS DDKAPI DriverEntry(IN PDRIVER_OBJECT pDriverObject,IN PUNICODE_STRING RegistryPath) {
  NTSTATUS NtStatus=STATUS_SUCCESS;
  pDriverObject->DriverUnload=DriverUnload;
  DbgPrint("DriverEntry()!\\n");
  FindHooks();
  return NtStatus;
}