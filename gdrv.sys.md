
```C++
0xC3502004-0x1400026F0
__int64 __fastcall mapphy_1400026F0(_DEVICE_OBJECT *pDevObj, _gdrv_t *inputBuffer)
{
  unsigned int io_space; // eax
  signed int interface_type; // r14d
  unsigned int bus; // r15d
  uintptr_t phys_addr_begin; // rbx
  NTSTATUS ns; // edi
  BOOLEAN v8_bool; // bl
  BOOLEAN v9_bool; // al
  DWORD v10_size; // eax
  PVOID LowPart; // rax
  PVOID VirtualBaseAddress; // [rsp+58h] [rbp-39h] BYREF
  void *SectionHandle; // [rsp+60h] [rbp-31h] BYREF
  ULONG v15_io_space; // [rsp+68h] [rbp-29h] BYREF
  LARGE_INTEGER phys_addr_end; // [rsp+70h] [rbp-21h] BYREF
  ULONG_PTR ViewSize; // [rsp+78h] [rbp-19h] BYREF
  union _LARGE_INTEGER SectionOffset; // [rsp+80h] [rbp-11h] BYREF
  LARGE_INTEGER TranslatedAddress; // [rsp+88h] [rbp-9h] BYREF
  PVOID Object; // [rsp+90h] [rbp-1h] BYREF
  struct _UNICODE_STRING DestinationString; // [rsp+98h] [rbp+7h] BYREF
  struct _OBJECT_ATTRIBUTES ObjectAttributes; // [rsp+A8h] [rbp+17h] BYREF
  ULONG AddressSpace_io_space; // [rsp+100h] [rbp+6Fh] BYREF

  io_space = inputBuffer->io_space;
  interface_type = inputBuffer->interface_type;
  bus = inputBuffer->bus;
  phys_addr_begin = inputBuffer->phys_addr;
  SectionHandle = 0i64;
  Object = 0i64;
  v15_io_space = io_space;
  AddressSpace_io_space = io_space;
  ViewSize = inputBuffer->size;
  RtlInitUnicodeString(&DestinationString, L"\\Device\\PhysicalMemory");
  ObjectAttributes.RootDirectory = 0i64;
  ObjectAttributes.ObjectName = &DestinationString;
  ObjectAttributes.Length = 48;
  ObjectAttributes.Attributes = 64;
  *(_OWORD *)&ObjectAttributes.SecurityDescriptor = 0i64;
  ns = ZwOpenSection(&SectionHandle, 0xF001Fu, &ObjectAttributes);
  if ( ns >= 0 )
  {
    ns = ObReferenceObjectByHandle(SectionHandle, 0xF001Fu, 0i64, 0, &Object, 0i64);
    if ( ns >= 0 )
    {
      phys_addr_end.QuadPart = phys_addr_begin + (unsigned int)ViewSize;
      v8_bool = HalTranslateBusAddress(
                  (INTERFACE_TYPE)interface_type,
                  bus,
                  (PHYSICAL_ADDRESS)phys_addr_begin,
                  &AddressSpace_io_space,
                  &TranslatedAddress);
      v9_bool = HalTranslateBusAddress(
                  (INTERFACE_TYPE)interface_type,
                  bus,
                  phys_addr_end,
                  &v15_io_space,
                  &phys_addr_end);
      if ( !v8_bool
        || !v9_bool
        || (v10_size = phys_addr_end.LowPart - TranslatedAddress.LowPart,
            phys_addr_end.LowPart == TranslatedAddress.LowPart) )
      {
        ns = 0xC0000001;
        goto LABEL_12;
      }
      ViewSize = v10_size;
      if ( AddressSpace_io_space )
      {
        LowPart = (PVOID)TranslatedAddress.LowPart;
LABEL_10:
        *(_QWORD *)&inputBuffer->interface_type = LowPart;
        ns = 0;
        goto LABEL_12;
      }
      VirtualBaseAddress = 0i64;
      SectionOffset = TranslatedAddress;
      ns = ZwMapViewOfSection(
             SectionHandle,
             (HANDLE)0xFFFFFFFFFFFFFFFFi64,
             &VirtualBaseAddress,
             0i64,
             v10_size,
             &SectionOffset,
             &ViewSize,
             ViewShare,
             0,
             0x204u);
      if ( ns >= 0 )
      {
        VirtualBaseAddress = (char *)VirtualBaseAddress
                           + TranslatedAddress.LowPart
                           - (unsigned __int64)SectionOffset.LowPart;
        DbgPrint("VirtualAddress=0x%x", VirtualBaseAddress);
        LowPart = VirtualBaseAddress;
        goto LABEL_10;
      }
    }
LABEL_12:
    ZwClose(SectionHandle);
  }
  return (unsigned int)ns;
}
```

```C++
0xC3502008-0x140001BCB
DbgPrint("InputBufferLength=%d,szieof(PVOID)=%d", Options, 8i64);
if ( Options < 8 )
 {
   v6 = -1073741670;
   DbgPrint("MAPMEM.SYS: ZwUnmapViewOfSection failed\n");
 }
 else
 {
   v6 = ZwUnmapViewOfSection((HANDLE)0xFFFFFFFFFFFFFFFFi64, *(PVOID *)&MasterIrp->Type);
   DbgPrint("MAPMEM.SYS: memory successfully unmapped\n");
 }
```
