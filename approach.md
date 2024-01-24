## Native PE
### Exception Handle: Easy
```c
if (ExcepDir.Size!=0)
{
      PIMAGE_RUNTIME_FUNCTION_ENTRY pImgRuntimeFuncEntry = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(pPeBaseAddress + pPeHdrs->pEntryExceptionDataDir->VirtualAddress);
      if (!RtlAddFunctionTable(pImgRuntimeFuncEntry, (pPeHdrs->pEntryExceptionDataDir->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)), pPeBaseAddress)) {
            PRINT_WINAPI_ERR("RtlAddFunctionTable");
      }
}
```
### TLS Callback: Easy
```c
if (TLSDir.SizeSize!=)
{
      PIMAGE_TLS_DIRECTORY    pImgTlsDirectory        = (PIMAGE_TLS_DIRECTORY)(pPeBaseAddress + pPeHdrs->pEntryTLSDataDir->VirtualAddress);
      PIMAGE_TLS_CALLBACK*    pImgTlsCallback         = (PIMAGE_TLS_CALLBACK*)(pImgTlsDirectory->AddressOfCallBacks);
      for (int i = 0; pImgTlsCallback[i] != NULL; i++){
            pImgTlsCallback[i]((LPVOID)pPeBaseAddress, DLL_PROCESS_ATTACH, NULL);
      }
}
```

### Command Line Support: Hard

### DLL Support: Easy (check file type)

### Export Function Support: Medium

### (Optional)x86 support: Medium

### (Optional)Delay Import: Hard
```c
 rva = ntnew->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress;
    
    if(rva != 0) {
      DPRINT("Processing Delayed Import Table");
      
      del = RVA2VA(PIMAGE_DELAYLOAD_DESCRIPTOR, cs, rva);
      
      // For each DLL
      for (;del->DllNameRVA != 0; del++) {
        name = RVA2VA(PCHAR, cs, del->DllNameRVA);
        
        dll = xGetLibAddress(inst, name);
        
        if(dll == NULL) continue;
        
        // Resolve the API for this library
        oft = RVA2VA(PIMAGE_THUNK_DATA, cs, del->ImportNameTableRVA);
        ft  = RVA2VA(PIMAGE_THUNK_DATA, cs, del->ImportAddressTableRVA);
          
        // For each API
        for (;; oft++, ft++) {
          // No API left?
          if (oft->u1.AddressOfData == 0) break;

          // Resolve by ordinal?
          if (IMAGE_SNAP_BY_ORDINAL(oft->u1.Ordinal)) {
            ft->u1.Function = (ULONG_PTR)xGetProcAddress(inst, dll, NULL, oft->u1.Ordinal);
          } else {
            // Resolve by name
            ibn = RVA2VA(PIMAGE_IMPORT_BY_NAME, cs, oft->u1.AddressOfData);
            ft->u1.Function = (ULONG_PTR)xGetProcAddress(inst, dll, ibn->Name, 0);
          }
        }
      }
    }
```

### (Optional)Function Patch: Medium


## Managed PE
Needed module: `mscoree`

Needed functions: `CLRCreateInstane/CorBindToRuntime`, `GetRuntime`(vtable+0x18), `GetInterface`(vtable+0x48), `IsLoadable`, `Start`(vtable+0x18), `ExecuteInDefaultAppDomain`(vtable+0x58) 

Optional functions: `GetDefaultDomain`, `CreateDomain`, `UnloadDomain`, `Stop`, `Release`, etc.




## (Optional)Script
Needed interfaces: `IActiveScriptSite`, `IActiveScriptSiteWindowVtbl`, `IHostVtbl`, `IActiveScriptParse`

Needed functions: `CoInitializeEx`, `CoCreateInstance`, `QueryInterface`,  `InitNew`, `SetScriptSite`, `AddNamedItem`, `ParseScriptText`, `SetScriptState`

- VBA, JS, Powershell
