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

### (Optional)Function Patch: Medium


## Managed PE
Needed module: `mscoree`

Needed functions: `CLRCreateInstane/CorBindToRuntime`, `GetRuntime`, `GetInterface`, `IsLoadable`, `Start`, `ExecuteInDefaultAppDomain` 

Optional functions: `GetDefaultDomain`, `CreateDomain`, `UnloadDomain`, `Stop`, `Release`, etc.




## (Optional)Script
Needed interfaces: IActiveScriptSite, IActiveScriptSiteWindowVtbl, IHostVtbl, IActiveScriptParse

Needed functions: CoInitializeEx, CoCreateInstance, QueryInterface,  InitNew, SetScriptSite, AddNamedItem, ParseScriptText, SetScriptState
- VBA, JS, Powershell
