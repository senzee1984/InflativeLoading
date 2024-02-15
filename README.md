# InflativeLoading

## ReadPEInMemory Project
To avoid manual mapping of an exe, run this program to get a template of in-memory exe file.

In this way, rather than manually map a file, we only need to patch specific areas like IAT, BaseReloc section, etc.

The read in-memory PE file will be saved as a binary file to append to the shellcode stub

```shell
PS C:\Users\Administrator\Desktop\petosc\project> .\ReadPEInMemory.exe .\mimikatz.exe mimi.bin
[+] DONE
[+] Size Of The Image : 0x137000
Process PID: 12512
PEB Address:0000000000D41000
Image Base Address:00007FF69AA80000
Data successfully written to mimi.bin. Total bytes read: 0x137000
```

## InflativeLoading Script

![image](/screenshot/mimikatz.png)
