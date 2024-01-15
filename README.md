# InflativeLoading

## ReadPEInMemory
To avoid manual mapping of an exe, run this program to get a template of in-memory exe file.

In this way, rather than manually map a file, we only need to patch specific area like IAT, BaseReloc section, etc.

The read in-memory PE file will be saved as a binary file to append to the shellcode stub

```shell
[+] DONE
[+] Size Of The Image : 7000
PID: 28264
PEB Address:0000005E5165F000
Image Base Address:00007FF78E730000
Read 28672 bytes from Image Base Address

00007FF78E730000  4D 5A 90 00 03 00 00 00 - 04 00 00 00 FF FF 00 00   MZ..............
00007FF78E730010  B8 00 00 00 00 00 00 00 - 40 00 00 00 00 00 00 00   ........@.......
00007FF78E730020  00 00 00 00 00 00 00 00 - 00 00 00 00 00 00 00 00   ................
00007FF78E730030  00 00 00 00 00 00 00 00 - 00 00 00 00 00 01 00 00   ................
00007FF78E730040  0E 1F BA 0E 00 B4 09 CD - 21 B8 01 4C CD 21 54 68   ........!..L.!Th
00007FF78E730050  69 73 20 70 72 6F 67 72 - 61 6D 20 63 61 6E 6E 6F   is program canno
00007FF78E730060  74 20 62 65 20 72 75 6E - 20 69 6E 20 44 4F 53 20   t be run in DOS
00007FF78E730070  6D 6F 64 65 2E 0D 0D 0A - 24 00 00 00 00 00 00 00   mode....$.......
......................................................................................
00007FF78E736FE0  00 00 00 00 00 00 00 00 - 00 00 00 00 00 00 00 00   ................
00007FF78E736FF0  00 00 00 00 00 00 00 00 - 00 00 00 00 00 00 00 00   ................
Data successfully written to 'dumped.bin'
```

## PrependedShellcodeStub
