# Jennov_P31HH35-3-FAS_PoC
PoC exploit for the [Jennov](https://jennov.com/) P31 P31HH35-3-FAS Wireless Security Camera.

This PoC exploits 3 stack-based buffer overflows in a CGI application (ajy.cgi) that serves
the endpoint /api/v1/group-list to perform a remote command injection. 

This PoC enables debugging code left within ajy.cgi by the developer (Jennov). Once enabled, user input (such as a command) is stored within a global debug buffer that is then fed to the system function to trigger a command injection.

Working on Firmware Version: **01.10100.10.50** (Latest as of 03-15-2025).

PoC can work on older firmware versions, but may require offsets to be slightly changed.

Limitation: For this PoC to work, the targeted device **MUST** have an SD card installed.

### Vulnerability Report:

Vulnerability report with possible solutions can be found [here](vuln_report.pdf). This document along with the PoC were provided to the manufacturer. No response has been received from the manufacturer.

### Overview of PoC:

Stage 1 Gadget: Trigger save_to_file function to write arbitrary data to web_debug.log. /mnt/mmc is the mount location of the SD card.

```
                             LAB_004015d8                                    XREF[1]:     004015c0(j)  
        004015d8 42 00 11 3c     lui        s1,0x42
        004015dc 34 00 a2 27     addiu      v0,sp,0x34
        004015e0 21 28 00 02     move       a1,s0
        004015e4 21 30 40 00     move       a2,v0
        004015e8 b0 91 24 26     addiu      a0=>chMsg.4238,s1,-0x6e50
        004015ec f0 22 10 0c     jal        libc.so.0::vsprintf                              int vsprintf(char * __s, char * 
        004015f0 18 00 a2 af     _sw        v0,local_18(sp)
        004015f4 c4 23 10 0c     jal        libc.so.0::strlen                                size_t strlen(char * __s)
        004015f8 b0 91 24 26     _addiu     a0=>chMsg.4238,s1,-0x6e50
        004015fc 40 00 04 3c     lui        a0,0x40
        00401600 b0 91 25 26     addiu      a1=>chMsg.4238,s1,-0x6e50
        00401604 74 7c 84 24     addiu      a0=>s_/mnt/mmc/web_debug.log_00407c74,a0,0x7c74  = "/mnt/mmc/web_debug.log"
        00401608 21 30 40 00     move       a2,v0
        0040160c c8 23 10 0c     jal        libBaseFun.so::save_to_file                      undefined save_to_file()
        00401610 01 00 07 24     _li        a3,0x1
        00401614 2c 00 bf 8f     lw         ra,local_4(sp)
        00401618 28 00 b1 8f     lw         s1,local_8(sp)
        0040161c 24 00 b0 8f     lw         s0,local_c(sp)
        00401620 08 00 e0 03     jr         ra
        00401624 30 00 bd 27     _addiu     sp,sp,0x30
```

Stage 2 Gadget: Trigger rename function to rename web_debug.log file to cgiDebug file to enable debugging. Debug print outs that can include user input are now stored in global debug buffer before being written to web_debug.log file.

```
        00402968 20 00 a5 27     addiu      a1,sp,0x20
        0040296c 48 23 10 0c     jal        libc.so.0::rename                                int rename(char * __old, char * 
        00402970 20 01 a4 27     _addiu     a0,sp,0x120
```

Stage 3 Gadget: Trigger sprintf function to store the command (offset in the global debug buffer) on the stack. The system function is then called with the provided command.

```
        00404194 21 28 80 02     move       a1=>s_echo_%d_>>_/var/Test.tmp_0040899c,s4       = "echo %d >> /var/Test.tmp"
        00404198 21 30 20 02     move       a2,s1
        0040419c a4 23 10 0c     jal        libc.so.0::sprintf
        004041a0 90 05 a4 27     _addiu     a0,sp,0x590
        004041a4 20 23 10 0c     jal        libpthread.so.0::system                          int system(char * __command)
        004041a8 90 05 a4 27     _addiu     a0,sp,0x590
```

### PoC in Action

https://github.com/user-attachments/assets/57723113-e430-478e-afd2-f1e90cd6da2e


