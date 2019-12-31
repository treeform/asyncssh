# AsyncSSH

SSH and run commands on other servers asynchronously. This is great if you have 
a cluster of servers and want to run commands on the at the same time. Waiting
for their results.

## Example:

If you just want to run a command and see its output:

```nim
var (output, code) = await execSSHCmd("root", "127.0.0.1", "uptime")
echo output
echo code
```

If you want to start a process which can be killed:

```nim
var p2 = newAsyncSSHProcess("root", "127.0.0.1", "uptime")
await p2.exec()
echo p2.output
echo p2.exitCode
echo p2.exitSignal
```