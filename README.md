# AsyncSSH

SSH and run commands on other servers asynchronously. This is great if you have 
a cluster of servers and want to run commands on the at the same time. Waiting
for their results.

## Example:

```nim
var (output, code) = await execSSHCmd("root", "127.0.0.1", "uptime")
echo output
echo code
```

```nim
var p2 = newAsyncSSHProcess("root", "127.0.0.1", "uptime")
await p2.exec()
echo p2.output
echo p2.exitCode
echo p2.exitSignal
```