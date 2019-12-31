import asyncdispatch
import asyncssh

proc ticker() {.async.} =
  var i = 0
  while true:
    echo "----------------- tick --------------------------------- ", i
    inc i
    await sleepAsync(1)

asyncCheck ticker()


proc testExec() {.async.} =
  var (output, code) = await execSSHCmd("root", "127.0.0.1", "uptime")
  echo output
  echo code

proc testSSHProcess() {.async.} =
  var p2 = newAsyncSSHProcess("root", "127.0.0.1", "uptime")
  await p2.exec()
  echo p2.output
  echo p2.exitCode
  echo p2.exitSignal

proc testMultiKill() {.async.} =
  var ps: seq[AsyncSSHProcess]
  for i in 0 .. 10:
    ps.add newAsyncSSHProcess("root", "127.0.0.1", "uptime")
    asyncCheck ps[^1].exec()
  
  while true:
    await sleepAsync(1)
    var allKilled = true
    for p in ps:   
      if p.running:
        echo "killing p before its done"
        try:
          p.kill()
        except:
          discard
      if p.killed == false:
          allKilled = false
    if allKilled: 
      break
      

  await sleepAsync(10)


waitFor testExec()
waitFor testSSHProcess()
waitFor testMultiKill()