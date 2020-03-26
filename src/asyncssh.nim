import os, net, posix, asyncdispatch, asyncnet
import libssh2


type
  AsyncSSHError* = object of Exception

  AsyncSSHProcess* = ref object
    output*: string
    exitCode*: int
    exitSignal*: string
    running*: bool
    finished*: bool
    killed*: bool
    username*: string
    hostname*: string
    command*: string
    password*: string
    port*: int
    pubkeyFile*: string
    privkeyFile*: string
    knownHostFile*: string

    sock: AsyncSocket
    session: Session


proc newAsyncSSHProcess*(
    username: string,
    hostname: string,
    command: string,
    password = "",
    port = 22,
    pubkeyFile = "~/.ssh/id_rsa.pub",
    privkeyFile = "~/.ssh/id_rsa",
    knownHostFile = "~/.ssh/known_hosts"
  ): AsyncSSHProcess  =
  ## Starts an async SSH process, call .exec() on it to start
  result = AsyncSSHProcess()
  result.username = username
  result.hostname = hostname
  result.command = command
  result.password = password
  result.port = port
  # expand ~ in all paths libssh2 only takes full paths
  result.pubkeyFile = pubkeyFile.expandTilde
  result.privkeyFile = privkeyFile.expandTilde
  result.knownHostFile = knownHostFile.expandTilde



proc kill*(p: AsyncSSHProcess) =
  ## Stops the SSH process
  if not p.running:
    raise newException(AsyncSSHError, "AsyncSSHProcess is not running.")
  if p.finished or p.killed:
    raise newException(AsyncSSHError, "AsyncSSHProcess is already finished.")
  discard p.session.sessionDisconnect("Normal shutdown, thank you for playing")
  discard p.session.sessionFree()
  p.sock.close()
  p.running = false
  p.killed = true
  p.finished = true

proc exec*(p: AsyncSSHProcess) {.async.} =
  ## Runs the SSH proces

  proc error(msg: string, code: int) {.noreturn.} =
    if not p.killed:
      raise newException(AsyncSSHError, msg & " Code: " & $code)

  if p.running:
    error("AsyncSSHProcess is already running.", 0)
  if p.finished:
    error("AsyncSSHProcess is already finished.", 0)

  p.running = true

  var rc = init(0)
  if rc != 0:
    error("Fibssh2 initialization failed.", rc)

  p.sock = newAsyncSocket()
  await p.sock.connect(p.hostname, Port(p.port))

  proc waitsocket(socket_fd: SocketHandle, s: Session): int =
    var timeout: Timeval
    var fd: TFdSet
    var writefd: TFdSet
    var readfd: TFdSet
    var dir: int
    timeout.tv_sec = 10.Time
    timeout.tv_usec = 0
    FD_ZERO(fd)
    FD_SET(socket_fd, fd)
    dir = s.sessionBlockDirections()
    if((dir and LIBSSH2_SESSION_BLOCK_INBOUND) == LIBSSH2_SESSION_BLOCK_INBOUND):
      readfd = fd
    if((dir and LIBSSH2_SESSION_BLOCK_OUTBOUND) == LIBSSH2_SESSION_BLOCK_OUTBOUND):
      writefd = fd
    var sfd  = cast[cint](socket_fd) + 1
    result = select(sfd, addr readfd, addr writefd, nil, addr timeout);

  p.session = sessionInit()
  p.session.sessionSetBlocking(0)

  while true:
    await sleepAsync(0)
    if p.killed: return
    rc = p.session.sessionHandshake(p.sock.getFd())
    if rc != LIBSSH2_ERROR_EAGAIN:
      break

  if rc != 0:
    error("Failure establing ssh connection.", rc)

  if p.killed: return
  var knownHosts = p.session.knownHostInit()
  if knownHosts.isNil:
    p.kill()
    error("Unable to create knownHosts", 0)

  if not existsFile(p.knownHostFile):
    writeFile(p.knownHostFile, "")

  if p.killed: return
  rc = knownHosts.knownHostReadfile(
    p.knownHostFile,
    LIBSSH2_KNOWNHOST_FILE_OPENSSH
  )
  if rc < 0:
    error("Read knownhost error.", rc)

  var length: int
  var typ: int

  var fingerprint = p.session.sessionHostkey(length, typ)
  if fingerprint.isNil:
    p.kill()
    error("Unable to fetch hostkey", 0)


  var host: knownhost_st
  let check = knownHosts.knownHostCheckP(
    p.hostname,
    22,
    fingerprint,
    length,
    LIBSSH2_KNOWNHOST_TYPE_PLAIN or LIBSSH2_KNOWNHOST_KEYENC_RAW or LIBSSH2_KNOWNHOST_KEY_SSHRSA,
    addr host
  )

  case check:
    of LIBSSH2_KNOWNHOST_CHECK_FAILURE:
      error("Something prevented the check to be made.", check)
    of LIBSSH2_KNOWNHOST_CHECK_NOTFOUND:
      # no host match was found
      rc = knownHosts.knownHostAddC(
        p.hostname,
        nil,
        fingerprint,
        length,
        nil,
        0,
        LIBSSH2_KNOWNHOST_TYPE_PLAIN or LIBSSH2_KNOWNHOST_KEYENC_RAW or LIBSSH2_KNOWNHOST_KEY_SSHRSA,
        nil
      )
      if rc == 0:
        knownHosts.knownHostWritefile(p.knownHostFile, LIBSSH2_KNOWNHOST_FILE_OPENSSH)
      else:
        error("Failed to add knownhost.", rc)
    of LIBSSH2_KNOWNHOST_CHECK_MATCH:
      # hosts and keys match.
      discard
    of LIBSSH2_KNOWNHOST_CHECK_MISMATCH:
      error("WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!", check)
    else:
      error("Unkown knownHosts error!", check)
  knownHosts.knownHostFree()

  if p.password.len > 0:
    while true:
      await sleepAsync(0)
      rc = p.session.userauthPassword(p.username, p.password, nil)
      if rc != LIBSSH2_ERROR_EAGAIN:
        break

    if rc != 0:
      p.kill()
      error("Authentication by password failed!", rc)

  else:
    while true:
      await sleepAsync(0)
      rc = p.session.userauthPublickeyFromFile(p.username, p.pubkeyFile, p.privkeyFile, p.password)
      if rc != LIBSSH2_ERROR_EAGAIN:
        break

    if rc != 0:
      p.kill()
      error("Authentication by public key failed!", rc)


  var channel: Channel
  while true:
    await sleepAsync(0)
    channel = p.session.channelOpenSession()
    if channel.isNil and p.session.sessionLastError(nil, nil, 0) == LIBSSH2_ERROR_EAGAIN:
      discard waitsocket(p.sock.getFd(), p.session)
    else:
      break

  if channel.isNil:
    p.kill()
    error("Unable to open a session", rc)

  while true:
    await sleepAsync(0)
    rc = channel.channelExec(p.command)
    if rc != LIBSSH2_ERROR_EAGAIN:
      break

  if rc != 0:
    p.kill()
    error("Failed exec.", rc)

  var bytecount = 0
  p.output = ""
  while true:
    await sleepAsync(0)
    var buffer: array[0..1024, char]
    rc = channel.channelRead(addr buffer, buffer.len)
    if rc > 0:
      bytecount += rc
      for i in 0..rc-1:
        p.output.add buffer[i]
    elif rc == LIBSSH2_ERROR_EAGAIN:
      discard waitsocket(p.sock.getFd(), p.session)
    else:
      break

  var exitCode = 127
  while true:
    await sleepAsync(0)
    rc = channel.channelClose()
    if rc == LIBSSH2_ERROR_EAGAIN:
      discard waitsocket(p.sock.getFd(), p.session)
    else:
      break

  var exitSignal: cstring

  if rc == 0:
    exitCode = channel.channelGetExitStatus()
    discard channel.channelGetExitSignal(exitSignal, 0, nil, 0, nil, 0)

  if not exitSignal.isNil:
    error("Got sinal: " & $exitSignal, rc)

  discard channel.channelFree()

  p.exitCode = exitCode
  p.exitSignal = $exitSignal
  p.finished = true


proc execSSHCmd*(
  username: string,
  hostname: string,
  command: string,
  password = "",
  port = 22,
  pubkeyFile = "~/.ssh/id_rsa.pub",
  privkeyFile = "~/.ssh/id_rsa",
  knownHostFile = "~/.ssh/known_hosts"
): Future[tuple[output: string, exitCode: int]] {.async.} =
  ## Runs a command on an host
  var p = newAsyncSSHProcess(
    username = username,
    hostname = hostname,
    command = command,
    password = password,
    port = port,
    pubkeyFile = pubkeyFile,
    privkeyFile = privkeyFile,
    knownHostFile = knownHostFile,
  )
  await p.exec()
  result[0] = p.output
  result[1] = p.exitcode