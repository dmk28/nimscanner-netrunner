import net, os, nativesockets
import std/random
import "../types/port_types"

type
  TCPHeader = object
    sourcePort: uint16
    destPort: uint16
    seqNumber: uint32
    ackNumber: uint32
    dataOffset: uint8
    flags: uint8
    windowSize: uint16
    checksum: uint16
    urgentPtr: uint16

proc calculateChecksum(data: openArray[byte]): uint16 =
  var sum: uint32 = 0
  for i in countup(0, data.len - 1, 2):
    if i + 1 < data.len:
      sum += (uint32(data[i]) shl 8) or uint32(data[i+1])
    else:
      sum += uint32(data[i]) shl 8
  while (sum shr 16) != 0:
    sum = (sum and 0xFFFF) + (sum shr 16)
  result = not uint16(sum)

proc connectSYNSocket*(address: string, port: Port): ScannedPort {.thread.} =
  const maxRetries = 3
  var retries = 0

  result = ScannedPort(scannedPort: port, status: PortStatus.unknown)

  while retries < maxRetries:
    var rawSocket = createNativeSocket(AF_INET, SOCK_RAW, IPPROTO_TCP)
    if rawSocket == osInvalidSocket:
      echo "Failed to create raw socket"
      return

    var header: TCPHeader
    randomize()
    header.sourcePort = nativesockets.htons(uint16(rand(49152..65535)))
    header.destPort = nativesockets.htons(uint16(port))
    header.seqNumber = nativesockets.htonl(uint32(rand(0..high(int))))
    header.ackNumber = 0
    header.dataOffset = (sizeof(TCPHeader) div 4) shl 4
    header.flags = 0x02  # SYN flag
    header.windowSize = nativesockets.htons(65535)
    header.checksum = 0
    header.urgentPtr = 0

    var packet = newSeq[byte](sizeof(TCPHeader))
    copyMem(addr packet[0], addr header, sizeof(TCPHeader))

    var sourceAddr, destAddr: Sockaddr_in
    sourceAddr.sin_family = AF_INET.uint16
    sourceAddr.sin_port = header.sourcePort
    sourceAddr.sin_addr.s_addr = INADDR_ANY

    destAddr.sin_family = AF_INET.uint16
    destAddr.sin_port = header.destPort
    
    # Convert IP address string to network address
    try:
      let ipAddr = parseIpAddress(address)
      case ipAddr.family
      of IpAddressFamily.IPv4:
        destAddr.sin_addr.s_addr = cast[uint32](ipAddr.address_v4)
      of IpAddressFamily.IPv6:
        echo "IPv6 is not supported for this operation"
        rawSocket.close()
        return
    except:
      echo "Invalid address"
      rawSocket.close()
      return

    # Calculate checksum
    var pseudoHeader = newSeq[byte](12 + sizeof(TCPHeader))
    copyMem(addr pseudoHeader[0], addr sourceAddr.sin_addr, 4)
    copyMem(addr pseudoHeader[4], addr destAddr.sin_addr, 4)
    pseudoHeader[8] = 0
    pseudoHeader[9] = 6  # TCP protocol
    var tcpLen = nativesockets.htons(uint16(sizeof(TCPHeader)))
    copyMem(addr pseudoHeader[10], addr tcpLen, 2)
    copyMem(addr pseudoHeader[12], addr packet[0], sizeof(TCPHeader))

    header.checksum = nativesockets.htons(calculateChecksum(pseudoHeader))
    copyMem(addr packet[16], addr header.checksum, 2)

    try:
      echo "Sending SYN packet to port ", port
      let sent = nativesockets.sendTo(rawSocket, addr packet[0], len(packet), 0, cast[ptr SockAddr](addr destAddr), sizeof(Sockaddr_in).SockLen)
      if sent < 0:
        echo "Failed to send packet"
        rawSocket.close()
        inc(retries)
        continue

      var response = newSeq[byte](1024)
      var fromAddr: Sockaddr_in
      var fromLen = sizeof(Sockaddr_in).SockLen
      var received = nativesockets.recvfrom(rawSocket, addr response[0], 1024, 0, cast[ptr SockAddr](addr fromAddr), addr fromLen)

      if received > 0:
        var ipHeaderLen = (response[0] and 0x0F) * 4
        var tcpHeader: TCPHeader
        copyMem(addr tcpHeader, addr response[ipHeaderLen], sizeof(TCPHeader))

        if (tcpHeader.flags and 0x12) == 0x12:  # SYN-ACK
          result.status = PortStatus.open
          return
        elif (tcpHeader.flags and 0x04) == 0x04:  # RST
          result.status = PortStatus.closed
          return
        else:
          result.status = PortStatus.filtered
          return
      else:
        echo "No response received from port ", port
        result.status = PortStatus.filtered
        return

    except:
      echo "Error: ", getCurrentExceptionMsg()

    finally:
      rawSocket.close()

    inc(retries)
    sleep(rand(100..1000))

  result.status = PortStatus.closedORfiltered