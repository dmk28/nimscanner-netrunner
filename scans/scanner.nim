import net, os
import std/random
import malebolgia
import sequtils
import "../types/port_types.nim"

type TCPHeader* = object
  sourcePort: Port
  destPort: Port
  sequenceNumber: uint
  ackNumber: uint
  dataOffset: uint
  reserved: uint
  flags: uint
  windowSize: uint16
  checksum: uint16
  urgentPointer: uint16


    
proc connectSYNSocket*(address: string, port: Port): ScannedPort {.thread.} =
  const maxRetries = 3  # Adjust the maximum number of retries as needed
  var retries = 0

  while retries < maxRetries:
    var socket: Socket = newSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
    let tcp_header = new TCPHeader
    randomize()

    socket.setSockOpt(OptNoDelay, true)
    socket.setSockOpt(OptKeepAlive, false)
    tcp_header.sourcePort = Port(uint16(rand(1024..65535)))
    tcp_header.destPort = port
    tcp_header.flags = 0x02

    let packet_size = 128
    let packet = addr tcp_header
    
    try:
      echo "Sending packet"
      discard socket.send(packet, packet_size)
      let response_size = packet_size
      let buffer: seq[byte] = newSeq[byte](response_size)
      let received_size = socket.recv(buffer.addr, response_size, 150)
      if received_size == response_size:
          echo "Received packet"
          var tcp_response: TCPHeader
          copyMem(addr tcp_response, buffer.addr, response_size)

          if tcp_response.flags == 0x12:
            result.scannedPort = port
            result.status = PortStatus.open
          elif tcp_response.flags == 0x10:
            discard tcp_response
          else: 
            result.scannedPort = port
            result.status = PortStatus.closedORfiltered
      else:
        
          result.scannedPort = port
          result.status = PortStatus.closedORfiltered

      # Connection successful, break out of the loop
      break

    except IOError as e:
      echo "Packet was not sent:", e.msg
    except OSError as e:
      case e.name
      of "ConnectionRefused":
        echo "Connection Refused. Retrying..."
      else:
        echo "Socket error:", e.name
    finally:
      if not socket.isNil:
        socket.close()

    # Increment the retry counter
    inc(retries)

  # If the loop exits without a successful connection, set status to closed
  if retries == maxRetries:
    result.scannedPort = port
    result.status = PortStatus.closedORfiltered
  return result



proc connectSocket*(address: string, port: Port): ScannedPort {.thread} =

    
    var socket: Socket = newSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
    try: 
        socket.connect(address, port, 50)
        result.scannedPort = port
        result.status = PortStatus.open
    except:
        result.scannedPort = port
        result.status = PortStatus.closed
        socket.close()
    finally:
      socket.close()
    return result

proc connectUDPSocket*(address: string, port: Port): ScannedPort {.thread} =
    var socket: Socket = newSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
    var data: string = ""
    var data_received: cstring

    try:
        socket.sendTo(address, port, data)
        let bytesRead: int = socket.recv(data_received, 512, timeout=125)
        if bytesRead > 0:
            if data_received.len > 0:
                result.scannedPort = port
                result.status   = PortStatus.open
            else:
                result.scannedPort = port
                result.status = PortStatus.openORfiltered
            result.scannedPort = port
            result.status = PortStatus.open
        else:
            var error = socket.getSocketError()
            if error.osErrorMsg == "ICMP_PORT_UNREACHABLE":
                result.scannedPort = port
                result.status = PortStatus.closed
            else:
                result.scannedPort = port
                result.status = PortStatus.filtered
           
        
    except OSError:  # Catch OSError when sending fails
        result.scannedPort = port
        socket.close()
        result.status = PortStatus.closed  
    except TimeoutError:
        result.scannedPort = port
        socket.close()
        result.status = PortStatus.closed
    except Exception:
        echo "Unexpected error: ", getCurrentExceptionMsg()
        result.scannedPort = port
        result.status = PortStatus.unknown
        
    finally:
      socket.close()
    

    return result



proc iterPorts*(address: string, list_ports: var seq[ScannedPort], option: int) =


  # Create a Master object for task coordination
  var m = createMaster()

  var results = newSeq[ScannedPort](65535)
  # Perform port scanning based on the provided option in parallel
  m.awaitAll:
    for n in 1 .. 65535:
        case option
        of 1:
          m.spawn connectSocket(address, Port(n)) -> results[n - 1]
        of 2:
          m.spawn connectUDPSocket(address, Port(n)) -> results[n - 1]
        of 3:
          m.spawn connectSYNSocket(address, Port(n)) -> results[n - 1] 
        else:
          raise newException(ValueError, "Invalid option")
  # Process the results
  # accounts for any possible voided ports in the seq, discards original, uses the filtered to print out results

  var filteredResults: seq[ScannedPort] = filter(results, proc(x: ScannedPort): bool = x.status == PortStatus.open and int(x.scannedPort) > 0)
  discard results
  for result in filteredResults:
      echo result.scannedPort, " is: ", result.status
  if filteredResults.len == 0:
    echo "No open ports found; please try another method or employ evasion techniques."

 

proc iterPortRange*(address: string, list_ports: var seq[ScannedPort], port_range: seq[int], option: int) {.thread.} =
  # Validate input parameters
  if port_range.len < 1 or port_range.len > 2:
    raise newException(ValueError, "Invalid port range")

  var min_range = port_range[0]
  var max_range = port_range[1]

  # Process port range
  if port_range.len == 1:
    min_range = 1

  # Create a Master object for task coordination
  var m = createMaster()
  
  var results = newSeq[ScannedPort](max_range-min_range+1)
  # Synchronize all spawned tasks using an AwaitAll block
  echo "[+][!!!]Scanning[!!!][+]"
  # Perform port scanning based on the provided option in parallel
  m.awaitAll:
    for n in min_range..max_range:
          case option
          of 1:
            m.spawn connectSocket(address, Port(n)) ->  results[n - min_range]
          of 2:
            m.spawn connectUDPSocket(address, Port(n)) -> results[n - min_range]
          of 3:
            m.spawn connectSYNSocket(address, Port(n)) -> results[n - min_range]
          else:
            raise newException(ValueError, "Invalid option")
  
  # accounts for any possible voided ports in the seq, discards original, uses the filtered to print out results
  var filteredResults: seq[ScannedPort] = filter(results, proc(x: ScannedPort): bool = int(x.scannedPort) > 0 and x.status == PortStatus.open) 
  discard results
  for result in filteredResults:
      if result.status == PortStatus.open:
        echo result.scannedPort, " is: ", result.status
  if filteredResults.len == 0:
    echo "No open ports found in given range"
 
  




      
