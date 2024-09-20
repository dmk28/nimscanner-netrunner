import net, os
import malebolgia
import sequtils
import "../types/port_types.nim"
import "./synscan.nim"

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



proc connectSocket*(address: string, port: Port): ScannedPort {.thread} =

    
    var socket: Socket = newSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
    try: 
        socket.connect(address, port, 120)
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
    echo "No open ports found. Please check for false negatives."
  

 

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
    echo "No open ports found. Please check for false negatives."



      
