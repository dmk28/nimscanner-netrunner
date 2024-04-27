import "../scans/scanner.nim"
import "../types/port_types.nim"
import  system
import parseutils, strutils, ndns
import malebolgia

# This is a simple port scanner written in Nim

proc rangeConverter(port_ranges: seq[string]): seq[int] =

  var port_range: seq[int] = @[]
  for port_range_str in port_ranges:
    port_range.add(parseInt(port_range_str))
  return port_range 

proc isValidIP(ip: string): bool =

  var octets = ip.split(".")
  echo "[+] Checking IP:", ip
  if octets.len != 4:
    echo "Invalid IP: incorrect number of octets"
    return false
  for octet in octets:
    var num: int
    if parseOct(octet, num) != 0:
      if num < 0 or num > 255:
        echo "Invalid IP: octet out of range"
        return false
    else:
      echo "Invalid IP: failed to parse octet"
      return false
  echo "[!] Valid IP address [!]"
  return true

 
proc resolveDNS(answer: string): seq[string] =
  let client = initDnsClient()
  let resolved = client.resolveIpv4(answer)
  return resolved



proc main() =
  

  var ip: string
  var port_range: seq[int] = @[]
  var list_ports: seq[ScannedPort] = @[]  
  var udpScanner: bool
  var generalScan = false
  var answer: string
  var port_range_format: string 
  var synScan: bool

  echo "Is it a host or an IP address? Type 'host' or 'ip'"
  let answer_host = readLine(stdin)
  if answer_host == "ip":

      echo "[?] Please type target IP Address: "
      answer = readLine(stdin)
      if isValidIP(answer):
                ip = answer
  else:
    echo "Please type host"
    answer = readLine(stdin)
    answer = resolveDNS(answer).join
    ip = answer

  echo "[?] Please type port range (ie: 100-9999) or press ENTER: "
  answer = readLine(stdin)
  if  answer.len > 0 and answer.len <= 65535:
            generalScan = false
            var port_ranges: seq[string] = answer.split("-")
            port_range_format = port_ranges[0] & " - " & port_ranges[1] #lazy workaround until I git gud
            port_range = rangeConverter(port_ranges)
  else:
            generalScan = true
            port_range = @[1, 65535]

  echo "[?] Would you like to scan UDP ports? (y/n): "
  answer = readLine(stdin)
  if answer.toLower() == "y":
            udpScanner = true
  else:
            udpScanner = false
            echo "[?] Would you like to do a SYN packet scan? (y/n): "
            answer = readLine(stdin)
            if answer.toLower() == "y":
              synScan = true

  if udpScanner and not generalScan:
    echo "[+] Scanning UDP ports at given range: ", port_range_format
    scanner.iterPortRange(ip, list_ports, port_range, 2)
  elif not udpScanner and not generalScan:
    echo "[+] Scanning TCP ports at given range: ", port_range_format
    scanner.iterPortRange(ip, list_ports, port_range, 1)
  elif udpScanner and generalScan:
    echo "[+] Scanning UDP ports at range 1-65535"
    scanner.iterPorts(ip, list_ports, 2)
  elif not udpScanner and generalScan:
    echo "[+] Scanning TCP ports at range 1-65535"
    scanner.iterPorts(ip, list_ports, 1)
  elif not udpScanner and synScan and not generalScan:
    scanner.iterPorts(ip, list_ports, 3)
  elif synScan and generalScan:
    scanner.iterPortRange(ip, list_ports, port_range, 3)

    
main()
