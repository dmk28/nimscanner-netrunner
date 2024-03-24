import net

type 
    PortStatus* = enum
     open, closed, filtered, unfiltered, openORfiltered, closedORfiltered, unknown
    ScannedPort* = object
        scannedPort*: Port 
        status*: PortStatus