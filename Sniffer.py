# -*- coding: latin-1 -*-
import sys
from scapy.all import *
import socket

class SimplePacket:
    srcMAC = ""
    dstMAC = ""
    srcIP = ""
    dstIP = ""
    transport = ""
    srcPort = ""
    dstPort = ""
    payload = ""

    def flat(self):
        return (self.srcMAC, self.dstMAC, self.srcIP, self.dstIP, self.transport, self.srcPort, self.dstPort, self.payload)

def __stripNonPrintable(str):
    printable = Set('Lu', 'Ll')
    return ''.join(c if unicodata.category(c) in printable else '.' for c in str)

def __checkIP(address):
    try:
        socket.inet_aton(address)
        return True
    except socket.error:
        return False

def __checkTransportProtocol(protocol):
    if protocol.strip().upper() in ["TCP", "UDP"]:
        return True
    else:
        return 

def __checkPort(port):
    try:
        p = int(port)
        return True if 0 < p < 65536 else False
    except ValueError:
        return False

def __extractPacketInfo(packet):
    simplePacket = SimplePacket()
    simplePacket.srcMAC = packet[Ether].src
    simplePacket.dstMAC = packet[Ether].dst
    simplePacket.srcIP = packet[IP].src
    simplePacket.dstIP = packet[IP].dst
    if TCP in packet: 
        simplePacket.transport = "TCP"
        simplePacket.srcPort = packet[TCP].sport
        simplePacket.dstPort = packet[TCP].dport
    if UDP in packet: 
        simplePacket.transport = "UDP"
        simplePacket.srcPort = packet[UDP].sport
        simplePacket.dstPort = packet[UDP].dport
    if Raw in packet:
        simplePacket.payload = packet[Raw].load
    else:
        simplePacket.payload = "---"
    return simplePacket


# ========================================================================================================
# Main functions
# ========================================================================================================

def MakeFilter(ipAddress=None, transportProtocol=None, port=None):
    filters = []
    if ipAddress and not __checkIP(ipAddress): 
        raise ValueError("L'adresse IP doit avoir le format 'xxx.xxx.xxx.xxx'. Non valable: %s" % ipAddress)
    if transportProtocol and not __checkTransportProtocol(transportProtocol): 
        raise ValueError("Le protocole de transport doit être 'TCP' ou 'UDP'. Non valable: %s" % transportProtocol)
    if port and not __checkPort(port): 
        raise ValueError("Le port doit être entre 1 et 65535. Non valable: %s" % port)

    filters.append("ip") # Only capture IPv4 packets
    if ipAddress: filters.append("host %s" % ipAddress)
    if port: filters.append("port %s" % port)
    if transportProtocol:
        filters.append(transportProtocol)
    else:
        filters.append("(tcp or udp)")
    filter = " and ".join(filters)
    print filter
    return filter

def Capture(count=10, filter=None, iface=None, timeout=60):
    if count < 1: count = 10
    if count > 25: count = 25
    packets = sniff(count=count, filter=filter, iface=iface, timeout=timeout)
    return [ __extractPacketInfo(packet) for packet in packets ]

