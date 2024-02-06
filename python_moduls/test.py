import socket
import struct
import netifaces as ni

ETH_P_ALL = 3
def find_eth0_interface():
    #Get eth0 interface name(varying in some cases)
    return ni.interfaces()[1]

ETH0_INTERFACE = find_eth0_interface()

def find_eth0_addr():
    #Get the current hosts eth0 interface
    return ni.ifaddresses(ETH0_INTERFACE)[2][0]['addr']

ETH0_ADDRESS = find_eth0_addr()

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((ETH0_INTERFACE, ETH_P_ALL))

while 1:

	packet = sock.recv(1024)
	print "YATA", str(packet)
	
