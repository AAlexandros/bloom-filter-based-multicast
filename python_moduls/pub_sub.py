import socket
import threading
import time
from payload_object import PubSubPayload
import netifaces as ni

#Import logger and set it so it doesnt show scapy warnings
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import Ether, IPv6, sendp, UDP, IP

BRD_ADDRESS = '10.255.255.255'
BRD_ETHE = 'ff:ff:ff:ff:ff:ff'
PORT = 10000
#All packet protocols
ETH_P_ALL = 3

#Get eth0 interface name(varying in some cases)
def find_eth0_interface():
    return ni.interfaces()[1]

ETH0_INTERFACE = find_eth0_interface()

#Get the current hosts eth0 interface
def find_eth0_addr():
    return ni.ifaddresses(ETH0_INTERFACE)[2][0]['addr']

ETH0_ADDRESS = find_eth0_addr()

# Stores information needed for host actions
class Storage(object):
    def __init__(self, udp_socket, raw_socket):
        self._subscribers = {}
        #Socket for communication with controller
        self.udp_socket = udp_socket
        #Socket for sending the packets to the subscribers
        self.raw_socket = raw_socket

	# Add a Bloom Filter for the given channel
    def add_bloomfilter(self, channel, bloomfilter):
        self._subscribers[channel] = bloomfilter

	# Remove a channel
	# In case of none subscribers in the channel or unsubscribe
    def remove_channel(self, channel):
        del self._subscribers[channel]

# Transmition of packets given a Bloom Filter
class SendingThread (threading.Thread):
    def __init__(self, storage, interval, group=None, target=None, name=None, args=(), kwargs=None, verbose=None):
        super(SendingThread, self).__init__(group, target, name, args, kwargs, verbose)
        self.storage = storage
        self.interval = interval
        self._stopped = False
        self.lock = threading.RLock()
        self.event = threading.Event()
        self.packets_tx = {}

    def set_stopped(self):
        with self.lock:
            self._stopped = True
            self.event.set()

    def is_stopped(self):
        with self.lock:
            return self._stopped

    def run(self):
        while not self.is_stopped():
			# Check every ten seconds
            self.event.wait(self.interval)

            if self.is_stopped(): 
                break

            if self.storage._subscribers:
                for channel in self.storage._subscribers:
                    if channel not in self.packets_tx:
                        self.packets_tx[channel] = 0;
                    bloomed_ip = self.storage._subscribers[channel]
                    print "Transmiting packet", self.packets_tx[channel], " for channel ", channel
                    self._transmit_packet(channel, bloomed_ip)
                    self.packets_tx[channel] += 1

    def _transmit_packet(self, channel,  bloomed_ip):
		# Create the payload data
        data = PubSubPayload(channel, PubSubPayload.COMND_DATA, str(self.packets_tx[channel])).packetOut()
        #Send via scapy socket interface (we dont care what sport and dport will be)
        sendp(Ether(src = "0F:0F:0F:0F:0F:0F")/IPv6(src = None, dst = bloomed_ip)
              /UDP(sport = 7000, dport = 7001)/data, iface = ETH0_INTERFACE)

# Receive the Forwarding messages from the controller
class ReceivingThread(threading.Thread):
    def __init__(self, storage, group=None, target=None, name=None, args=(), kwargs=None, verbose=None):
        super(ReceivingThread, self).__init__(group, target, name, args, kwargs, verbose)
        self.storage = storage
        self._stopped = False
        self.lock = threading.RLock()

    def set_stopped(self):
        with self.lock:
            self._stopped = True

    def is_stopped(self):
        with self.lock:
            return self._stopped

    def run(self):
        while not self.is_stopped():
            data = self.storage.udp_socket.recv(1024)
            print "Got data", str(data)

            if self.is_stopped():    #xriazete?
                break

            payload = PubSubPayload.packetIn(data)
            subscriber_channel = payload.channel_name
            bloom_filter = payload.payload
            print bloom_filter
            if payload.command == PubSubPayload.COMND_FWD:
                self.storage.add_bloomfilter(subscriber_channel, bloom_filter)
            #ToDo Under Construction
            elif payload.command == PubSubPayload.COMND_QUIT:
                pass

#Receive packets when the connection is established
#ToDo Initialise this socket only when one or more connections are setted up
class ReceivingPacketsThread(threading.Thread):
    def __init__(self, storage, group=None, target=None, name=None, args=(), kwargs=None, verbose=None):
        super(ReceivingPacketsThread, self).__init__(group, target, name, args, kwargs, verbose)
        self.storage = storage
        self._stopped = False
        self.lock = threading.RLock()

    def set_stopped(self):
        with self.lock:
            self._stopped = True

    def is_stopped(self):
        with self.lock:
            return self._stopped

    def run(self):
        while not self.is_stopped():
            data, address = self.storage.raw_socket.recvfrom(1024)
            struct_payload = self.packet_manager(data)
            if struct_payload != None:
                #print address#[4][1:].replace("\x",":").upper()
                channel = struct_payload.channel_name
                #We want to skip our own captured packets
                if channel not in self.storage._subscribers:
                    packet_number = struct_payload.payload
                    print "Got packet from publisher with packet number ", packet_number," for channel ", channel,"."

# Keeps only the usefull part of the package based on our protocol
    # Conducts minimal configuration, the network wont allow packets that dont have our mark pass anyway
    def packet_manager(self, data):
        #If packet has at least the size of payload we need
        try:
            usefull_data = data[-80:]
            try:
                packet_payload = PubSubPayload.packetIn(usefull_data)
                command = packet_payload.command
                if command == PubSubPayload.COMND_DATA:
                    return packet_payload
            except:
                #In case the packet has another Struct return None
                return None
        except:
            return None

# Send a packet containing a command for controller
def interact(channel, command):
    announcement = PubSubPayload(channel, command).packetOut()
    interact_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    interact_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    interact_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 2)
    interact_socket.sendto(announcement, (BRD_ADDRESS, PORT))
    interact_socket.close()

def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #In case program closes unexpectably, the socket will close as well
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_socket.bind((ETH0_ADDRESS, PORT))

    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)
    #In case program closes unexpectably, the socket will close as well
    raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #Bind the socket to corresponding hosts eth0 interface, receive every packet
    raw_socket.bind((ETH0_INTERFACE, ETH_P_ALL))

    storage = Storage(udp_socket, raw_socket)
    sending_thread = SendingThread(storage, 10)
    receiving_thread = ReceivingThread(storage)
    receiving_packets_thread = ReceivingPacketsThread(storage)

    sending_thread.start()
    receiving_thread.start()
    receiving_packets_thread.start()

	#User UI, not something special, suits the simple network host capabilities	
    while True:
        info_input = raw_input('''Press "publish" to publish for a channel
          "subscribe" to subscribe for a channel
          "unpublish" to end a publishment for a channel
          "unsubscribe" to end a subscription for a channel
          "exit" to exit \r\n''')
        if info_input == 'publish':
            channel_input = raw_input("Insert channel name for publishing\r\n")
            interact(channel_input, PubSubPayload.COMND_PUB)
        elif info_input == 'subscribe':
            channel_input = raw_input("Insert a channel for subscription\r\n")
            interact(channel_input, PubSubPayload.COMND_SUB)
        elif info_input == 'unpublish':
            channel_input = raw_input("Insert a channel for unpublishing\r\n")
            #Stop sending packets to this channel
            storage.remove_channel(channel_input)
            interact(channel_input, PubSubPayload.COMND_QUIT)
        elif info_input == 'unsubscribe':
            channel_input = raw_input("Insert a channel for unsubscribing\r\n")
            interact(channel_input, PubSubPayload.COMND_QUIT)
        elif info_input == 'exit':
            break
        else:
            print "Please check your spelling and try again"

    print 'closing all'

	# Stop the threads and the Sockets
    sending_thread.set_stopped()
    receiving_thread.set_stopped()
    receiving_packets_thread.set_stopped()
    udp_socket.sendto("STOP", (ETH0_ADDRESS, PORT))
    udp_socket.close()

if __name__ == '__main__':
    main()


