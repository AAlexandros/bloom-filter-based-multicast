"""
Object defined for making fixed  payload atributes, helping us in packet forwarding
""" 

import struct

class PubSubPayload(object):

    # Command is pubisher, subscriber or forward
    COMND_PUB = 'PB'
    COMND_SUB = 'SB'
    COMND_FWD = 'FW'
    COMND_DATA = 'DA'
    COMND_QUIT = 'QU'

    #Packet format is: 10 byte channel name, 2 byte command and 68 byte payload
    pktFormat = '10s2s68s'

    def __init__(self,channel_name, command, payload = '0'):
        self.channel_name = channel_name
        self.command = command
        self.payload = payload

    def packetOut(self):
        packet = struct.pack(PubSubPayload.pktFormat, self.channel_name, self.command, self.payload)
        return packet

	# Factory method, for creating a payload_object object from a packet
    @classmethod
    def packetIn(PubSubPayload,packet):
        unpacked = struct.unpack(PubSubPayload.pktFormat, packet)
        channel_name = unpacked[0].split('\x00', 1)[0]
        command = unpacked[1].split('\x00', 1)[0]
        payload = unpacked[2].split('\x00', 1)[0]
        return PubSubPayload(channel_name,command,payload)
