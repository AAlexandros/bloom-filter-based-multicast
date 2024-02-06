import pox.lib.packet as pkt
from ext.payload_object import PubSubPayload
from pox.core import core
from pox.lib.revent import *
import pox.openflow.libopenflow_01 as of
from pox.lib import addresses as addr

log = core.getLogger()

class createAppointment(Event):
    """
    New appointment has occured
    """

    def __init__(self, appointmentID, publisher_ip, publisher_mac, publisher_switch_port, publisher_switch_id,
                 subscriber_ip, subscriber_mac, subscriber_switch_port, subscriber_switch_id):
        Event.__init__(self)
        self.appointmentID = appointmentID
        self.publisher_ip = publisher_ip
        self.publisher_mac = publisher_mac
        self.publisher_switch_port = publisher_switch_port
        self.publisher_switch_id = publisher_switch_id
        self.subscriber_ip = subscriber_ip
        self.subscriber_mac = subscriber_mac
        self.subscriber_switch_port = subscriber_switch_port
        self.subscriber_switch_id = subscriber_switch_id


class Manager(EventMixin):
    # Change the name at core
    _core_name = "randezvous_manager"

    _eventMixin_events = {createAppointment}

    def __init__(self):
        self.appointmentID = 1

        # Member network info needed for topology manager
        self.memberInfo = MemberTable()
        # Info about channel subscriptions and publishings
        self.channelInfo = ChannelTable()
		# Helps manage Randezvous Manager - Topology Manager communication
        self.appointmentTable = {}

        # Add listener for l2_learning.addListener and topology_manager events
        def startup():
            core.l2_learning_BF.addListeners(self)
            core.topology_manager.addListeners(self)

        core.call_when_ready(startup, ('l2_learning_BF', 'topology_manager'))

	# Handles Randezvous Manager newMembership events
    def _handle_newMembership(self, event):
        channel = event.channel
        msg_type = event.msg_type
        ipAddr = event.ipAddr
        macAddr = event.macAddr
        port = event.port
        dpID = event.dpID
        self.memberInfo.add_member(ipAddr, macAddr, port, dpID)
        if msg_type == "SB":
            add_sub = self.channelInfo.add_subscriber(channel, ipAddr)

            if add_sub != "Exists":
                # check if interaction occurs and if so rise a createAppointment Event
                publisher = self.channelInfo.pubCheck(channel)
                if publisher is not None:
                    self.raiseAppointmentEvent(publisher, ipAddr, channel)

        elif msg_type == "PB":
            add_pub = self.channelInfo.add_publisher(channel, ipAddr)

			# ToDO (Imoprovement)
            # Check if the publisher is in charge for the channel (in case if there is another one)
            if add_pub != "Exists":
                subscribers = self.channelInfo.subCheck(channel)
                for sub in subscribers:
                    self.raiseAppointmentEvent(ipAddr, sub, channel)

		#ToDo (Fix)
		# This function wasnt updated from our Non Bloom Filter version so it doesnt function properly 
		# Must synchronise with Topology Manager, so he can Remove the subscriber and then make the new Bloom Filter
        elif msg_type == "QU":
            #Delete person from channelInfo table
            pub_sub = self.channelInfo.pub_or_sub(channel, ipAddr)

            #if its publisher we don't care, if its subscriber we must notify its publisher (if there is)
            if pub_sub == "subscriber":
                #print self.memberInfo._member_table
                its_publisher = self.channelInfo.pubCheck(channel)
                if its_publisher is not None:
                    #create packet
                    payload = self.constructPayload(channel, PubSubPayload.COMND_QUIT, ipAddr)
                    sub_mac = self.memberInfo._member_table[ipAddr]['Mac']
                    pub_mac = self.memberInfo._member_table[its_publisher]['Mac']
                    notification_packet = self.packetConstruct(payload, ipAddr, its_publisher, sub_mac, pub_mac)

                    #send packet
                    outDpId = self.memberInfo._member_table[its_publisher]["sID"]
                    outPort = self.memberInfo._member_table[its_publisher]['sPort']
                    self.sendPacket(notification_packet, outDpId, outPort)
            #If no channels are using this person remove him from member table
            person_remains = self.channelInfo.remove_person(channel, ipAddr)
            if not person_remains:
                self.memberInfo.remove_member(ipAddr)
        else:
            log.warning("Check your forwarding type")

    # When a Bloom Filter is created we send it to the publisher
    def _handle_createTopology(self, event):

        if event.appointmentID in self.appointmentTable:
            #log.info(str(self.appointmentTable))
            pubIp = self.appointmentTable[event.appointmentID]['publisher']
            subIp = self.appointmentTable[event.appointmentID]['subscriber']
            channel = self.appointmentTable[event.appointmentID]['channel']
            pubInfo = self.memberInfo._member_table[pubIp]
            subInfo = self.memberInfo._member_table[subIp]

            sendMsg_type = PubSubPayload.COMND_FWD

            # construct payload
            payload = self.constructPayload(channel, sendMsg_type, event.bloomfilter)
            # construct packet
            trigerPacket = self.packetConstruct(payload, subIp, pubIp, subInfo["Mac"], pubInfo["Mac"])

            outDpId = pubInfo["sID"]
            outPort = pubInfo["sPort"]
            self.sendPacket(trigerPacket, outDpId, outPort)
        else:
            log.warning("No Appointment with id %", event.appointmentID)

	# Store the data corresponding to an appointment, triger a createAppointment event
    def raiseAppointmentEvent(self, pub, sub, channel):
        self.appointmentTable[self.appointmentID] = {'publisher': pub,
                                                     'subscriber': sub,
                                                     'channel': channel}
        publisherInfo = self.memberInfo._member_table[pub]
        subscriberInfo = self.memberInfo._member_table[sub]
        self.raiseEvent(createAppointment, self.appointmentID, pub, publisherInfo["Mac"], publisherInfo["sPort"],
                        publisherInfo["sID"], sub, subscriberInfo["Mac"], subscriberInfo["sPort"], subscriberInfo["sID"])
        self.appointmentID += 1

    # Construct payload according to our packet struct
    def constructPayload(self, channel, msgType, payLoad):
        tempPSP = PubSubPayload(channel, msgType, payLoad)
        return tempPSP.packetOut()

    # Create a packet
    # Carefull:Port is int type, IP is <addr.IPAddr object> type and mac address is <addr.EthAddr object> type
    ##Consider to add raw packet in packets.raw parameter
    def packetConstruct(self, payload, srcIP, dstIP, srcMAC, dstMAC, srcPort=6633, dstPort=10000,
                        IP_protocol = pkt.ipv4.UDP_PROTOCOL, ethType = 2048):

        # Create UDP Packet
        ##Checksum and length is automaticly included when 
        ##packet_base pack method is calling udps hdr method
        sendUdp = pkt.udp()
        sendUdp.srcport = srcPort
        sendUdp.dstport = dstPort
        sendUdp.payload = payload

        # Create IP Packet
        sendIp = pkt.ipv4()
        dstIpObj = addr.IPAddr(srcIP)
        sendIp.srcip = dstIpObj
        srcIpObj = addr.IPAddr(dstIP)
        sendIp.dstip = srcIpObj
        sendIp.payload = sendUdp
        sendIp.protocol = pkt.ipv4.UDP_PROTOCOL

        # Create Ethernet Packet
        sendEth = pkt.ethernet()
        sendEth.src = srcMAC
        sendEth.dst = dstMAC
        sendEth.type = ethType
        sendEth.payload = sendIp
        unEth = sendEth
        sendEthPacket = sendEth.pack()

        return sendEthPacket

    # Comanding the switch to send the packet throught the given port
	# Default port 1
    def sendPacket(self, packet, dpId, port=1):
        # Send the packet
        con = core.openflow.getConnection(dpId)
        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port=port))
        msg.data = packet
        con.send(msg)

# Stores the info of the system clients
class MemberTable(object):
    def __init__(self):
        self._member_table = {}

    def add_member(self, memberIP, memberMac, switchPort, switchDpId):
        if memberIP not in self._member_table:
            self._member_table[memberIP] = {"Mac": memberMac,
                                            "sPort": switchPort,
                                            "sID": switchDpId}

    def remove_member(self, member_ip):
        del self._member_table[member_ip]

# Stores clients registered as publishers or subscribers in out system for a given Channel
class ChannelTable(object):
    def __init__(self):
        self._channel_table = {}

    #Adds publisher, if already exists return "Exists"
    def add_publisher(self, channel_name, publisher_ip):
        if channel_name not in self._channel_table:
            self._channel_table[channel_name] = {"publishers": set(),
                                                 "subscribers": set()}

        if publisher_ip not in self._channel_table[channel_name]['publishers']:
            self._channel_table[channel_name]['publishers'].add(publisher_ip)
            log.info("Publisher added "+ str(publisher_ip)+" for channel "+str(channel_name))
            return "Done"
        else:
            return "Exists"

    #Adds subscriber, if already exists return "Exists"
    def add_subscriber(self, channel_name, subscriber_ip):
        if channel_name not in self._channel_table:
            self._channel_table[channel_name] = {"publishers": set(),
                                                 "subscribers": set()}

        if subscriber_ip not in self._channel_table[channel_name]['subscribers']:
            self._channel_table[channel_name]['subscribers'].add(subscriber_ip)
            print "Subscriber added "+str(subscriber_ip)+" for channel "+str(channel_name)
            return "Done"
        else:
            return "Exists"

    #We take granted that a person cant pub and sub fore the same channel
    #Returns True if a person was removed, False if not
    def remove_person(self, channel, person_ip):
        if channel in self._channel_table:
            if person_ip in self._channel_table[channel]["publishers"]:
                self._channel_table[channel]["publishers"].remove(person_ip)
                self.check_channel(channel)
                return self.check_person(person_ip)
            if person_ip in self._channel_table[channel]["subscribers"]:
                self._channel_table[channel]["subscribers"].remove(person_ip)
                self.check_channel(channel)
                return self.check_person(person_ip)
            else:
                log.warning("No person with such ip recorded in "+str(channel)+"'s list")
        else:
            log.warning("No such channel "+str(channel))
        return True

    #Checks if a channel has records, if not remove it
    def check_channel(self, channel):
        if not self._channel_table[channel]:
            del self._channel_table[channel]

    #Checks if a person still has a record in Channeltable, if not remove him from memberTable
    #could not check the channel he is removed from
    def check_person(self, person_ip):
        person_flag = False
        for channel in self._channel_table:
            if person_ip in self._channel_table[channel]:
                person_flag = True
                break
        return person_flag

    #Return if the persone with ip_address is publisher or subscriber
    def pub_or_sub(self, channel, ip_address):
        if ip_address in self._channel_table[channel]["subscribers"]:
            return "subscriber"
        elif ip_address in self._channel_table[channel]["publishers"]:
            return "publisher"
        else:
            log.warning("No such person with ip"+str(ip_address))

    # Could do so it returns the set of subscribers and choose one
    def pubCheck(self, channel):
        if self._channel_table[channel]['publishers']:
            return next(iter(self._channel_table[channel]['publishers']))

    def subCheck(self, channel):
        return self._channel_table[channel]['subscribers']

    def __str__(self):
        return str(self._channel_table)


# Could add more options for randezvous_manager component, like choosing publisher
# so launch function would be more effective
def launch():
    core.registerNew(Manager)
