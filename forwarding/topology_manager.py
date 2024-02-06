'''
Topology manager is responsible for adjusting the behavior of the switches as well as keeping track of the topology
of the network, delivering Randezvous Manager bloom filters associated with the path the packet has to go through.
'''

from pox.lib.revent import *
from pox.core import core
import networkx as nx
import ext.bloomfilter as bf
from pox.lib import addresses as addr
import pox.openflow.libopenflow_01 as of
import pox.openflow.nicira as nic
import pox.lib.packet.ethernet as ethernet
import pox.lib.packet.ipv6 as ipv6

log = core.getLogger()

#Class used to triger events for created topologies
class createTopology(Event):
    """
    Create bloom-filters
    """
    def __init__ (self, apId, bloomfilter):
        Event.__init__(self)
        self.appointmentID = apId
        self.bloomfilter = bloomfilter

class Topology(EventMixin):

    PACKET_MARK = "0F:0F:0F:0F:0F:0F"

    #Change the name at core
    _core_name = "topology_manager"

    _eventMixin_events = set([
      createTopology,
    ])

    # ToDo (Improve)
	# Make more object orianted data structs for more complicated network topology management
    def __init__(self):
        #Store dependencies between two neighbour nodes, of the type node1:{node2 :bloomfinter}
        self.graphDependencies = {}
        #Store the bloomfiters for the last edge of the graph that corresponds to the publisher
        self.sub_graphDependencies = {}
        #Store dependencies on host graphs forming spanning trees
        #the depencencies are of the type ip1 : [(1,2),(2,3)] meaning that in the graph there is a link between host with ip1
        #and a switch with dpid = 1, a link between node with dpid = 1 and another with dpid = 2 and so on
        self.hostDependencies = {}
        #Dict with a list which stores the subscriber's the publisher is sending to
        self.publisher_subs = {}
        #Store graph in a directional nx graph format
        self.topoGraph = nx.DiGraph()
        #Store hosts we already connected to the network by setting flows that correspond to links
        self.hosts_linked = []
        #Stores links already connected, maybe later a better way
        self.swiches_linked = []
        #Stores current table_id for switch's linkid forwarding rules
        self.table_ids = {}

        #We wait openflow_discovery and randezvous_manager to boot first
        def startup():
            core.randezvous_manager.addListeners(self)
            core.openflow_discovery.addListeners(self)
        core.call_when_ready(startup, 'randezvous_manager')

	# ToDo (Improve)
	# Update the data at LinkEvent with type = "drop"
    #When a new link is added from openflow_discovery, create a table and add the appropriate flows in it
    def _handle_LinkEvent (self, event):
        switch1_id = event.link.dpid1
        switch2_id = event.link.dpid2
        port1 = event.link.port1
        port2 = event.link.port2

        connection = core.openflow.getConnection(switch1_id)

        #Pox only supports one table, we need multiple tables and we achieve this with nicira extension
        #Enable multiple table capability on each switch
        # We do it only the first time switch connects
        if switch1_id not in self.table_ids:
            # Turn on Nicira packet_ins
            msg = nic.nx_packet_in_format()
            connection.send(msg)
            # Turn on ability to specify table in flow_mods
            msg = nic.nx_flow_mod_table_id()
            connection.send(msg)

            # Todo (Maybe)
			# Our own flow to Controller

        #Mac address for the switches in given port network cards
        mac_addr1 = str(self._find_mac(switch1_id, port1))
        self.topoGraph.add_edge(switch1_id, switch2_id)

        link_id = bf.bloomfilter.set_bloomfilter_by_mac(mac_addr1)

        #Store the link_id
        if switch1_id not in self.graphDependencies:
            self.graphDependencies[switch1_id] = {switch2_id: link_id}
        else:
            self.graphDependencies[switch1_id][switch2_id] = link_id

        try:
            self.insert_flow(switch1_id, link_id, port1)
        except:
            log.info("Aborting link down events. System shuting down")

    def _handle_createAppointment (self, event):

        #Get data from createAppointment event's object
        #Todo Get rid of not used parameters
        #appointmentID = appointmentID
        publisher_ip = event.publisher_ip
        #publisher_mac = str(event.publisher_mac)
        publisher_switch_port = event.publisher_switch_port
        publisher_switch_id = event.publisher_switch_id
        subscriber_ip = event.subscriber_ip
        #subscriber_mac = str(event.subscriber_mac)
        subscriber_switch_port = event.subscriber_switch_port
        subscriber_switch_id = event.subscriber_switch_id

        #If there is no graph dependency for the subscribers ip, create one and add corresponding bloomfilter
        if subscriber_ip not in self.sub_graphDependencies:
            #Find corresponding switch's network card's mac for specific subscriber
            sub_mac = str(self._find_mac(subscriber_switch_id, subscriber_switch_port))
            #Generate link id for this mac and store it in sub_graphDependencies
            sub_link_id = bf.bloomfilter.set_bloomfilter_by_mac(sub_mac)
            self.sub_graphDependencies[subscriber_ip] = sub_link_id
            if subscriber_ip not in self.hosts_linked:
                #Insert a flow for this link_id to coresponding switch with id = subscriber_switch_id
                self.insert_flow(subscriber_switch_id, sub_link_id, subscriber_switch_port)
                #We established the connection for this host
                self.hosts_linked.append(subscriber_ip)

        #Insert flows in case there arent any for the publisher
        if publisher_ip not in self.hosts_linked:
            #Find corresponding switch's network card's mac for specific publisher
            pub_mac = str(self._find_mac(publisher_switch_id, publisher_switch_port))
            pub_link_id = bf.bloomfilter.set_bloomfilter_by_mac(pub_mac)
            #Insert a flow for this link_id to coresponding switch with id = publisher_switch_id
            self.insert_flow(publisher_switch_id, pub_link_id, publisher_switch_port)
            #We established the connection for this host
            self.hosts_linked.append(publisher_ip)

        #Put the subscriber to hosts subscriber list
        if publisher_ip not in self.publisher_subs:
            self.publisher_subs[publisher_ip] = [subscriber_ip]
        else:
            if subscriber_ip not in self.publisher_subs[publisher_ip]:
                self.publisher_subs[publisher_ip].append(subscriber_ip)
            else:
                log.warning("Subscriber " + str(subscriber_ip) + " is already in publisher's " + publisher_ip + " list")

        #Calculate shortest path
        topo_short_path = nx.shortest_path(self.topoGraph, publisher_switch_id, subscriber_switch_id)
        #In case there isnt a forwarding graph for the publisher
        if publisher_ip not in self.hostDependencies:
            topo_short_graph = nx.DiGraph()
            for i in range(len(topo_short_path) - 1):
                topo_short_graph.add_edge(topo_short_path[i], topo_short_path[i + 1])
            self.hostDependencies[publisher_ip] = topo_short_graph
        else:
            #Get old topology
            old_topology = self.hostDependencies[publisher_ip]
            #Merge it with new one
            for i in range(len(topo_short_path) - 1):
                old_topology.add_edge(topo_short_path[i], topo_short_path[i + 1])
            #Update the stored graph
            self.hostDependencies[publisher_ip] = old_topology
        log.info("This is what happens" + str(self.hostDependencies[publisher_ip].edges()))
        bloomfilter = self._calc_bloomfilter(self.hostDependencies[publisher_ip], publisher_ip)

        bloomed_IPv6_addr = bloomfilter.to_IPv6_str()

        self.raiseEvent(createTopology, event.appointmentID, bloomed_IPv6_addr)

    def insert_flow(self, switch1_id, link_id, out_port):
        #Create new table_id entry if it doesnt exist
        if switch1_id not in self.table_ids:
            self.table_ids[switch1_id] = 0
        #Pick the current table id of the switch
        table_id = self.table_ids[switch1_id]

        bloomed_ipv6 = link_id.to_IPv6()

        connection = core.openflow.getConnection(switch1_id)

        #FIRST FLOW RULE
        #If link_id matches with the bloom filter: Forward and go to next table
        msg = nic.nx_flow_mod()
        msg.priority = 8
        msg.match.eth_type = ethernet.IPV6_TYPE
        #Check if the packet has our packets mark
        msg.match.eth_src = Topology.PACKET_MARK
        msg.match.ipv6_dst = bloomed_ipv6
        msg.match.ipv6_dst_mask = bloomed_ipv6
        msg.table_id = table_id
        msg.actions.append(of.ofp_action_output(port = out_port))
        msg.actions.append(nic.nx_action_resubmit.resubmit_table(table = table_id + 1))
        connection.send(msg)

        #SECOND FLOW RULE
        #Else: just go to next table
        msg = nic.nx_flow_mod()
        #We want this flow to not be prioritised from othere two flows
        msg.priority = 7
        msg.match.eth_type = ethernet.IPV6_TYPE
        #Check if the packet has our packets mark
        msg.match.eth_src = Topology.PACKET_MARK
        msg.table_id = table_id
        msg.actions.append(nic.nx_action_resubmit.resubmit_table(table = table_id + 1))
        connection.send(msg)

        #THIRD FLOW RULE
        #We dont want packets we just sent to return back from where it came from
        msg = nic.nx_flow_mod()
        #We want this flow to have a highter priority from the first flow rule
        msg.priority = 9
        msg.match.eth_src = Topology.PACKET_MARK
        msg.match.in_port = out_port
        msg.table_id = table_id
        msg.actions.append(nic.nx_action_resubmit.resubmit_table(table = table_id + 1))
        connection.send(msg)

        #Increase the counter of the table_id we are on
        self.table_ids[switch1_id] = self.table_ids[switch1_id] + 1

    #Find mac address of network interface of speciffic nodes port
    def _find_mac(self, dpid, port):
        con = core.openflow.getConnection(dpid)
        try:
            info = con.features
            #In the corresponding info
            for obj in info.ports:
                #Find speciffic port
                if obj.port_no == port:
                    #Return its mac address
                    return obj.hw_addr
        except:
            log.info('Ending connection with the Controller')

    #Calculate bloom filter
    def _calc_bloomfilter(self, graph, publisher_ip):
        bloomfilter = bf.bloomfilter()
        for i in range(len(graph)-1):
			edge_from = graph.edges()[i][0]
			edge_to = graph.edges()[i][1]
            temp_bloomfilter = self.graphDependencies[edge_from][edge_to]
            log.info("Temp Bloomfilter: " + str(temp_bloomfilter))
            bloomfilter = bloomfilter.merge(temp_bloomfilter)
        for sub in self.publisher_subs[publisher_ip]:
            log.info("Last nodes bloomfinter: " + str(self.sub_graphDependencies[sub]))
            #Last step we merge with bloom filters corresponding to subscribers edges
            bloomfilter = bloomfilter.merge(self.sub_graphDependencies[sub])
        log.info("Bloomfilter done "+str(bloomfilter))

        return bloomfilter

def launch ():
      core.registerNew(Topology)
