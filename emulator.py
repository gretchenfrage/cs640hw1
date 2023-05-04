from argparse import ArgumentParser
from socket import socket as create_socket, gethostname, AF_INET, SOCK_DGRAM
import time
from datetime import datetime
from collections import namedtuple, defaultdict
import random
from heapq import heappop, heappush
import copy

from common import *
import queue

import os

def parse_cli_args():
    ''' Parse command line input.

    Returned object has these fields:
    - bind_to_port : int, from -p parameter, to bind to
    - queue_size : int, from -q parameter, the size of each of the three queues
    - forwarding_table : str, from -f parameter, file containg static forwarding table
    - log_file_name : str, from -l parameter, the name of the log file
    '''
    parser = ArgumentParser(prog='emulator')
    parser.add_argument('-p', dest='bind_to_port', metavar='port', required=True, type=int)
    parser.add_argument('-q', dest='queue_size', metavar='queue_size', required=False, type=int)
    parser.add_argument('-l', dest='log_file_name', metavar='log', required=False, type=str)
    parser.add_argument('-f', dest='topology_file_name', metavar='filename', required=True, type=str)
    args = parser.parse_args()
    if not args.queue_size:
        args.queue_size = 100
    if not args.log_file_name:
        args.log_file_name = 'logfile'
    return args

DelayedPacket = namedtuple('DelayedPacket', [
    'packet',
    'delayed_until',
])

class NodeLinkState:
    def __init__(self):
        # highest ever known seq no
        self.seq_no = -1
        self.neighbors = []
        self.expires = None
        self.is_fresh = True
        # TODO: expiration something

class DirectLink:
    def __init__(self, last_heartbeat):
        self.last_heartbeat = last_heartbeat
        self.last_sent_heartbeat = 0
        self.is_online = True

def debug_log_sendto(packet, target):
    pass
    #debug_print(f"[SEND] {target} {packet}")

class Emulator:
    def __init__(self, hostname, port, queue_size, log_file_name, topology_file_name):
        self.emul_hostname = hostname
        self.emul_port = port
        self.queue_size = queue_size
        self.log_file = self.createLogFile(log_file_name)
        #self.forwarding_table = self.createForwardingTable(forwarding_table_file)
        self.queues = [queue.Queue(),queue.Queue(),queue.Queue()]
        self.delayed_packet = None

        # mapping from (ip address string, port int) to NodeLinkState
        # defaultdict makes queries for absent keys auto-populate that entry with NodeLinkState()
        self.nodes_link_state = defaultdict(NodeLinkState)

        # mapping from (ip address string, port int) to DirectLink
        self.direct_links = self.read_direct_links(hostname, port, topology_file_name)

        self.interval_of_transmission = 1
        self.last_transmitted = None
        self.current_my_seq_no = 0

        self.link_send_heartbeat_interval = 1
        self.link_timeout_period = 3

        debug_print(f"{self.direct_links=}")



    def createLogFile(self,log_file_name):
        if not os.path.exists(log_file_name):
            open(log_file_name, "w").close()
        return log_file_name

    def read_direct_links(self, my_hostname, my_port, topology_file_name):
        # the "readtopology" function

        now = time.time()

        meeeee = (resolve_ip(my_hostname), my_port)
        with open(topology_file_name, 'r') as f:
            for line in f.readlines():
                parts = line.split(' ')
                parts = [part.split(',') for part in parts]
                parts = [(part[0], int(part[1])) for part in parts]
                parts = [(resolve_ip(hostname), port) for hostname, port in parts]

                if parts[0] == meeeee:
                    return {
                        part: DirectLink(now)
                        for part in parts[1:]
                    }
        raise Exception(
            f"couldn't find my direct links in topology.txt {meeeee=}"
        )

    def compute_forwarding_table(self):
        ''' Compute forwarding table from self.nodes_link_state. '''
        # the "buildForwardTable" function

        now = time.time()

        self.forwarding_table = {}

        conns = defaultdict(set)

        for a, node_link_state in self.nodes_link_state.items():
            if node_link_state.is_fresh:
                if node_link_state.expires is not None and node_link_state.expires < now:
                    node_link_state.is_fresh = False
                    debug_print(f"[EXPIRED] {a} {node_link_state.expires=}")
            else:
                if node_link_state.expires >= now:
                    node_link_state.is_fresh = True
                    debug_print(f"[UN-EXPIRED] {a} {node_link_state.expires=}")

            if node_link_state.is_fresh:
                for neighbor in node_link_state.neighbors:
                    b = (neighbor.ip_address, neighbor.port)

                    conns[a].add((b, neighbor.cost))
                    conns[b].add((a, neighbor.cost))

        #debug_print(f"{conns=}")
        source = (get_host_ip(), self.emul_port)

        def dijkstra(src):
            visited = set()
            distance = defaultdict(lambda: float('inf'))
            #prev_hop = dict()

            distance[src] = 0
            priority_queue = [(0, src, None)]

            while priority_queue:
                dist, node, prev = heappop(priority_queue)

                if node in visited:
                    continue

                visited.add(node)

                if prev is None:
                    pass
                elif prev == source:
                    self.forwarding_table[f"{node[0]}:{node[1]}"] = f"{node[0]}:{node[1]}"
                else:
                    self.forwarding_table[f"{node[0]}:{node[1]}"] = self.forwarding_table[f"{prev[0]}:{prev[1]}"]
                #prev_hop[node] = prev

                for neighbor_key, neighbor_cost in conns[node]:
                    if neighbor_key not in visited:
                        new_dist = dist + neighbor_cost
                        if new_dist < distance[neighbor_key]:
                            distance[neighbor_key] = new_dist
                            heappush(priority_queue, (new_dist, neighbor_key, node))

            #return prev_hop

        #rev_hop = dijkstra(source)
        dijkstra(source)

        self.forwarding_table = {
            key: (
                # next hop
                next_hop,
                # delay,
                0.0,
                # loss probability
                0.0,
            )
            for key, next_hop in self.forwarding_table.items()
        }

    def handle_link_packet(self, packet, received_from, binary, socket):
        # running this on any packet so that any packet received over link is counted as keeping connection alive
        # a nice property
        self.handle_heartbeat_packet(packet, received_from)
        
        if packet.packet_type == LinkPacketType.OUTER:
            self.routing(packet)
        elif packet.packet_type == LinkPacketType.HEARTBEAT:
            pass
        elif packet.packet_type == LinkPacketType.LINKSTATE:
            self.handle_link_state_packet(packet, received_from, binary, socket)
        elif packet.packet_type == LinkPacketType.ROUTETRACE:
            # TODO routetrace logic
            self.routeTraceFrwding(packet, socket)
            # raise Exception('unimplemented')
        else:
            raise Exception(f"unknown packet type for emulator: {repr(packet)}")

    def routeTraceFrwding(self, packet, socket):
        # the "forwardpacket" function specifically for routetrace packets
        # outer packets as in the previous assignments are handled in the other one
        if packet.TTL == 0:
            received_ip_address = packet.src_ip_address
            received_port = packet.src_port
            # Create a new routetrace packet with the emulator's IP and port as the source address
            new_packet = RouteTracePacket( TTL=packet.TTL, src_ip_address=get_host_ip(), src_port=self.emul_port, 
                          dst_ip_address=packet.dst_ip_address, dst_port=packet.dst_port)
            
            #self.send_packet(new_packet,(received_ip_address,received_port))
            binary = encode_packet(new_packet)
            debug_print(f"sending routetrace packet response {repr(packet)} to {repr((received_ip_address,received_port))}")
            socket.sendto(binary, (received_ip_address,received_port))
        else:
            # Decrement the TTL value in the packet and forward it to the next hop based on the routing table
            #packet.TTL -= 1
            packet = RouteTracePacket(
                TTL=packet.TTL - 1,
                src_ip_address=packet.src_ip_address,
                src_port=packet.src_port,
                dst_ip_address=packet.dst_ip_address,
                dst_port=packet.dst_port,
            )

            #TODO: need to get the next shortest hop 
            # next_hop = self.(packet.dest_ip)
            #next_hop = (a,b)
            #self.send_packet(packet, next_hop)

            destination = packet.dst_ip_address + ":" + str(packet.dst_port)
            if destination in self.forwarding_table:
                next_hop = self.forwarding_table[destination][0]
                binary = encode_packet(packet)
                debug_print(f"sending routetrace packet {repr(packet)} to {repr(next_hop)}")
                socket.sendto(binary, (next_hop.split(':')[0], int(next_hop.split(':')[1])))
            else:
                debug_print(f"no forwarding entry found for routetrace packet {packet=}")

    def handle_heartbeat_packet(self, packet, received_from):
        if received_from not in self.direct_links:
            return
        direct_link = self.direct_links[received_from]
        direct_link.last_heartbeat = time.time()
        if not direct_link.is_online:
            direct_link.is_online = True
            debug_print(f"[LINK UP] {repr(received_from)} {direct_link.last_heartbeat=}")

    def handle_link_state_packet(self, packet, received_from, binary, socket):
        # I guess this would be the "createroutes" function?
        # one way or the other, we've implemented the functionality in an isomorphic way

        # lookup entry (create if necessary)
        node_link_state = self.nodes_link_state[(packet.creator_ip_address, packet.creator_port)]

        #debug_print(f"received link state packet {packet} from {received_from}")
        
        # short-circuit if new packet of date
        if packet.seq_no <= node_link_state.seq_no:
            #debug_print(f"ignoring link state packet because it's out of date {packet=} {node_link_state=} {packet.seq_no=} {node_link_state.seq_no=}")
            return
        else:
            pass
            #debug_print(f"link state packet is not out of date  {packet=} {node_link_state=} {packet.seq_no=} {node_link_state.seq_no=}")

        # update internal entry
        node_link_state.seq_no = packet.seq_no
        node_link_state.neighbors = list(packet.neighbors)
        node_link_state.expires = packet.expires

        # TODO recalculate routing table

        # reliable flood it
        direct_link_match_counter = 0
        for direct_link in self.direct_links.keys():
            if direct_link == (resolve_ip(received_from[0]), received_from[1]):
                #debug_print(f"not flooding to {repr(direct_link)} because that's who I received it from")
                direct_link_match_counter += 1
            #debug_print(f"flooding-relaying to {repr(direct_link)}: {repr(packet)}")
            debug_log_sendto(packet, direct_link)
            socket.sendto(binary, direct_link)

        if direct_link_match_counter != 1:
            debug_print(f"warning: {direct_link_match_counter=} (should be 1, right?)")

        self.on_nodes_link_state_update()

    def on_nodes_link_state_update(self):

        self.curr_printing_connectivity = {
            key: [
                f"{neighbor.ip_address}:{neighbor.port}"
                for neighbor in val.neighbors
            ]
            for key, val in self.nodes_link_state.items()
        }
        if self.curr_printing_connectivity != getattr(self, 'last_printed_connectivity', None):
            debug_print("")
            debug_print("printing connectivity graph")
            for key, val in self.curr_printing_connectivity.items():
                key_str = f"{key[0]}:{str(key[1])}"
                debug_print(f"- {key_str} has the following links:")
                for neighbor in val:
                    debug_print(f"- - {neighbor}")
            debug_print("")
        self.last_printed_connectivity = copy.deepcopy(self.curr_printing_connectivity)


#        if self.nodes_link_state != getattr(self, 'last_printed_nodes_link_state', None):
#            debug_print("")
#            debug_print("printing connectivity graph")
#            debug_print(f"{self.nodes_link_state=}")
#            #for key, val in self.nodes_link_state.items():
#            #    key_str = f"{key[0]}:{str(key[1])}"
#            #    debug_print(f"- {key_str} has the following links:")
#            #    for neighbor in val.neighbors:
#            #        neighbor_str = f"{neighbor.ip_address}:{neighbor.port}"
#            #        debug_print(f"- - {neighbor_str}")
#            debug_print("")
#
#            self.last_printed_nodes_link_state = copy.deepcopy(self.nodes_link_state)
        
        self.compute_forwarding_table()

        if self.forwarding_table != getattr(self, 'last_printed_forwarding_table', None):
            debug_print("")
            debug_print("printing forwarding table")
            for key, (val, _, _) in self.forwarding_table.items():
                debug_print(f"- ({key}, {val})")
            debug_print("")

            self.last_printed_forwarding_table = self.forwarding_table

    def routing(self, packet):
        destination = packet.dst_ip_address+":"+str(packet.dst_port)
        # Check if the destination is in the forwarding table
        if destination in self.forwarding_table:
            # If the destination is in the forwarding table, forward the packet to the next hop
            # next_hop_details = self.forwarding_table[destination]
            self.queue_packet(packet)
        else:
            self.log_event(packet, "No forwarding entry found")
        
        #returning the next_hop_details.
        # return next_hop_details

    def queue_packet(self,packet):
        # print("IN the queue")
        # print(packet.priority.value)
        if ((self.queues[packet.priority.value-1]).qsize() <self.queue_size) :
            self.queues[packet.priority.value-1].put(packet)
        else :
            self.log_event(packet, f"Priority queue {packet.priority} was full")

    def send_packet(self,packet,socket,next_hop_details):
        next_hop = next_hop_details[0]
        delay = next_hop_details[1]
        loss_prob = next_hop_details[2]
        destination = packet.dst_ip_address+":"+str(packet.dst_port)
        #doing bandwidth simulation
        #doing loss simulation
        dont_drop = True
        # "Note that your emulator should NOT drop END packets. This is because
        # testing is made harder when END packets get dropped."
        if packet.inner.packet_type != PacketType.END:
            rand = random.random()
            debug_print(f"loss prob = {loss_prob}, rand = {rand}")
            dont_drop = rand > loss_prob
        if dont_drop:
            #encoding and sending to the next hop
            binary = encode_packet(packet)
            #debug_print(f"sending {repr(packet)} to {repr(next_hop)}")
            socket.sendto(binary, (next_hop.split(':')[0], int(next_hop.split(':')[1])))
        else:
            self.log_event(packet,f"Packet dropped: destination {destination} lost due to loss probability")
    

    def dequeue_packet(self,socket):
        flag = False
        if(self.queues[0].empty() == False):
            packet = self.queues[0].get()
            flag = True
        elif(self.queues[1].empty() == False):
            packet = self.queues[1].get()
            flag = True
        elif(self.queues[2].empty() == False):
            packet = self.queues[2].get()
            flag = True

        if(flag == True):
            destination = packet.dst_ip_address+":"+str(packet.dst_port)
            next_hop_details = self.forwarding_table[destination]
            delay = next_hop_details[2]
            delayed_until = time.time() + float(delay) / 1000
            self.delayed_packet = DelayedPacket(
                packet=packet,
                delayed_until=delayed_until
            )

    def send_emulator(self, socket):
        # this gets called constantly
        # so naive busy-polling logic can simply go in here :)
        
        now = time.time()
        
        # heartbeat stuff with direct links
        for send_to, direct_link in self.direct_links.items():
            # periodically send heartbeat to links
            if now - direct_link.last_sent_heartbeat > self.link_send_heartbeat_interval:
                direct_link.last_sent_heartbeat = now # AAAAAAAAAAAAAAAAAAAAAAAAAA there we goes
                socket.sendto(encode_packet(HeartbeatPacket()), send_to)

            # and detect if the link hasn't sent myself a heartbeat in too long
            if direct_link.is_online and now - direct_link.last_heartbeat > self.link_timeout_period:
                direct_link.is_online = False
                debug_print(f"[LINK DOWN] {repr(send_to)} {direct_link.last_heartbeat}")

        # periodic transmission of link state packet
        if self.last_transmitted is None or now - self.last_transmitted >= self.interval_of_transmission:
            self.last_transmitted = now

            self.current_my_seq_no += 1

            ls_packet = LinkStatePacket(
                creator_ip_address=resolve_ip(self.emul_hostname),
                creator_port=self.emul_port,
                seq_no=self.current_my_seq_no,
                expires=now + 3,
                neighbors=[
                    LinkInfo(
                        ip_address=direct_link[0],
                        port=direct_link[1],
                        cost=1.0,
                    )
                    for direct_link, direct_link_obj in self.direct_links.items()
                    if direct_link_obj.is_online
                ]
            )
            ls_binary = encode_packet(ls_packet)

            for direct_link in self.direct_links.keys():
                #debug_print(f"sending ls packet {ls_packet} to {direct_link}")
                debug_log_sendto(ls_packet, direct_link)
                socket.sendto(ls_binary, direct_link)

            my_node_link_state = self.nodes_link_state[(resolve_ip(self.emul_hostname), self.emul_port)]
            my_node_link_state.seq_no = self.current_my_seq_no
            my_node_link_state.neighbors = list(ls_packet.neighbors)

            self.on_nodes_link_state_update()

        # other stuff

        if self.delayed_packet is None:
            self.dequeue_packet(socket)

        if (
            self.delayed_packet is not None
            and time.time() >= self.delayed_packet.delayed_until
        ):
            packet = self.delayed_packet.packet
            self.delayed_packet = None
            destination = packet.dst_ip_address+":"+str(packet.dst_port)
            next_hop_details = self.forwarding_table[destination]
            self.send_packet(packet,socket,next_hop_details)

    def log_event(self,packet, reason):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
        log_entry = f"[{timestamp}] Packet dropped: {packet.src_ip_address}:{packet.src_port} -> {packet.dst_ip_address}:{packet.dst_port} "
        #need to check what is the length inner or outer.
        payload_size = len(encode_inner_packet(packet.inner))
        log_entry += f"Priority: {packet.priority.value}, Size: {payload_size}, Reason: {reason}"
        # log_entry += f"Priority: {packet.priority.value}, Size: {packet.inner.length}, Reason: {reason}"
        with open(self.log_file, 'a') as f:
            f.write(log_entry + '\n')
        debug_print(log_entry)



def run_emulator(args):
    socket = create_socket(AF_INET, SOCK_DGRAM)
    socket.bind(("0.0.0.0", args.bind_to_port))
    socket.setblocking(False)

    emulator = Emulator(
        # as per https://piazza.com/class/ldj54bkd4mi1g/post/153
        hostname=gethostname(),
        port=args.bind_to_port,
        queue_size=args.queue_size,
        log_file_name=args.log_file_name,
        topology_file_name=args.topology_file_name,
    )

    #binding the emulator to the port.
    while(True):
        emulator.send_emulator(socket)
        try:
            binary, remote_addr = socket.recvfrom(6000) 
            packet = decode_packet(binary)
            #debug_print(f"[RECV] {remote_addr} {packet}")
            emulator.handle_link_packet(packet, remote_addr, binary, socket)
        except BlockingIOError:
            time.sleep(0.01)


    



if __name__ == '__main__':
    run_emulator(parse_cli_args())