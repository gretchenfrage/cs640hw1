from argparse import ArgumentParser
from socket import socket as create_socket, AF_INET, SOCK_DGRAM
from time import time, sleep
from datetime import datetime
import random

from common import *
import queue

def parse_cli_args():
    ''' Parse command line input.

    Returned object has these fields:
    - bind_to_port : int, from -p parameter, to bind to
    - queue_size : int, from -q parameter, the size of each of the three queues
    - forwarding_table : str, from -f parameter, file containg static forwarding table
    - log_file_name : str, from -l parameter, the name of the log file
    '''
    parser = ArgumentParser(prog='sender')
    parser.add_argument('-p', dest='bind_to_port', metavar='port', required=True, type=int)
    parser.add_argument('-q', dest='queue_size', metavar='queue_size', required=True, type=int)
    parser.add_argument('-f', dest='forwarding_table', metavar='filename', required=True, type=str)
    parser.add_argument('-l', dest='log_file_name', metavar='log', required=True, type=str)
    return parser.parse_args()

class Emulator:
    def __init__(self, hostname, port, queue_size, forwarding_table_file,log_file_name):
        self.emul_hostname = hostname
        self.emul_port = port
        self.queue_size = queue_size
        self.log_file = log_file_name
        self.forwarding_table = self.create_forwarding_table(forwarding_table_file)
        self.queues = [queue.Queue(),queue.Queue(),queue.Queue()]
        self.delayExpire = True

    #we are creating a forwarding table for this emulator from the given list.
    def createForwardingTable(self,forwarding_table):
        forwarding_table = {}
        with open(forwarding_table, 'r') as f:
            for line in f:
                tokens = line.strip().split()
                if (tokens[0] == self.emul_hostname and int(tokens[1]) == self.emul_port):
                    destination = tokens[2]+":"+str(tokens[3])
                    next_hop = (tokens[4], int(tokens[5]))
                    delay = int(tokens[6])
                    loss_prob = float(tokens[7])
                    forwarding_table[destination] = (next_hop, delay, loss_prob)

        return forwarding_table

    def routing(self,packet):
        destination = packet.dst_ip_address+":"+str(packet.dst_port)
        # Check if the destination is in the forwarding table
        if destination in self.forwarding_table:
            # If the destination is in the forwarding table, forward the packet to the next hop
            next_hop_details = self.forwarding_table[destination]
            self.queue_packet(packet)
        else:
            self.log_event(destination, "no forwarding entry found")
        
        #returning the next_hop_details.
        return next_hop_details

    def queue_packet(self,packet):
        if (len(self.queues[packet.priority-1])<self.queue_size) :
            self.queues[packet.priority-1].put(packet)
        else :
            self.log_event(packet, f"priority queue {packet.priority} was full")

    def send_packet(self,packet,socket,next_hop_details):
        next_hop = next_hop_details[0]
        delay = next_hop_details[1]
        loss_prob = next_hop_details[2]
        destination = packet.dst_ip_address+":"+str(packet.dst_port)
        #doing bandwidth simulation
        delayExpire = False
        time.sleep(delay/1000) # Convert delay from milliseconds to seconds
        delayExpire = True
        #doing loss simulation
        if random.random() > loss_prob:
            #encoding and sending to the next hop
            binary = encode_packet(packet)
            socket.sendto(binary, next_hop)
        else:
            self.log_event(packet,f"Packet dropped: destination {destination} lost due to loss probability")
        pass
    

    def send_emulator(self,socket,next_hop_details):
        if(self.queues[0].empty() == False):
            packet = self.queues[0].get()
            self.send_packet(packet,socket,next_hop_details)
        elif(self.queues[1].empty() == False):
            packet = self.queues[1].get()
            self.send_packet(packet,socket,next_hop_details)
        elif(self.queues[2].empty() == False):
            packet = self.queues[2].get()
            self.send_packet(packet,socket,next_hop_details)
        

    def log_event(self,packet, reason):
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
        log_entry = f"[{timestamp}] Packet dropped: {packet.src_ip_address}:{packet.src_port} -> {packet.dst_ip_address}:{packet.dst_port} "
        #need to check what is the length inner or outer.
        log_entry += f"Priority: {packet.priority}, Size: {packet.length}, Reason: {reason}"
        with open(self.log_file, 'a') as f:
            f.write(log_entry + '\n')



def run_emulator(args):
    emulator = Emulator(hostname='0.0.0.0', port=args.bind_to_port, forwarding_table_file=args.forwarding_table, queue_size=args.queue_size)
    socket = create_socket(AF_INET, SOCK_DGRAM)
    socket.bind(("0.0.0.0", args.bind_to_port))

    #binding the emulator to the port.
    while(True):
        binary, remote_addr = socket.recvfrom(6000)
        packet = decode_packet(binary)
        assert (
            packet.packet_type == PacketType.REQUEST
        ), f"emulator received non-request packet: {repr(packet)}"
        request = packet

        next_hop_details = emulator.routing(request)
        emulator.send_emulator(socket,next_hop_details)


    pass



if __name__ == '__main__':
    run_emulator(parse_cli_args())