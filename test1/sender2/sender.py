
from argparse import ArgumentParser
from socket import socket as create_socket, AF_INET, SOCK_DGRAM
from time import time, sleep
from datetime import datetime

from common import *


def parse_cli_args():
    ''' Parse command line input.

    Returned object has these fields:
    - bind_to_port : int, from -p parameter, to bind to
    - send_to_port : int, from -g parameter, to send data to
    - send_rate : float, from -r parameter, packets-per-second rate limit
    - sequence_start : int, from -q parameter, initial sequence_num value
    - chunk_len : int, from -l parameter, data packet payload length
    '''
    parser = ArgumentParser(prog='sender')
    parser.add_argument('-p', dest='bind_to_port', metavar='port', required=True, type=int)
    parser.add_argument('-g', dest='send_to_port', metavar='requester port', required=True, type=int)
    parser.add_argument('-r', dest='send_rate', metavar='rate', required=True, type=float)
    parser.add_argument('-q', dest='sequence_start', metavar='seq_no', required=True, type=int)
    parser.add_argument('-l', dest='chunk_len', metavar='length', required=True, type=int)
    return parser.parse_args()


class RateLimiter:
    ''' Utility to limit the rate at which some event happens by sleeping. '''

    def __init__(self, rate):
        self.blocked_until = None
        self.delay = 1.0 / float(rate)

    def rate_limit_event(self):
        ''' Sleep until a rate-limited event is allowed to occur, and then
        update internal state to represent that it has occurred.
        '''
        now = time()
        if self.blocked_until is not None and now < self.blocked_until:
            sleep(self.blocked_until - now)
            self.blocked_until += self.delay
        else:
            self.blocked_until = now + self.delay


def print_sender_packet(packet, send_to):
    ''' Print packet information, including the trailing empty line, as
    required to be printed when the sender sends a packet.

    See example:
    https://github.com/Tingjia980311/cs640/blob/main/output1.txt
    '''

    if packet.packet_type == PacketType.DATA:
        payload = packet.payload
    elif packet.packet_type == PacketType.END:
        payload = bytes()
    else:
        raise Exception(
            f"invalid packet type {repr(packet.packet_type)} for"
            f" print_sender_packet"
        )

    print(f"{packet.packet_type.name} Packet")
    print(f"send time:        {datetime.now()}")
    print(f"requester addr:   {send_to[0]}:{send_to[1]}")
    print(f"Sequence num:     {packet.sequence_num}")
    print(f"length:           {len(payload)}")
    # assignment description does, in fact, say
    # "The first 4 bytes of the payload"
    # not the first 4 characters of the payload
    payload_str = (payload[:min(4, len(payload))]
        .decode('utf-8', errors='replace'))
    print(f"payload:          {payload_str}")
    print()


class PacketSeqSender:
    ''' Utility for a sender to send a sequence of packets to a receiver.
    Handles sequence number assignment.
    '''

    def __init__(
        self,
        socket,
        rate_limiter,
        remote_addr,
        send_to_port,
        sequence_start,
    ):
        self.socket = socket
        self.rate_limiter = rate_limiter
        self.send_to = (remote_addr[0], send_to_port)
        self.next_sequence_num = sequence_start

    def __dispense_sequence_num(self, payload_len):
        sequence_num = self.next_sequence_num
        # "For example, if the first seq_no is 50 and the payload size is 10
        # bytes, then the next seq_no should be 60."
        self.next_sequence_num += payload_len
        return sequence_num

    def __send_packet_inner(self, packet):
        binary = encode_packet(packet)
        self.rate_limiter.rate_limit_event()
        print_sender_packet(packet, self.send_to)
        self.socket.sendto(binary, self.send_to)

    def send_data_packet(self, payload):
        ''' Send a data packet, including rate limiting and printing. '''
        self.__send_packet_inner(DataPacket(
            sequence_num=self.__dispense_sequence_num(len(payload)),
            payload=payload,
        ))

    def send_end_packet(self):
        ''' Send an end packet, including rate limiting and printing. '''
        self.__send_packet_inner(EndPacket(
            sequence_num=self.__dispense_sequence_num(0),
        ))


def run_sender(args):
    ''' Run the sender indefinitely via the `args` object as returned from
    `parse_cli_args`.
    '''
    # setup
    socket = create_socket(AF_INET, SOCK_DGRAM)
    socket.bind(("0.0.0.0", args.bind_to_port))
    
    rate_limiter = RateLimiter(args.send_rate)

    # begin receiving request packets
    # while True:
    # "The length parameter will always be less than 5KB."
    # 6000 bytes to allow header and to be safe
    binary, remote_addr = socket.recvfrom(6000)
    packet = decode_packet(binary)
    assert (
        packet.packet_type == PacketType.REQUEST
    ), f"sender received non-request packet: {repr(packet)}"
    request = packet

    # begin sending response packets
    sender = PacketSeqSender(
        socket,
        rate_limiter,
        remote_addr,
        args.send_to_port,
        args.sequence_start,
    )

    # open the file and send its content chunk-by-chunk
    with open(request.file_name, 'rb') as f:
        more_chunks = True
        while more_chunks:
            chunk = f.read(args.chunk_len)
            if chunk:
                sender.send_data_packet(chunk)
            else:
                sender.send_end_packet()
                more_chunks = False

if __name__ == '__main__':
    run_sender(parse_cli_args())
