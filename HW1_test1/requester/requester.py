
from argparse import ArgumentParser
from socket import socket as create_socket, AF_INET, SOCK_DGRAM
from collections import namedtuple
from datetime import datetime
from common import *

dic = {}


def parse_cli_args():
    ''' Parse command line input.

    Return object has these fields:
    - port : int, from the -p parameter, to bind to
    - file_name: str, from the -o parameter, to serve
    '''
    parser = ArgumentParser(prog='sender')
    parser.add_argument('-p', dest='port', metavar='port', required=True, type=int)
    parser.add_argument('-o', dest='file_name', metavar='file option', required=True)
    return parser.parse_args()


# ==== tracker file parsing ====

''' Row of a tracker file. '''
TrackerRow = namedtuple('TrackerRow', [
    'file_name', # : string
    'id', # : int, for part retrieval sequencing
    'sender_hostname', # : string
    'sender_port', # : int
])

def parse_tracker_file_line(line):
    ''' Parse a TrackerRow from a line of text. '''
    elems = list(line.split(' '))
    assert (len(elems) == 4), f"line {repr(line)} has wrong elem num"
    return TrackerRow(
        file_name=elems[0],
        id=int(elems[1]),
        sender_hostname=elems[2],
        sender_port=int(elems[3])
    )

def read_tracker_file(path='tracker.txt'):
    ''' Read the tracker file and parse it as a TrackerRow list. '''
    with open(path, 'r') as f:
        return [parse_tracker_file_line(line) for line in f.readlines()]


# ==== remainder of requester program ====

def request(args):
    ''' Run the requester via the `args` object as returned from
    `parse_cli_args`.
    '''

    # read tracker file
    tracker_rows = read_tracker_file()

    # determine sequence of senders to request from
    tracker_row_seq = sorted(
        filter(
            lambda row: row.file_name == args.file_name,
            tracker_rows,
        ),
        key=lambda row: row.id,
    )

    # bind socket
    socket = create_socket(AF_INET, SOCK_DGRAM)
    socket.bind(("0.0.0.0", args.port))

    # begin download from each sender to the file
    next_sequence_num = 0
    with open(args.file_name, 'wb') as f:
        for row in tracker_row_seq:
            # send request
            packet = RequestPacket(file_name=args.file_name)
            binary = encode_packet(packet)
            socket.sendto(binary, (row.sender_hostname, row.sender_port))

            # receive response
            next_sequence_num = receive_from(f, socket, next_sequence_num)


def print_receiver_packet(packet,received_from):
    if packet.packet_type == PacketType.DATA:
        payload = packet.payload
    elif packet.packet_type == PacketType.END:
        payload = bytes()
    else:
        raise Exception(
            f"invalid packet type {repr(packet.packet_type)} for"
            f" print_receiver_packet"
        )

    #to calculate the data for the summary.
    address = received_from[0]+":"+str(received_from[1])

    receivedTime = datetime.now()
    if address in dic:
        if(packet.packet_type == PacketType.END):
           dic[address]['EndTime'] = receivedTime
        else:
            dic[address]['DataPackets'] = dic[address]['DataPackets']+1
            dic[address]['DataBytes'] = dic[address]['DataBytes']+len(payload)

    else:
        dic[address] = {'DataPackets' : 1, 'DataBytes' :  len(payload)}
        if(packet.packet_type == PacketType.DATA):
           dic[address]['StartTime'] = receivedTime

    #end for summary calculations.


    print(f"{packet.packet_type.name} Packet")
    print(f"received time:        {receivedTime}")
    print(f"sender addr:   {received_from[0]}:{received_from[1]}")
    print(f"Sequence num:     {packet.sequence_num}")
    print(f"length:           {len(payload)}")
    # assignment description does, in fact, say
    # "The first 4 bytes of the payload"
    # not the first 4 characters of the payload

    #for the end packet we are just printing the payload
    if(packet.packet_type == PacketType.END):
        print(f"payload:          0")
    else:
        payload_str = (payload[:min(4, len(payload))]
            .decode('utf-8', errors='replace'))
        print(f"payload:          {payload_str}")
    print()

def print_receiver_packet_summary(packet,received_from):
    address = received_from[0]+":"+str(received_from[1])
    totalDurationInSecs = (dic[address]['EndTime']-dic[address]['StartTime']).total_seconds()
    print(f"Summary")
    print(f"sender addr:   {received_from[0]}:{received_from[1]}")
    print(f"Total Data packets:     {dic[address]['DataPackets']}")
    print(f"Total Data bytes:          {dic[address]['DataBytes']}")
    avg_pps = dic[address]['DataPackets'] / totalDurationInSecs
    avg_pps = int(round(avg_pps))
    print(f"Average packets/second:          {avg_pps}")
    print(f"Duration of the test:         {totalDurationInSecs*1000} ms")
    print()


def receive_from(file, socket, next_sequence_num):
    ''' Receive Data packets and write to file until receive End packet.
    Return updated expected next sequence number.
    '''
    ended = False
    while not ended:
        # "The length parameter will always be less than 5KB."
        # 6000 bytes to allow header and to be safe
        binary, remote_addr = socket.recvfrom(6000)
        packet = decode_packet(binary)

        # assert (
        #     packet.sequence_num == next_sequence_num
        # ), f"expected sequence num {next_sequence_num}, got {packet.sequence_num}"
        
        if packet.packet_type == PacketType.DATA:
            file.write(packet.payload)
            print_receiver_packet(packet,remote_addr)
            next_sequence_num += len(packet.payload)
        elif packet.packet_type == PacketType.END:
            print_receiver_packet(packet,remote_addr)
            print_receiver_packet_summary(packet,remote_addr)
            ended = True
        else:
            raise Exception(
                f"requested received illegal packet type: "
                f"{repr(packet.packet_type)}"
            )
    return next_sequence_num


if __name__ == '__main__':
    request(parse_cli_args())
