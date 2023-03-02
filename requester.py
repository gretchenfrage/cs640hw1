
from argparse import ArgumentParser
from socket import socket as create_socket, AF_INET, SOCK_DGRAM
from collections import namedtuple

from common import *


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
    socket.bind(("127.0.0.1", args.port))

    # begin download from each sender to the file
    next_sequence_num = 0
    with open(args.file_name, 'xb') as f:
        for row in tracker_row_seq:
            # send request
            packet = RequestPacket(file_name=args.file_name)
            binary = encode_packet(packet)
            socket.sendto(binary, (row.sender_hostname, row.sender_port))

            # receive response
            next_sequence_num = receive_from(f, socket, next_sequence_num)


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

        assert (
            packet.sequence_num == next_sequence_num
        ), f"expected sequence num {next_sequence_num}, got {packet.sequence_num}"
        
        if packet.packet_type == PacketType.DATA:
            file.write(packet.payload)
            next_sequence_num += len(packet.payload)
        elif packet.packet_type == PacketType.END:
            ended = True
        else:
            raise Exception(
                f"requested received illegal packet type: "
                f"{repr(packet.packet_type)}"
            )
    return next_sequence_num


if __name__ == '__main__':
    request(parse_cli_args())
