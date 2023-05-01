
from argparse import ArgumentParser
from socket import socket as create_socket, AF_INET, SOCK_DGRAM
from collections import namedtuple
from datetime import datetime
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
    parser.add_argument('-f', dest='net_hostname', metavar='f_hostname', required=True)
    parser.add_argument('-e', dest='net_port', metavar='f_port', required=True, type=int)
    parser.add_argument('-w', dest='window_size', metavar='window', required=True, type=int)
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


# ==== printing and collecting stats ====

class AddressStats:
    def __init__(self, start_time):
        self.start_time = start_time
        self.data_packets = 0
        self.data_bytes = 0
        self.end_time = None


def print_receiver_packet(packet, received_from, stats):
    received_time = datetime.now()

    if packet.packet_type == PacketType.DATA:
        payload = packet.payload
    elif packet.packet_type == PacketType.END:
        payload = bytes()
    else:
        raise Exception(
            f"invalid packet type {repr(packet.packet_type)} for"
            f" print_receiver_packet"
        )

    address = received_from[0] + ":" + str(received_from[1])

    if address not in stats:
        stats[address] = AddressStats(received_time)

    if packet.packet_type == PacketType.DATA:
        stats[address].data_packets += 1
        stats[address].data_bytes += len(payload)
    elif packet.packet_type == PacketType.END:
        stats[address].end_time = received_time
    else:
        raise Exception('unreachable')

    # HW2: "Suppress display of individual DATA packet
    # information."
    if False:
        print(f"{packet.packet_type.name} Packet")
        print(f"received time:        {received_time}")
        print(f"sender addr:   {received_from[0]}:{received_from[1]}")
        print(f"Sequence num:     {packet.sequence_num}")
        print(f"length:           {len(payload)}")

        if packet.packet_type == PacketType.DATA:
            # assignment description does, in fact, say
            # "The first 4 bytes of the payload"
            # not the first 4 characters of the payload
            payload_str = (payload[:min(4, len(payload))]
                .decode('utf-8', errors='replace'))
            print(f"payload:          {payload_str}")
        elif packet.packet_type == PacketType.END:
            # for the end packet we just print the payload
            print(f"payload:          0")
        else:
            raise Exception('unreachable')

        print()


def print_receiver_packet_summary(packet, received_from, stats):
    address = received_from[0] + ":" + str(received_from[1])
    total_duration = stats[address].end_time - stats[address].start_time
    total_duration_secs = total_duration.total_seconds()

    print(f"Summary")
    print(f"sender addr:            {received_from[0]}:{received_from[1]}")
    print(f"Total Data packets:     {stats[address].data_packets}")
    print(f"Total Data bytes:       {stats[address].data_bytes}")
    avg_pps = stats[address].data_packets / total_duration_secs
    avg_pps = int(round(avg_pps))
    print(f"Average packets/second: {avg_pps}")
    print(f"Duration of the test:   {total_duration_secs * 1000} ms")
    print()


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
    src_ip_address, src_port = socket.getsockname()
    net_send_to = (args.net_hostname, args.net_port)

    # begin download from each sender to the file
    stats = {}
    with open(args.file_name, 'wb') as f:
        for row in tracker_row_seq:
            # convenience closure to wrap packets with OuterPacket
            dst_ip_address=resolve_ip(row.sender_hostname)
            encapsulate = lambda inner: OuterPacket(
                priority=PriorityLevel(1),
                src_ip_address=get_host_ip(),
                src_port=src_port,
                dst_ip_address=dst_ip_address,
                dst_port=row.sender_port,
                inner=inner,
            )

            # send request
            packet = encapsulate(RequestPacket(
                file_name=args.file_name,
                window_size=args.window_size,
            ))
            binary = encode_packet(packet)
            debug_print(f"sending {repr(packet)} to {repr(net_send_to)}")
            socket.sendto(binary, net_send_to)

            # receive response
            receive_from(
                f, socket, net_send_to, encapsulate, args.window_size, stats
            )


def receive_from(file, socket, net_send_to, encapsulate, window_size, stats):
    ''' Receive Data packets and write to file until receive End packet.
    '''
    ended = False

    window_sequence_num_start = 1
    window_data_packets = [None for _ in range(window_size)]
    window_missing_count = window_size

    while not ended:
        # "The length parameter will always be less than 5KB."
        # 6000 bytes to allow header and to be safe
        binary, remote_addr = socket.recvfrom(6000)
        packet = decode_packet(binary)
        
        # "Verify that the destination IP address in the packet is indeed its
        # own IP address"
        if not (
            packet.dst_ip_address == get_host_ip()
            and packet.dst_port == socket.getsockname()[1]
        ):
            # just ignoring for now, possibly it would be better to error
            continue

        if packet.inner.packet_type == PacketType.DATA:
            # received data packet

            # send back ack
            #
            # "The requester acks every packet that it receives, even if it
            # has already written that packet to the file"
            #
            # am assuming here that we should be sending the ack packets to the
            # same as we're sending request packets to, hopefully that's fine
            ack_packet = encapsulate(AckPacket(
                sequence_num=packet.inner.sequence_num,
            ))
            ack_binary = encode_packet(ack_packet)
            if not should_drop_debug_thing(ack_packet):
                debug_print(f"sending {repr(ack_packet)}")
                socket.sendto(ack_binary, net_send_to)

            # ignore packet if older than current window
            if packet.inner.sequence_num < window_sequence_num_start:
                continue

            index = packet.inner.sequence_num - window_sequence_num_start

            # this should not be possible for well-behaving senders
            assert (
                index < window_size
            ), f"received a packet for a future window {repr(packet)}"

            # ignore packet if already received (ack was still already sent)
            if window_data_packets[index] is not None:
                continue

            # update window state
            window_data_packets[index] = packet
            window_missing_count -= 1

            # if window fully received, write to file and prepare next window
            if window_missing_count == 0:
                # write to file
                for packet in window_data_packets:
                    file.write(packet.inner.payload)
                    print_receiver_packet(packet.inner, remote_addr, stats)

                # prepare for next window
                window_sequence_num_start += window_size
                window_data_packets = [None for _ in range(window_size)]
                window_missing_count = window_size
        elif packet.inner.packet_type == PacketType.END:
            # received end packet

            # write the last window to the file
            last_window_size = window_size - window_missing_count
            for data_packet in window_data_packets[:last_window_size]:
                assert (
                    data_packet is not None
                ), "END packet received, but last window received packets " \
                    "do not form a prefix"
                file.write(data_packet.inner.payload)

            # print and end
            print_receiver_packet(packet.inner, remote_addr, stats)
            print_receiver_packet_summary(packet.inner, remote_addr, stats)
            ended = True
        else:
            raise Exception(
                f"requested received illegal packet type: "
                f"{repr(packet.packet_type)}"
            )


if __name__ == '__main__':
    request(parse_cli_args())
