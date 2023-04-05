
from argparse import ArgumentParser
from socket import socket as create_socket, AF_INET, SOCK_DGRAM
from time import time, sleep
from datetime import datetime
from queue import SimpleQueue

from common import *


def parse_cli_args():
    ''' Parse command line input.

    Returned object has these fields:
    - bind_to_port   : int, from -p parameter, to bind to
    - requester_port : int, from -g parameter, for dst_port
    - send_rate      : float, from -r parameter, packets-per-second rate limit
    - sequence_start : int, from -q parameter
                       OBSOLETE: initial sequence_num value
                       Addendum (HW2): now doesn't seem to be used for anything
    - chunk_len      : int, from -l parameter, data packet payload length
    - net_hostname   : from -f parameter, hostname of the network emulator to
                       directly send packets to
    - net_port       : from -e parameter, port of the network emulator to
                       directly send packets to
    - priority       : from -i parameter, priority level to send packets with
    - timeout_ms     : float, from -t parameter, timeout for resending packet
                       if haven't received ack
    '''
    parser = ArgumentParser(prog='sender')
    parser.add_argument('-p', dest='bind_to_port', metavar='port', required=True, type=int)
    parser.add_argument('-g', dest='requester_port', metavar='requester port', required=True, type=int)
    parser.add_argument('-r', dest='send_rate', metavar='rate', required=True, type=float)
    parser.add_argument('-q', dest='sequence_start', metavar='seq_no', required=False, type=int)
    parser.add_argument('-l', dest='chunk_len', metavar='length', required=True, type=int)
    parser.add_argument('-f', dest='net_hostname', metavar='f_hostname', required=True)
    parser.add_argument('-e', dest='net_port', metavar='f_port', required=True, type=int)
    parser.add_argument('-i', dest='priority', metavar='priority', required=True, type=int)
    parser.add_argument('-t', dest='timeout_ms', metavar='timeout', required=True, type=float)
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


def socket_recvfrom_deadline(socket, deadline):
    ''' Like `socket.recvfrom(6000)`, but times out at instant `deadline` and
    returns `None`.
    '''
    now = time()
    socket.settimeout(max(deadline - now, 0))
    try:
        return socket.recvfrom(6000)
    except (TimeoutError, BlockingIOError):
        return None
    else:
        return None


class WindowListItem:
    def __init__(self, data_packet):
        self.data_packet = data_packet
        self.acked = False
        self.resend_count = 0

class WindowQueueItem:
    def __init__(self, index, sent):
        self.index = index
        self.sent = sent

class PacketSeqSender:
    ''' Utility for a sender to send a sequence of packets to a receiver.
    Handles sequence number assignment

    HW2: also handles windows, acks, resending of data packets.
    '''

    def __init__(
        self,
        socket,
        rate_limiter,
        net_hostname,
        net_port,
        dst_addr,
        dst_port,
        window_size,
        timeout,
        priority,
    ):
        # basic state
        self.socket = socket
        self.rate_limiter = rate_limiter
        self.send_to = (net_hostname, net_port)
        self.dst_addr = dst_addr
        self.dst_port = dst_port
        self.window_size = window_size
        self.timeout = timeout
        self.priority = priority
        # HW2: "Always start at sequence number 1"
        self.next_sequence_num = 1
        
        # window state
        self.__reset_window_state()

        # stats
        self.num_retransmissions = 0
        self.num_total_transmissions = 0


    def __dispense_sequence_num(self):
        sequence_num = self.next_sequence_num
        # OBSOLETE: "For example, if the first seq_no is 50 and the payload
        #           size is 10 bytes, then the next seq_no should be 60."
        #
        # HW2: "Increment the sequence number by 1 for each packet sent,
        # instead of by the packet length"
        self.next_sequence_num += 1
        return sequence_num

    def __send_packet_inner(self, packet):
        ''' Encapsulate and encode inner packet, rate limit, then send. Also
        print.
        '''
        packet = OuterPacket(
            priority=self.priority,
            src_ip_address=self.socket.getsockname()[0],
            src_port=self.socket.getsockname()[1],
            dst_ip_address=self.dst_addr,
            dst_port=self.dst_port,
            inner=packet,
        )
        binary = encode_packet(packet)
        self.rate_limiter.rate_limit_event()
        print_sender_packet(packet.inner, self.send_to)

        if not should_drop_debug_thing(packet):
            self.socket.sendto(binary, self.send_to)

    def __reset_window_state(self):
        # list of WindowListItem, containing each packet in the current window
        # and whether it's been acked
        self.window_list = []
        # queue of WindowQueueItem, queue of indexes in the window list and
        # when they were last sent. assumed to always stay in order of last
        # sent.
        self.window_queue = SimpleQueue()
        # sequence number of the first packet of the current window
        self.window_sequence_num_start = self.next_sequence_num

    def __pop_next_unacked(self):
        ''' Pop the next window queue item which has not been acked, or return
        None.
        '''
        while not self.window_queue.empty():
            queue_item = self.window_queue.get_nowait()
            if not self.window_list[queue_item.index].acked:
                return queue_item
        return None

    def finalize_window(self):
        ''' Wait for all packets in current window to have been acknowledged,
        resending if appropriate.
        '''

        # until queue empty
        next_unacked = self.__pop_next_unacked()
        while next_unacked is not None:

            # wait until either
            # - next window queue item reaches deadline
            # - receive a packet
            deadline = next_unacked.sent + self.timeout
            received = socket_recvfrom_deadline(self.socket, deadline)

            if received is None:
                list_item = self.window_list[next_unacked.index]

                # next window queue item reached deadline
                if list_item.resend_count == 5:
                    # if reached resend count, give up and mark as acked
                    sequence_num = list_item.data_packet.sequence_num
                    print(f"giving up on sequence num {sequence_num}")

                    # mark that item in the list as acked
                    list_item.acked = True
                    next_unacked = self.__pop_next_unacked()
                else:
                    # if haven't reached resend count, resend
                    list_item.resend_count += 1

                    # resend it (with rate limiting)
                    self.__send_packet_inner(list_item.data_packet)
                    
                    # reinsert it into the back of the window queue
                    # (with new sent time)
                    next_unacked.sent = time()
                    self.window_queue.put_nowait(next_unacked)
                    next_unacked = self.__pop_next_unacked()

                    # update stats
                    self.num_total_transmissions += 1
                    self.num_retransmissions += 1
            else:
                # received a packet

                # it must be an ack packet
                binary, remote_addr = received
                packet = decode_packet(binary)
                assert (
                    packet.inner.packet_type == PacketType.ACK
                ), f"sender received non-ack packet: {repr(packet)}"
                ack = packet

                # mark that item in the list as acked
                index = ack.inner.sequence_num - self.window_sequence_num_start
                self.window_list[index].acked = True

                # handle if the acked packet was next_unacked
                if index == next_unacked.index:
                    next_unacked = self.__pop_next_unacked()

    def send_data_packet(self, payload):
        ''' Send a data packet, including rate limiting and printing.
        
        HW2: also handle windowing, acks, and resending. Windowing within a
        sequence of data packets is handled automatically. However, the
        sequence must be finalized with a manual call to `finalize_window`
        before sending the end packet.
        '''
        # prepare
        data_packet = DataPacket(
            sequence_num=self.__dispense_sequence_num(),
            payload=payload,
        )
        
        # send (including rate limiting)
        self.__send_packet_inner(data_packet)
        now = time()

        # update windowing data structures
        list_index = len(self.window_list)
        self.window_list.append(WindowListItem(data_packet))
        self.window_queue.put_nowait(WindowQueueItem(list_index, now))

        # update stats
        self.num_total_transmissions += 1

        if len(self.window_list) == self.window_size:
            # if window used up, automatically finalize window and begin next
            # one
            self.finalize_window()
            self.__reset_window_state()

    def send_end_packet(self):
        ''' Send an end packet, including rate limiting and printing. '''
        self.__send_packet_inner(EndPacket(
            sequence_num=self.__dispense_sequence_num(),
        ))

    def print_stats(self):
        percent = (
            float(self.num_retransmissions)
            / float(self.num_total_transmissions)
            * 100
        )
        print(f"Observed packet loss rate = %{'{:.2f}'.format(percent)}")


def run_sender(args):
    ''' Run the sender via the `args` object as returned from `parse_cli_args`.
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
        packet.inner.packet_type == PacketType.REQUEST
    ), f"sender received non-request packet: {repr(packet)}"
    request = packet

    print(request)

    # begin sending response packets
    sender = PacketSeqSender(
        socket,
        rate_limiter,
        args.net_hostname,
        args.net_port,
        request.src_ip_address,
        args.requester_port,
        request.inner.window_size,
        args.timeout_ms / 1000,
        PriorityLevel(args.priority),
    )

    # open the file and send its content chunk-by-chunk
    with open(request.inner.file_name, 'rb') as f:
        more_chunks = True
        while more_chunks:
            chunk = f.read(args.chunk_len)
            if chunk:
                sender.send_data_packet(chunk)
            else:
                sender.finalize_window()
                sender.send_end_packet()
                more_chunks = False

    # print stats
    sender.print_stats()

if __name__ == '__main__':
    run_sender(parse_cli_args())
