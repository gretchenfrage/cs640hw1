
from enum import Enum
from collections import namedtuple
from ipaddress import IPv4Address, AddressValueError
from socket import gethostbyname, gethostname
import struct


# ==== "should drop" ====

'''
This is just a thing for debugging reliable transfer before the network
emulator is finished.
'''

ENABLE_SHOULD_DROP_DEBUG_THING = False
should_drop_counter = 0

def should_drop_debug_thing(packet):
    global should_drop_counter

    if not ENABLE_SHOULD_DROP_DEBUG_THING:
        return False
    if packet.inner.packet_type not in [PacketType.DATA, PacketType.ACK]:
        return False
    should_drop_counter += 1
    should_drop = should_drop_counter % 2 == 0
    if should_drop:
        print(f"debug dropping {repr(packet.inner)}\n")
    return should_drop


# ==== additional debug stuff ====

DEBUG_PRINT = False

def debug_print(s):
    if DEBUG_PRINT:
        print(s)


# ==== network utilities ====

def get_host_ip():
    """ Attempt to get the public IP address of the local host.

    https://stackoverflow.com/a/166520/4957011
    """
    return gethostbyname(gethostname())

def resolve_ip(resolvable):
    """ Convert a host name or IP address into an IP address.
    """
    try:
        # case that it is already an IP address
        IPv4Address(resolvable)
        return resolvable
    except AddressValueError:
        # otherwise assume is a host name
        return gethostbyname(resolvable)


# ==== packets ====

'''
What's in a packet?


Outer packet (added in HW2)
---------------------------

#### Priority

"
    Valid values for priority levels are:

    0x01 - highest priority
    0x02 - medium priority
    0x03 - lowest priority
"

"All the packets sent by the requester should have priority 1."

"The priority of the END packet is the same as the other packets in the flow."

#### Source IP address

32-bit IP address

#### Source port

16 bits

#### Destination IP address

32-bit IP address

#### Destination port

16 bits

#### (Outer) length

"The length field of the outer packet is set to the total size of the inner
packet, i.e. inner packet header size + inner packet payload size."


Inner packet
------------

#### Packet type

All packets have a packet type. One of Request, Data, or End.

Addendum (HW2): Ack packet type.

#### Sequence number

"For Request packets, the sequence field is set to 0." It is thus implied
that both Data and End packets have settable sequence numbers.

Addendum (HW2): "For the ack packet ... the sequence field will contain the
sequence number of the packet that is being acknowledged."

#### (Inner) length

OBSOLETED: "In case the packet type is a request, the packet length should be
           set to 0." However, it also doesn't seem like an End packet would
           have any content. So, I guess really only a Data packet can have a
           non-zero length.

Addendum (HW2): "The inner length field of the request packet will be filled
with this window size so that the sender can extract and use this value for
sending."

"The length parameter will always be less than 5KB." So, that's a possibly
convenient assumption we're allowed to make.

#### Payload

In Data packets, it's the chunk of Data. In this case it determines the length
field.

In Request packets, it's the name of the file it's requesting, _however_, in
such cases the length field is still set to 0.

---

Additional things to keep in mind:

- the sender has packet rate limiting
- the sender must print some information every time it sends a packet
'''


# ==== packet data type definitions ====
# 
#     link packet ----[is one of]----\
#                                    |
#     /------------------------------/
#     |
#     |---> outer packet ----[contains]----\
#     |                                    |
#     |---> heartbeat packet               |
#     |                                    |
#     |---> link state packet              |
#     |                                    |
#     |---> routetrace packet              |
#                                          |
#     /------------------------------------/
#     |
#     \---> inner packet ----[is one of]---\
#                                          |
#     /------------------------------------/
#     |
#     |---> request packet
#     |
#     |---> data packet
#     |
#     |---> end packet
#     |
#     |---> ack packet
# 

def packet_data_type_factory(enum, suffix):
    def packet_data_type(name, fields):
        assert (
            name.endswith(suffix)
        ), f"{repr(name)} expected to end with suffix {repr(suffix)}"
        packet_type = enum[name.removesuffix(suffix).upper()]

        inner_constructor = namedtuple(name, ['packet_type'] + fields)
        def outer_constructor(**kwargs):
            return inner_constructor(
                packet_type=packet_type,
                **kwargs,
            )

        return outer_constructor
    return packet_data_type


class LinkPacketType(Enum):
    OUTER = ord('O')
    HEARTBEAT = ord('H')
    LINKSTATE = ord('L')
    ROUTETRACE = ord('R')

link_packet_data_type = packet_data_type_factory(LinkPacketType, 'Packet')

class PriorityLevel(Enum):
    ''' Valid priority level as described by assignment.

    The values are the byte values as they exist on the wire.
    '''
    Highest = 1
    Medium = 2
    Lowest = 3

''' Representation of an outer packet, a type of link packet.
'''
OuterPacket = link_packet_data_type('OuterPacket', [
    'priority',
    'src_ip_address',
    'src_port',
    'dst_ip_address',
    'dst_port',
    'inner',
])

''' Representation of a heartbeat packet (aka "HelloMessage"), a type of link
packet.
'''
HeartbeatPacket = link_packet_data_type('HeartbeatPacket', [])

''' Representation of a link state packet (aka "LinkStateMessage"), a type of
link packet.
'''
LinkStatePacket = link_packet_data_type('LinkStatePacket', [
    'creator_ip_address',
    'creator_port',
    'seq_no',    # integer
    'expires',   # float unix timestamp in seconds
    'neighbors', # list of LinkInfo
])

''' Neighbor link information within a LinkStatePacket. '''
LinkInfo = namedtuple('NeighborLinkInfo', [
    'ip_address',
    'port',
    'cost', # float
])

''' Representation of a route trace packet, a type of link packet. '''
RouteTracePacket = link_packet_data_type('RouteTracePacket', [
    # TODO routetrace logic
])

class PacketType(Enum):
    ''' Type of (inner) packet as described by assignment.

    The values are the packet type discriminant as it exists on the wire.
    '''
    REQUEST = ord('R')
    DATA = ord('D')
    END = ord('E')
    ACK = ord('A')

inner_packet_data_type = packet_data_type_factory(PacketType, 'Packet')

''' Representation of a request packet. '''
RequestPacket = inner_packet_data_type('RequestPacket', ['file_name', 'window_size'])

''' Representation of a data packet. '''
DataPacket = inner_packet_data_type('DataPacket', ['sequence_num', 'payload'])

''' Representation of an end packet. '''
EndPacket = inner_packet_data_type('EndPacket', ['sequence_num'])

''' Representation of an ack packet. '''
AckPacket = inner_packet_data_type('AckPacket', ['sequence_num'])


# ==== packet data type encoding/decoding ====

'''
Struct format string (as used in python's struct packing module) representing
the binary format of the outer non-payload part of the packets.

! makes it network order

Fields are:
- priority (8-bit unsigned int)
- src ip address (4 byte IPv4 address)
- src port (16-bit unsigned int)
- dst ip address (4 byte IPv4 address)
- dst port (16-bit unsigned int)
- (outer) length (32-bit unsigned int)

See: https://docs.python.org/3/library/struct.html
'''
OUTER_HEADER_FORMAT = "!B4sH4sHI"

''' Number of bytes in an outer header. '''
OUTER_HEADER_SIZE = 17

'''
Struct format string (see above) representing the binary format of the inner
non-payload part of the packets.

Fields are:

- packet type (8-bit unsigned int)
- sequence number (32-bit unsigned int)
- inner length (32-bit unsigned int)
'''
INNER_HEADER_FORMAT = "!BII"

''' Number bytes in the part of the header that contributes to the outer
length.
'''
INNER_HEADER_SIZE = 9

''' Struct format string (see above) representing the non-variadic parts of the
binary format of a link state packet.

Fields are:
- creator ip address (4 byte IPv4 address)
- creator port (16-bit unsigned int)
- seq no (64-bit unsigned int)
- expires (64-bit float)
- number of neighbors (64-bit unsigned int)
'''
LINK_STATE_HEADER_FORMAT = "!4sHQdQ"

LINK_STATE_HEADER_SIZE = 30

''' Struct format string (see above) representing a neighbor link element in
the binary format of a link state packet.

Fields are:
- ip address (4 byte IPv4 address)
- port (16-bit unsigned int)
- cost (32-bit float)
'''
LINK_INFO_FORMAT = "!4sHf"

LINK_INFO_SIZE = 10


def encode_packet(packet):
    ''' Convert any link packet into bytes. '''
    if packet.packet_type == LinkPacketType.OUTER:
        buf = encode_outer_packet(packet)
    elif packet.packet_type == LinkPacketType.HEARTBEAT:
        buf = bytes()
    elif packet.packet_type == LinkPacketType.LINKSTATE:
        buf = encode_link_state_packet(packet)
    elif packet.packet_type == LinkPacketType.ROUTETRACE:
        # TODO routetrace logic
        raise Exception('unimplemented')
    else:
        raise Exception(f"unknown link packet type {repr(packet.packet_type)}")

    buf = bytes([packet.packet_type.value]) + buf
    return buf

def encode_outer_packet(packet):
    ''' Convert an OuterPacket into bytes, _not including the link packet type
    byte_. '''
    inner = encode_inner_packet(packet.inner)
    buf = bytearray(OUTER_HEADER_SIZE)
    header = (
        # priority
        packet.priority.value,
        # src ip address
        IPv4Address(packet.src_ip_address).packed,
        # src port
        packet.src_port,
        # dst ip address
        IPv4Address(packet.dst_ip_address).packed,
        # dst port
        packet.dst_port,
        # (outer) length
        len(inner),
    )
    struct.pack_into(OUTER_HEADER_FORMAT, buf, 0, *header)
    buf.extend(inner)
    return buf

def encode_link_state_packet(packet):
    ''' Convert a LinkStatePacket into bytes, _not including the link packet
    type byte_. '''
    
    # pack header
    buf = bytearray(LINK_STATE_HEADER_SIZE)
    header = (
        # creator ip address
        IPv4Address(packet.creator_ip_address).packed,
        # creator port
        packet.creator_port,
        # seq number
        packet.seq_no,
        # expires
        packet.expires,
        # number of neighbors
        len(packet.neighbors),
    )
    print(f"{repr(header)=}")
    struct.pack_into(LINK_STATE_HEADER_FORMAT, buf, 0, *header)

    # pack link info elements
    for link_info in packet.neighbors:

        link_info_buf = bytearray(LINK_INFO_SIZE)
        link_info_args = (
            # ip address
            IPv4Address(link_info.ip_address).packed,
            # port
            link_info.port,
            # cost
            link_info.cost,
        )
        struct.pack_into(LINK_INFO_FORMAT, link_info_buf, 0, *link_info_args)

        buf.extend(link_info_buf)

    return buf

def encode_inner_packet(packet):
    ''' Convert any inner packet type into bytes. '''

    # type-specific logic to get sequence_num, length, and payload values
    if packet.packet_type == PacketType.REQUEST:
        sequence_num = 0
        length = packet.window_size
        payload = packet.file_name.encode('utf-8')
    elif packet.packet_type == PacketType.DATA:
        sequence_num = packet.sequence_num
        length = len(packet.payload)
        payload = packet.payload
    elif packet.packet_type in [PacketType.END, PacketType.ACK]:
        sequence_num = packet.sequence_num
        length = 0
        payload = bytes()
    else:
        raise Exception(f"unknown packet type {repr(packet.packet_type)}")

    # pack
    buf = bytearray(INNER_HEADER_SIZE)
    header = (        
        # packet type
        packet.packet_type.value,
        # sequence number
        sequence_num,
        # (inner) length
        length,
    )
    struct.pack_into(INNER_HEADER_FORMAT, buf, 0, *header)
    buf.extend(payload)
    return buf

def decode_packet(binary):
    ''' Convert encoded bytes into some type of link packet.

    Isn't guaranteed to detect all malformed packets, but may do some debug
    checks.
    '''
    packet_type = LinkPacketType(binary[0])
    binary = binary[1:]

    if packet_type == LinkPacketType.OUTER:
        return decode_outer_packet(binary)
    elif packet_type == LinkPacketType.HEARTBEAT:
        assert (len(binary) == 0)
        return HeartbeatPacket()
    elif packet_type == LinkPacketType.LINKSTATE:
        return decode_link_state_packet(binary)
    elif packet_type == LinkPacketTpye.ROUTETRACE:
        # TODO routetrace logic
        raise Exception('unimplemented')
    else:
        raise Exception(f"unknown link packet type {repr(packet.packet_type)}")

def decode_outer_packet(binary):
    ''' Convert encoded bytes, _not including the link packet type byte_, into
    an OuterPacket.
    '''
    (
        priority,
        src_ip_address,
        src_port,
        dst_ip_address,
        dst_port,
        length,
    ) = struct.unpack(OUTER_HEADER_FORMAT, binary[:OUTER_HEADER_SIZE])
    inner = binary[OUTER_HEADER_SIZE:]
    assert (length == len(inner))
    return OuterPacket(
        priority=PriorityLevel(priority),
        src_ip_address=IPv4Address(src_ip_address).exploded,
        src_port=src_port,
        dst_ip_address=IPv4Address(dst_ip_address).exploded,
        dst_port=dst_port,
        inner=decode_inner_packet(inner),
    )

def decode_link_state_packet(binary):
    ''' Convert encoded bytes, _not including the link packet type byte_, into
    a LinkStatePacket.
    '''
    (
        creator_ip_address,
        creator_port,
        seq_no,
        expires,
        num_neighbors,
    ) = struct.unpack(LINK_STATE_HEADER_FORMAT, binary[:LINK_STATE_HEADER_SIZE])

    assert (len(binary) == LINK_STATE_HEADER_SIZE + LINK_INFO_SIZE * num_neighbors)

    neighbors = []
    for i in range(num_neighbors):
        offset = LINK_STATE_HEADER_SIZE + LINK_INFO_SIZE * i
        (
            link_ip_address,
            link_port,
            link_cost,
        ) = struct.unpack(LINK_INFO_FORMAT, binary[offset:offset + LINK_INFO_SIZE])
        neighbors.append(LinkInfo(
            ip_address=IPv4Address(link_ip_address).exploded,
            port=link_port,
            cost=link_cost,
        ))

    return LinkStatePacket(
        creator_ip_address=IPv4Address(creator_ip_address).exploded,
        creator_port=creator_port,
        seq_no=seq_no,
        expires=expires,
        neighbors=neighbors,
    )

def decode_inner_packet(binary):
    ''' Convert encoded bytes into the appropriate inner packet type.

    Isn't guarnateed to detect all malformed packets, but may do some debug
    checks.
    '''

    # unpack values
    (
        discriminant,
        sequence_num,
        length,
    ) = struct.unpack(INNER_HEADER_FORMAT, binary[:INNER_HEADER_SIZE])
    packet_type = PacketType(discriminant)
    payload = binary[INNER_HEADER_SIZE:]

    # type-specific logic to convert to python type
    if packet_type == PacketType.REQUEST:
        assert (sequence_num == 0), "malformed packet"
        return RequestPacket(file_name=payload.decode('utf-8'), window_size=length)
    elif packet_type == PacketType.DATA:
        assert (length == len(payload)), "malformed packet"
        return DataPacket(sequence_num=sequence_num, payload=payload)
    elif packet_type == PacketType.END:
        assert (length == len(payload)), "malformed packet"
        assert (len(payload) == 0), "malformed packet"
        return EndPacket(sequence_num=sequence_num)
    elif packet_type == PacketType.ACK:
        assert (length == len(payload)), "malformed packet"
        assert (len(payload) == 0), "malformed packet"
        return AckPacket(sequence_num=sequence_num)
    else:
        raise Exception(f"unknown packet type {repr(packet_type)}")


if __name__ == '__main__':
    # random demo of encoding and decoding you can run by running common.py
    # directly. maybe should eventually create proper testing modules.
    packet = OuterPacket(
        priority=PriorityLevel.Medium,
        src_ip_address='82.123.92.0',
        src_port=25565,
        dst_ip_address='127.0.0.1',
        dst_port=80,
        inner=DataPacket(
            sequence_num=7,
            payload=b"hello"
        )
    )
    print(f"packet = {repr(packet)}")
    encoded = encode_packet(packet)
    print(f"encoded = {repr(encoded)}")
    decoded = decode_packet(encoded)
    print(f"decoded = {repr(decoded)}")
    assert (packet == decoded)

    packet = OuterPacket(
        priority=PriorityLevel.Medium,
        src_ip_address='82.123.92.0',
        src_port=25565,
        dst_ip_address='127.0.0.1',
        dst_port=80,
        inner=AckPacket(sequence_num=4)
    )
    print(f"packet = {repr(packet)}")
    encoded = encode_packet(packet)
    print(f"encoded = {repr(encoded)}")
    decoded = decode_packet(encoded)
    print(f"decoded = {repr(decoded)}")
    assert (packet == decoded)

    packet = OuterPacket(
        priority=PriorityLevel.Medium,
        src_ip_address='82.123.92.0',
        src_port=25565,
        dst_ip_address='127.0.0.1',
        dst_port=80,
        inner=RequestPacket(file_name='foo.txt', window_size=70)
    )
    print(f"packet = {repr(packet)}")
    encoded = encode_packet(packet)
    print(f"encoded = {repr(encoded)}")
    decoded = decode_packet(encoded)
    print(f"decoded = {repr(decoded)}")
    assert (packet == decoded)

    packet = LinkStatePacket(
        creator_ip_address='84.24.0.122',
        creator_port=5621,
        seq_no=66638,
        expires=8923423423,
        neighbors=[
            LinkInfo(
                ip_address='7.7.7.7',
                port=4,
                cost=1.0,
            ),
            LinkInfo(
                ip_address='8.8.1.3',
                port=4,
                cost=1.0,
            ),
            LinkInfo(
                ip_address='7.7.4.7',
                port=50,
                cost=1.0,
            ),
        ]
    )
    print(f"packet = {repr(packet)}")
    encoded = encode_packet(packet)
    print(f"encoded = {repr(encoded)}")
    decoded = decode_packet(encoded)
    print(f"decoded = {repr(decoded)}")
    assert (packet == decoded)

    packet = HeartbeatPacket()
    print(f"packet = {repr(packet)}")
    encoded = encode_packet(packet)
    print(f"encoded = {repr(encoded)}")
    decoded = decode_packet(encoded)
    print(f"decoded = {repr(decoded)}")
    assert (packet == decoded)

