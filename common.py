
from enum import Enum
from collections import namedtuple
import struct

'''
What's in a packet?

#### Packet type

All packets have a packet type. One of Request, Data, or End.

#### Sequence number

"For Request packets, the sequence field is set to 0." It is thus implied
that both Data and End packets have settable sequence numbers.

#### Length

"In case the packet type is a request, the packet length should be set to 0."
However, it also doesn't seem like an End packet would have any content. So,
I guess really only a Data packet can have a non-zero length.

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

class PacketType(Enum):
    ''' Type of packet as described by assignment.

    The values are the packet type discriminant as it exists on the wire.
    '''
    REQUEST = ord('R')
    DATA = ord('D')
    END = ord('E')

def packet_data_type(name, fields):
    ''' Create a packet data type.

    This creates a data type which functions generally like namedtuple, except
    that it also has a `packet_type` field which is automatically populated
    with the corresponding `PacketType` value upon construction.
    '''
    SUFFIX = "Packet"
    assert (
        name.endswith("Packet")
    ), f"{repr(name)} expected to end with suffix {repr(SUFFIX)}"
    packet_type = PacketType[name.removesuffix(SUFFIX).upper()]

    inner_constructor = namedtuple(name, ['packet_type'] + fields)
    def outer_constructor(**kwargs):
        return inner_constructor(
            packet_type=packet_type,
            **kwargs,
        )

    return outer_constructor

''' Representation of a request packet. '''
RequestPacket = packet_data_type('RequestPacket', ['file_name'])

''' Representation of a data packet. '''
DataPacket = packet_data_type('DataPacket', ['sequence_num', 'payload'])

''' Representation of an end packet. '''
EndPacket = packet_data_type('EndPacket', ['sequence_num'])


# ==== packet data type encoding/decoding ====

'''
Struct format string (as used in python's struct packing module) representing
the binary format of the non-payload part of our packets.

! makes it network order.

Fields are:
- packet type (8 bit unsigned int)
- sequence number (32-bit unsigned int)
- length (32-bit unsigned int)

See: https://docs.python.org/3/library/struct.html
'''
HEADER_FORMAT = "!BII"

''' Number of bytes in a header. '''
HEADER_SIZE = 9

def encode_packet(packet):
    ''' Convert any packet type into bytes. '''

    # type-specific logic to get sequence_num, length, and payload values
    if packet.packet_type == PacketType.REQUEST:
        sequence_num = 0
        length = 0
        payload = packet.file_name.encode('utf-8')
    elif packet.packet_type == PacketType.DATA:
        sequence_num = packet.sequence_num
        length = len(packet.payload)
        payload = packet.payload
    elif packet.packet_type == PacketType.END:
        sequence_num = packet.sequence_num
        length = 0
        payload = bytes()
    else:
        raise Exception(f"unknown packet type {repr(packet.packet_type)}")

    # pack
    buf = bytearray(HEADER_SIZE)
    header = (
        packet.packet_type.value,
        sequence_num,
        length,
    )
    struct.pack_into(HEADER_FORMAT, buf, 0, *header)
    buf.extend(payload)
    return buf

def decode_packet(binary):
    ''' Convert encoded bytes into the appropriate packet type.

    Isn't guarnateed to detect all malformed packets, but may do some debug
    checks.
    '''

    # unpack values
    (
        discriminant,
        sequence_num,
        length,
    ) = struct.unpack(HEADER_FORMAT, binary[:HEADER_SIZE])
    packet_type = PacketType(discriminant)
    payload = binary[HEADER_SIZE:]

    # type-specific logic to convert to python type
    if packet_type == PacketType.REQUEST:
        assert (sequence_num == 0), "malformed packet"
        assert (length == 0), "malformed packet"
        return RequestPacket(file_name=payload.decode('utf-8'))
    elif packet_type == PacketType.DATA:
        assert (length == len(payload)), "malformed packet"
        return DataPacket(sequence_num=sequence_num, payload=payload)
    elif packet_type == PacketType.END:
        assert (length == len(payload)), "malformed packet"
        assert (len(payload) == 0), "malformed packet"
        return EndPacket(sequence_num=sequence_num)
    else:
        raise Exception(f"unknown packet type {repr(packet_type)}")
