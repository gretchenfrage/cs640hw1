
from common import *


for original in [
    RequestPacket(file_name='foo.txt'),
    DataPacket(sequence_num=3, payload=b"hi"),
    EndPacket(sequence_num=4),
]:
    binary = encode_packet(original)
    print(repr(binary))
    decoded = decode_packet(binary)
    print(repr(decoded))
    assert (original == decoded), "round trip failed"
