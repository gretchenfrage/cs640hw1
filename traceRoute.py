import socket
import argparse
from common import *
from socket import socket as create_socket, AF_INET, SOCK_DGRAM

import time


def main():
    parser = argparse.ArgumentParser(description='Route tracer utility')
    parser.add_argument('-a', dest='port', type=int, required=True, help='Port to listen on')
    parser.add_argument('-b', dest='src_host', type=str, required=True, help='Source hostname')
    parser.add_argument('-c', dest='src_port', type=int, required=True, help='Source port')
    parser.add_argument('-d', dest='dest_host', type=str, required=True, help='Destination hostname')
    parser.add_argument('-e', dest='dest_port', type=int, required=True, help='Destination port')
    parser.add_argument('-f', dest='debug', type=int, default=0, help='Debug level')

    args = parser.parse_args()

    ttl = 0
    sock = create_socket(AF_INET, SOCK_DGRAM)
    sock.bind(("0.0.0.0", args.port))

    # Get the hostname
    routeTrace_hostname = socket.gethostname()

    # Get the IP address
    routeTrace_ip_address = socket.gethostbyname(routeTrace_hostname)
    routeTrace_port = args.port

    
    while True:

        #doubt : NEED TO CREATE A PACKET HERE
        # Create the routetrace packet
        packet = RouteTracePacket(type='T', TTL=ttl, src_ip_address=routeTrace_ip_address, src_port=routeTrace_port, 
                          dest_ip_address=args.dest_host, dest_port=args.dest_port)
        
        binary = encode_packet(packet)
        sock.sendto(binary,(args.src_host, args.src_port))

        #TODO: debugging
        if args.debug==1:
            print(f'TTL={packet.TTL} src address : {routeTrace_ip_address}:{routeTrace_port}'
                  f'dst={args.dest_host}:{args.dest_port}')
    

        # Wait for a response
        binary, remote_addr = socket.recvfrom(6000)
        packet = decode_packet(binary)


        #doubt: does it have to be src_ip_address only can we have different packet for this return output.
        response_ip_address = packet.src_ip_address
        response_ip_port = packet.src_port

        #TODO: debugging
        if args.debug==1:
            print(f'TTL={packet.TTL} responded packet address : {response_ip_address}+:{response_ip_port}'
                  f'dst={packet.dest_ip_address}:{packet.dest_port}')

        if(response_ip_address == args.dest_host and response_ip_port == args.dest_port):
            break

        ttl = ttl+1

        time.sleep(0.1)
            
        

if __name__ == '__main__':
    main()
