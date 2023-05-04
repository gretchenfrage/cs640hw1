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

    args.src_host = resolve_ip(args.src_host)
    args.dest_host = resolve_ip(args.dest_host)

    ttl = 0
    sock = create_socket(AF_INET, SOCK_DGRAM)
    sock.bind(("0.0.0.0", args.port))

    # Get the hostname
    routeTrace_hostname = socket.gethostname()

    # Get the IP address
    routeTrace_ip_address = socket.gethostbyname(routeTrace_hostname)
    routeTrace_port = args.port
    count = 0
    
    while True:

        #doubt : NEED TO CREATE A PACKET HERE
        # Create the routetrace packet
        packet = RouteTracePacket( TTL=ttl, src_ip_address=routeTrace_ip_address, src_port=routeTrace_port, 
                          dst_ip_address=args.dest_host, dst_port=args.dest_port)
        
        binary = encode_packet(packet)
        sock.sendto(binary,(args.src_host, args.src_port))


        if args.debug==1:
            print(f"[debug] send to {args.src_host}:{args.src_port}")
            print(f"        packet (TTL={packet.TTL}, src={packet.src_ip_address}:{packet.src_port}, dest={packet.dst_ip_address}:{packet.dst_port})")
            #print(f'[debug: send]    TTL={packet.TTL} src={args.src_host}:{args.src_port} '
            #      f'dest={args.dest_host}:{args.dest_port}')
    

        # Wait for a response
        binary, remote_addr = sock.recvfrom(6000)
        packet = decode_packet(binary)

        if args.debug==1:
            print(f"[debug] receive from {remote_addr[0]}:{remote_addr[1]}")
            print(f"        packet (TTL={packet.TTL}, src={packet.src_ip_address}:{packet.src_port}, dest={packet.dst_ip_address}:{packet.dst_port})")
            #print(f'[debug: receive] TTL={packet.TTL} src={args.src_host}:{args.src_port} '
            #      f'dest={args.dest_host}:{args.dest_port}')


        #doubt: does it have to be src_ip_address only can we have different packet for this return output.
        response_ip_address = packet.src_ip_address
        response_ip_port = packet.src_port

        # #TODO: debugging
        # if args.debug==1:
        if(count == 0):
            print(f'Hop# IP Port' )
        count = count+1
        print(f'{count} {response_ip_address} {response_ip_port}' )
        # print(f'TTL={packet.TTL} responded packet address : {response_ip_address}:{response_ip_port} '
        #           f'traceroute={packet.dst_ip_address}:{packet.dst_port}')

        if(response_ip_address == args.dest_host and response_ip_port == args.dest_port):
            break

        ttl = ttl+1

        time.sleep(0.1)
            
        

if __name__ == '__main__':
    main()
