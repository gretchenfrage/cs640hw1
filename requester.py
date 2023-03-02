
from argparse import ArgumentParser
from socket import socket, AF_INET, SOCK_DGRAM

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
