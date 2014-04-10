#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""Send one packet to client and spoof the source IP address. """


import sys
import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from random import randint
from scapy.all import *


__author__ = 'Black September'
__date__ = '2014, April 9'
__version__ = '0.0.1'


def parse_args():
    """Command line options."""
    source_port = randint(49152, 65535)

    parser = argparse.ArgumentParser(description='Spoofs the source IP address of one TCP packet')

    dst = parser.add_argument_group('- Victim')
    dst.add_argument('-T', dest='target', help='Destination IP address.', required=True)
    dst.add_argument('-P', dest='dstport', help='Destination port', required=True,
                     type=int)

    src = parser.add_argument_group('- Attacker')
    src.add_argument('-S', dest='source', help='Spoofed IP address.', required=True)
    src.add_argument('-SP', dest='srcport', help='Source port (default: random)',
                     type=int, default=source_port)

    args = parser.parse_args()
    
    return args


def spoofed_packet(dst_ip, dst_port, src_ip, src_port):
    """Sends a spoofed TCP packet to the target. """
    p1 = IP(dst=dst_ip, src=src_ip)/TCP(dport=dst_port, sport=src_port, flags='S')
    send(p1)

    print('SYN sent to {0}:{1}'.format(dst_ip, dst_port))


def check_args(args):
    target = args.target
    dstport = args.dstport
    source = args.source
    srcport = args.srcport

    spoofed_packet(target, dstport, source, srcport)


def main():
    """Main function."""
    args = parse_args()
    check_args(args)


if __name__ == '__main__':
    main()
