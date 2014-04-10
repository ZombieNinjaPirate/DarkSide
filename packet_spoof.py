#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""
   Copyright (c) 2014, Are Hansen

   All rights reserved.
 
   Redistribution and use in source and binary forms, with or without modification, are
   permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice, this list
   of conditions and the following disclaimer.
 
   2. Redistributions in binary form must reproduce the above copyright notice, this
   list of conditions and the following disclaimer in the documentation and/or other
   materials provided with the distribution.
 
   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND AN
   EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
   OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
   SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
   INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
   TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
   BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
   STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
   THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""


"""Sends one packet to client and spoof the source IP address. """


__author__ = 'Are Hansen'
__date__ = '2014, April 9'
__version__ = '0.0.1'


import sys
import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from random import randint
from scapy.all import *


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
