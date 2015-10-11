#!/usr/bin/env python


"""
Copyright (c) 2015, Are Hansen

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


import argparse
import datetime
import nmap
import os
import re
import sys
import urllib2


__app__ = sys.argv[0].split('/')[-1].split('.')[-2]
__author__ = 'Are Hansen'
__date__ = '2015, June 2'
__version__ = '0.0.3'


def parse_args():
    """Command line options. """
    parser = argparse.ArgumentParser(
    description='{0} - v{1}, {2} - {3}'.format(__app__, __version__, __date__, __author__)
    )

    dst = parser.add_argument_group('- Target acquisition')
    trg = dst.add_mutually_exclusive_group(required=True)
    trg.add_argument(
                     '-U', 
                     dest='url', 
                     help='Search URL for IPv4 objects',
                     nargs=1 
                     )
    trg.add_argument(
                     '-F', 
                     dest='tfile', 
                     help='File containing one target per line',
                     type=argparse.FileType('r'),
                     nargs='?'
                     )

    scn = parser.add_argument_group('- Scan options')
    scn.add_argument(
                     '-p', 
                     dest='ports', 
                     help='TCP ports (Example: 22 80 443)',
                     required=True,
                     nargs=1 
                     )
    scn.add_argument(
                     '-T', 
                     dest='speed', 
                     help='Scan speed (default: 3)',
                     choices=['0', '1', '2', '3', '4', '5']
                     )

    ofo = parser.add_argument_group('- Offensive options')
    ofo.add_argument(
                     '-B', 
                     dest='brute', 
                     help='Brute force attack',
                     choices=['ftp', 'https', 'ssh']
                     )
    ofo.add_argument(
                     '-Bu', 
                     dest='buser', 
                     help='File containing one user name per line',
                     type=argparse.FileType('r'),
                     nargs='?'
                     )
    ofo.add_argument(
                     '-Bp', 
                     dest='bpass', 
                     help='File containing password per line',
                     type=argparse.FileType('r'),
                     nargs='?'
                     )

    args = parser.parse_args()    
    return args


def getTargets(gurl):
    """Requests a web page, extracts any in the format of an IPv4 address and returns
    those objects in the form of a list."""
    try:
        opener = urllib2.build_opener(urllib2.HTTPHandler)
        req = urllib2.Request(gurl)
        res = opener.open(req)
        page = str(res.readlines())
        ipv4 = re.findall( r'[0-9]+(?:\.[0-9]+){3}', page)
        return ipv4
    except urllib2.URLError, err:
         return err


def scan_ports(hostlist, portlist):
    """Do some dirty 'ol port scans by interfacing with Nmap. """
    print 'Scanning {0} TCP ports on {1} targets.'.format(len(hostlist), len(portlist))
    nm = nmap.PortScanner()
    
    for host in hostlist:
        start = datetime.datetime.now()
        nm.scan(host, portlist, arguments='-Pn -n')
        nm.command_line()
        nm.scaninfo()
        ended = datetime.datetime.now()

        for host in nm.all_hosts():
            print'----------------------------------------------------'
            print 'Scan started: \t{0}'.format(start)
            print 'Target: \t{0}'.format(host)

        try:
            proto = nm[host].all_protocols()[-1]
            lport = nm[host]['tcp'].keys()

            for port in sorted(lport):
                #
                # if port is SSH and offensive argument is used:
                #   begin bruteforce
                #   - show user name and password used
                #   - show only succesfull credentials
                #   - summarize number of user names and passwords
                #
                if 'open' in nm[host][proto][port]['state']:
                    print 'Open port: \t{0}/{1}'.format(proto, port)
                stime = ended - start
        except KeyError, notcp:
                print 'Open port: \tNO OPEN TCP PORTS'

        print 'Scan time: \t{0}'.format(stime)


def process_args(args):
    """Parse and check the arguments. """
    p1 ='22,199,2812,2999,3001,3306,4369,4440,5269,5282,5666,6010,6011,6556,7777'
    p2 = '7990,7991,7992,7993,7994,7995,7996,7997,7998,7999,8080,10000,10796'
    p3 = '49889,53059,57835,58711,60173,60278,60513,60783'
    port = '{0},{1},{2}'.format(p1, p2, p3)
    scan_ports(getTargets(args.url[0]), port)


def main():
    """The main brain... """
    args = parse_args()
    process_args(args)


if __name__ == '__main__':
    main()
