#!/usr/bin/env python3
# coding: utf8

__version__ = "0.9"

import iodevices
import writers
import parsers

import os, sys, re, importlib
import argparse
import signal
import struct
import util
import faulthandler
import logging

current_parser = None
logger = logging.getLogger('scat')

if os.name != 'nt':
    faulthandler.register(signal.SIGUSR1)

def sigint_handler(signal, frame):
    global current_parser 
    current_parser.stop_diag()
    sys.exit(0)

def hexint(string):
    if string[0:2] == '0x' or string[0:2] == '0X':
        return int(string[2:], 16)
    else:
        return int(string)

if __name__ == '__main__':
    # Load parser modules
    parser_dict = {}
    for parser_module in dir(parsers):
        if parser_module.startswith('__'):
            continue
        if type(getattr(parsers, parser_module)) == type:
            c = getattr(parsers, parser_module)()
            parser_dict[c.shortname] = c

    parsers_desc = ', '.join(parser_dict.keys())

    parser = argparse.ArgumentParser(description='Reads diagnostic messages from smartphone baseband.')
    parser.add_argument('-D', '--debug', help='Print debug information, mostly hexdumps.', action='store_true')
    parser.add_argument('-t', '--type', help='Baseband type to be parsed.\nAvailable types: %s' % parsers_desc, required=True)

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-s', '--serial', help='Use serial diagnostic port')
    input_group.add_argument('-u', '--usb', action='store_true', help='Use USB diagnostics port')
    input_group.add_argument('-d', '--dump', help='Read from baseband dump (QMDL)', nargs='*')

    usb_group = parser.add_argument_group('USB device settings')
    usb_group.add_argument('-v', '--vendor', help='Specify USB vendor ID', type=hexint)
    usb_group.add_argument('-p', '--product', help='Specify USB product ID', type=hexint)
    usb_group.add_argument('-a', '--address', help='Specify USB device address(bus:address)', type=str)
    usb_group.add_argument('-c', '--config', help='Specify USB configuration number for DM port', type=int, default=-1)
    usb_group.add_argument('-i', '--interface', help='Specify USB interface number for DM port', type=int, default=2)

    if 'qc' in parser_dict.keys():
        qc_group = parser.add_argument_group('Qualcomm specific settings')
        qc_group.add_argument('--qmdl', help='Store log as QMDL file (Qualcomm only)')
        qc_group.add_argument('--qsr-hash', help='Specify QSR message hash file (usually QSRMessageHash.db), implies --msgs', type=str)
        qc_group.add_argument('--qsr4-hash', help='Specify QSR4 message hash file (need to obtain from the device firmware), implies --msgs', type=str)
        qc_group.add_argument('--events', action='store_true', help='Decode Events as GSMTAP logging')
        qc_group.add_argument('--msgs', action='store_true', help='Decode Extended Message Reports and QSR Message Reports as GSMTAP logging')

    if 'sec' in parser_dict.keys():
        sec_group = parser.add_argument_group('Samsung specific settings')
        sec_group.add_argument('-m', '--model', help='Device model for analyzing diagnostic messages', type=str)

    ip_group = parser.add_argument_group('GSMTAP IP settings')
    ip_group.add_argument('-P', '--port', help='Change UDP port to emit GSMTAP packets', type=int, default=4729)
    ip_group.add_argument('--port-up', help='Change UDP port to emit user plane packets', type=int, default=47290)
    ip_group.add_argument('-H', '--hostname', help='Change base host name/IP to emit GSMTAP packets. For dual SIM devices the subsequent IP address will be used.', type=str, default='127.0.0.1')

    ip_group.add_argument('-F', '--pcap-file', help='Write GSMTAP packets directly to specified PCAP file')

    args = parser.parse_args()

    GSMTAP_IP = args.hostname
    GSMTAP_PORT = args.port
    IP_OVER_UDP_PORT = args.port_up

    if not args.type in parser_dict.keys():
        print('Error: invalid baseband type specified. Available modules: %s' % parsers_desc)
        sys.exit(0)

    # Device preparation
    io_device = None
    if args.serial:
        io_device = iodevices.SerialIO(args.serial)
    elif args.usb:
        io_device = iodevices.USBIO()
        if args.address:
            usb_bus, usb_device = args.address.split(':')
            usb_bus = int(usb_bus, base=10)
            usb_device = int(usb_device, base=10)
            io_device.probe_device_by_bus_dev(usb_bus, usb_device)
        elif args.vendor == None:
            io_device.guess_device()
        else:
            io_device.probe_device_by_vid_pid(args.vendor, args.product)

        if args.config > 0:
            io_device.set_configuration(config)
        io_device.claim_interface(args.interface)
    elif args.dump:
        io_device = iodevices.FileIO(args.dump)
    else:
        print('Error: no device specified.')
        sys.exit(0)

    # Writer preparation
    if args.pcap_file == None:
        writer = writers.SocketWriter(GSMTAP_IP, GSMTAP_PORT, IP_OVER_UDP_PORT)
    else:
        writer = writers.PcapWriter(args.pcap_file, GSMTAP_PORT, IP_OVER_UDP_PORT)

    current_parser = parser_dict[args.type]
    current_parser.set_io_device(io_device)
    current_parser.set_writer(writer)

    if args.debug:
        logger.setLevel(logging.DEBUG)
        current_parser.set_parameter({'log_level': logging.DEBUG})
    else:
        logger.setLevel(logging.INFO)
        current_parser.set_parameter({'log_level': logging.INFO})
    ch = logging.StreamHandler(stream = sys.stdout)
    f = logging.Formatter('%(asctime)s %(name)s (%(funcName)s) %(levelname)s: %(message)s')
    ch.setFormatter(f)
    logger.addHandler(ch)

    if args.type == 'qc':
        current_parser.set_parameter({
            'qsr-hash': args.qsr_hash,
            'qsr4-hash': args.qsr4_hash,
            'events': args.events,
            'msgs': args.msgs})
    elif args.type == 'sec':
        current_parser.set_parameter({'model': args.model})

    # Run process
    if args.serial or args.usb:
        current_parser.stop_diag()
        current_parser.init_diag()
        current_parser.prepare_diag()

        signal.signal(signal.SIGINT, sigint_handler)

        if not (args.qmdl == None) and args.type == 'qc':
            current_parser.run_diag(RawWriter(args.qmdl))
        else:
            current_parser.run_diag()

        current_parser.stop_diag()
    elif args.dump:
        current_parser.read_dump()
    else:
        assert('Invalid input handler?')
        sys.exit(0)
