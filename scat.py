#!/usr/bin/env python3
# coding: utf8

__version__ = "0.9"

import iodevices
import writers

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
    pysearchre = re.compile('.py$', re.IGNORECASE)
    pluginfiles = filter(pysearchre.search,
                           os.listdir(os.path.join(os.path.dirname(__file__),
                                                 'parsers')))
    form_module = lambda fp: '.' + os.path.splitext(fp)[0]
    parsers_dir = map(form_module, pluginfiles)
    # import parent module / namespace
    importlib.import_module('parsers')
    parsers = {}
    for p in parsers_dir:
        if not p.startswith('.__') and p.endswith('parser'):
            m = importlib.import_module(p, package="parsers")
            parsers[m.shortname()] = m.__entry__

    parsers_desc = ', '.join(parsers.keys())

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

    if 'qc' in parsers.keys():
        qc_group = parser.add_argument_group('Qualcomm specific settings')
        qc_group.add_argument('--qmdl', help='Store log as QMDL file (Qualcomm only)')

    if 'sec' in parsers.keys():
        sec_group = parser.add_argument_group('Samsung specific settings')
        sec_group.add_argument('-m', '--model', help='Device model for analyzing diagnostic messages', type=str)

    ip_group = parser.add_argument_group('GSMTAP IP settings')
    ip_group.add_argument('-P', '--port', help='Change UDP port to emit GSMTAP packets', type=int, default=4729)
    ip_group.add_argument('--port-up', help='Change UDP port to emit user plane packets', type=int, default=47290)
    ip_group.add_argument('-H', '--hostname', help='Change host name/IP to emit GSMTAP packets', type=str, default='127.0.0.1')
    ip_group.add_argument('--port-sim2', help='Change UDP port to emit GSMTAP packets for SIM 2', type=int, default=4729)
    ip_group.add_argument('--port-up-sim2', help='Change UDP port to emit user plane packets for SIM 2', type=int, default=47290)
    ip_group.add_argument('--hostname-sim2', help='Change host name/IP to emit GSMTAP packets for SIM 2', type=str, default='127.0.0.2')

    ip_group.add_argument('-F', '--pcap-file', help='Write GSMTAP packets directly to specified PCAP file')
    ip_group.add_argument('--pcap-file-up', help='Write user plane packets directly to specified PCAP file')
    ip_group.add_argument('--pcap-file-sim2', help='Write GSMTAP packets directly to specified PCAP file for SIM 2')
    ip_group.add_argument('--pcap-file-up-sim2', help='Write user plane packets directly to specified PCAP file for SIM 2')

    args = parser.parse_args()

    GSMTAP_IP_SIM1 = args.hostname
    GSMTAP_PORT_SIM1 = args.port
    IP_OVER_UDP_PORT_SIM1 = args.port_up

    GSMTAP_IP_SIM2 = args.hostname_sim2
    GSMTAP_PORT_SIM2 = args.port_sim2
    IP_OVER_UDP_PORT_SIM2 = args.port_up_sim2

    if not args.type in parsers.keys():
        print('Error: invalid baseband type specified. Available modules: %s' % parsers_desc)
        sys.exit(0)

    # Device preparation
    handler = None
    if args.serial:
        handler = iodevices.SerialIO(args.serial)
    elif args.usb:
        handler = iodevices.USBIO()
        if args.address:
            usb_bus, usb_device = args.address.split(':')
            usb_bus = int(usb_bus, base=10)
            usb_device = int(usb_device, base=10)
            handler.probe_device_by_vid_pid(usb_bus, usb_device)
        elif args.vendor == None:
            handler.guess_device()
        else:
            handler.probe_device_by_vid_pid(args.vendor, args.product)

        if args.config > 0:
            handler.set_configuration(config)
        print(dev.get_active_configuration())
        handler.claim_interface(args.interface)
    elif args.dump:
        handler = iodevices.FileIO(args.dump)
    else:
        print('Error: no device specified.')
        sys.exit(0)

    # Writer preparation
    if args.pcap_file == None:
        writer_cpup_sim1 = writers.SocketWriter(GSMTAP_IP_SIM1, GSMTAP_PORT_SIM1, GSMTAP_IP_SIM1, IP_OVER_UDP_PORT_SIM1)
        writer_cpup_sim2 = writers.SocketWriter(GSMTAP_IP_SIM2, GSMTAP_PORT_SIM2, GSMTAP_IP_SIM2, IP_OVER_UDP_PORT_SIM2)
    else:
        writer_cpup_sim1 = writers.PcapWriter(args.pcap_file, GSMTAP_PORT_SIM1, IP_OVER_UDP_PORT_SIM1)
        writer_cpup_sim2 = writers.PcapWriter(args.pcap_file_sim2, GSMTAP_PORT_SIM2, IP_OVER_UDP_PORT_SIM2)

    current_parser = parsers[args.type]()
    current_parser.setHandler(handler)
    current_parser.setWriter(writer_cpup_sim1, writer_cpup_sim2)

    if args.debug:
        logger.setLevel(logging.DEBUG)
        current_parser.setParameter({'log_level': logging.DEBUG})
    else:
        logger.setLevel(logging.INFO)
        current_parser.setParameter({'log_level': logging.INFO})
    ch = logging.StreamHandler(stream = sys.stdout)
    f = logging.Formatter('%(asctime)s %(name)s (%(funcName)s) %(levelname)s: %(message)s')
    ch.setFormatter(f)
    logger.addHandler(ch)

    if args.type == 'sec':
        current_parser.setParameter({'model': args.model})

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
