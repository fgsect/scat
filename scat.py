#!/usr/bin/python3
# coding: utf8

__version__ = "0.9"

import os, sys, re, importlib
import argparse
import usb
import socket
import signal
import serial
import struct
import util
import datetime
import gzip, bz2

GSMTAP_IP = "127.0.0.1"
GSMTAP_PORT = 4729
IP_OVER_UDP_PORT = 47290

current_parser = None

ip_id = 10

eth_hdr = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00'

# Device Handler
class SerialHandler:
    def __init__(self, port_name):
        self.port = serial.Serial(port_name, baudrate=115200, timeout=0.1, rtscts=True, dsrdtr=True)

    def __enter__(self):
        return self

    def read(self, read_size):
        buf = b''
        buf = self.port.read(read_size)
        buf = bytes(buf)
        return buf

    def write(self, write_buf):
        self.port.write(write_buf)

    def __exit__(self, exc_type, exc_value, traceback):
        self.port.close()

class USBHandler:
    def __init__(self, usb_dev, usb_iface):
        self.usb_dev = usb_dev
        self.usb_cfg = self.usb_dev.get_active_configuration()
        self.intf = self.usb_cfg[(usb_iface, 0)]
        self.w_handle = usb.util.find_descriptor(self.intf, custom_match =
                lambda e: usb.util.endpoint_direction(e.bEndpointAddress) ==
                usb.util.ENDPOINT_OUT)
        self.r_handle = usb.util.find_descriptor(self.intf, custom_match =
                lambda e: usb.util.endpoint_direction(e.bEndpointAddress) ==
                usb.util.ENDPOINT_IN)

    def __enter__(self):
        return self

    def read(self, read_size):
        buf = b''
        try:
            buf = self.r_handle.read(read_size)
            buf = bytes(buf)
        except usb.core.USBError:
            return b''
        return buf

    def write(self, write_buf):
        self.w_handle.write(write_buf)

    def __exit__(self, exc_type, exc_value, traceback):
        usb.util.dispose_resources(self.usb_dev)

class FileHandler:
    def _open_file(self, fname):
        if self.f:
            self.f.close()

        if fname.find('.gz') > 0:
            self.f = gzip.open(fname, 'rb')
        elif fname.find('.bz2') > 0:
            self.f = bz2.open(fname, 'rb')
        else:
            self.f = open(fname, 'rb')

    def __init__(self, fnames):
        self.fnames = fnames[:]
        self.fnames.reverse()
        self.fname = ''
        self.file_available = True
        self.f = None

        self.open_next_file()

    def read(self, read_size):
        buf = b''
        try:
            buf = self.f.read(read_size)
            buf = bytes(buf)
        except:
            return b''
        return buf

    def open_next_file(self):
        try:
            self.fname = self.fnames.pop()
        except IndexError:
            self.file_available = False
            return
        self._open_file(self.fname)

    def write(self, write_buf):
        pass
        
    def __exit__(self, exc_type, exc_value, traceback):
        if self.f:
            self.f.close()

# PCAP Writer
class SocketWriter:
    def __init__(self, ip_cp, port_cp, ip_up, port_up):
        self.ip_cp = ip_cp
        self.port_cp = port_cp
        self.sock_cp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock_cp_recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.ip_up = ip_up
        self.port_up = port_up
        self.sock_up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock_up_recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def __enter__(self):
        return self

    def write_cp(self, sock_content, ts=None):
        self.sock_cp.sendto(sock_content, (self.ip_cp, self.port_cp))

    def write_up(self, sock_content, ts=None):
        self.sock_up.sendto(sock_content, (self.ip_up, self.port_up))

    def __exit__(self, exc_type, exc_value, traceback):
        self.sock_cp_recv.close()
        self.sock_up_recv.close()

class PcapWriter:
    def __init__(self, fname, port_cp = 4729, port_up = 47290):
        self.port_cp = port_cp
        self.port_up = port_up
        self.ip_id = 0
        self.pcap_file = open(fname, 'wb')
        pcap_global_hdr = struct.pack('<LHHLLLL',
                0xa1b2c3d4,
                2,
                4,
                0,
                0,
                0xffff,
                1,
                )
        self.pcap_file.write(pcap_global_hdr)

    def __enter__(self):
        return self

    def write_pkt(self, sock_content, port, ts=datetime.datetime.now()):
        pcap_hdr = struct.pack('<LLLL',
                int(ts.timestamp()),
                ts.microsecond,
                len(sock_content) + 8 + 20 + 14,
                len(sock_content) + 8 + 20 + 14,
                )

        ip_hdr = struct.pack('!BBHHBBBBHLL',
                0x45,                        # version, IHL, dsf
                0x00,
                len(sock_content) + 8 + 20,  # length
                self.ip_id,                  # id
                0x40,                        # flags/fragment offset
                0x00,
                0x40,                        # TTL
                0x11,                        # proto = udp
                0xffff,                      # header checksum
                0x7f000001,                  # src address
                0x7f000001,                  # dest address
                )
        udp_hdr = struct.pack('!HHHH',
                13337,                 # source port
                port,                  # destination port
                len(sock_content) + 8, # length
                0xffff,                # checksum
                )

        self.pcap_file.write(pcap_hdr + eth_hdr + ip_hdr + udp_hdr + sock_content)
        self.ip_id += 1
        if self.ip_id > 65535:
            self.ip_id = 0

    def write_cp(self, sock_content, ts=datetime.datetime.now()):
        self.write_pkt(sock_content, self.port_cp, ts)

    def write_up(self, sock_content, ts=datetime.datetime.now()):
        self.write_pkt(sock_content, self.port_up, ts)

    def __exit__(self, exc_type, exc_value, traceback):
        self.pcap_file.close()

class RawWriter:
    def __init__(self, fname, header=b'', trailer=b''):
        self.raw_file = open(fname, 'wb')
        self.raw_file.write(header)
        self.trailer = trailer

    def __enter__(self):
        return self

    def write_cp(self, sock_content, ts=datetime.datetime.now()):
        self.raw_file.write(sock_content)

    def write_up(self, sock_content, ts=datetime.datetime.now()):
        self.raw_file.write(sock_content)

    def __exit__(self, exc_type, exc_value, traceback):
        self.raw_file.write(self.trailer)
        self.raw_file.close()

class NullWriter:
    def write_cp(self, sock_content, ts=None):
        return

    def write_up(self, sock_content, ts=None):
        return

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
                                                 'parser')))
    form_module = lambda fp: '.' + os.path.splitext(fp)[0]
    parsers_dir = map(form_module, pluginfiles)
    # import parent module / namespace
    importlib.import_module('parser')
    parsers = {}
    for p in parsers_dir:
        if not p.startswith('.__') and p.endswith('parser'):
            m = importlib.import_module(p, package="parser")
            parsers[m.shortname()] = m.__entry__

    parsers_desc = ', '.join(parsers.keys())

    parser = argparse.ArgumentParser(description='Reads diagnostic messages from smartphone baseband.')
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
        handler = SerialHandler(args.serial)
    elif args.usb:
        # 0x0408: Samsung
        # 0x1004: LG
        # 0x2931: Jolla

        if args.address:
            print('Trying USB device at address %s' % (args.address))
            usb_bus, usb_device = args.address.split(':')
            usb_bus = int(usb_bus, base=10)
            usb_device = int(usb_device, base=10)

            dev = usb.core.find(bus=usb_bus, address=usb_device)
            if dev is None:
                raise ValueError('Device not found')
        elif args.vendor == None:
            dev = usb.core.find(idVendor=0x1004)
            if dev is None:
                dev = usb.core.find(idVendor=0x2931)
                if dev is None: 
                    dev = usb.core.find(idVendor=0x04e8)
                    if dev is None:
                        raise ValueError('Device not found')
        else:
            if args.product == None:
                dev = usb.core.find(idVendor=args.vendor)
            else:
                dev = usb.core.find(idVendor=args.vendor, idProduct=args.product)
            if dev is None:
                raise ValueError('Device not found')

        if args.config > 0:
            dev.set_configuration(args.config)
        print(dev.get_active_configuration())
        # Nexus 5: Interface #2 is DIAG
        # GS6: Interface #4
        handler = USBHandler(dev, args.interface)
    elif args.dump:
        handler = FileHandler(args.dump)
    else:
        print('Error: no input method specified.')
        sys.exit(0)

    # Writer preparation
    if args.pcap_file == None:
        writer_cpup_sim1 = SocketWriter(GSMTAP_IP_SIM1, GSMTAP_PORT_SIM1, GSMTAP_IP_SIM1, IP_OVER_UDP_PORT_SIM1)
        writer_cpup_sim2 = SocketWriter(GSMTAP_IP_SIM2, GSMTAP_PORT_SIM2, GSMTAP_IP_SIM2, IP_OVER_UDP_PORT_SIM2)
    else:
        writer_cpup_sim1 = PcapWriter(args.pcap_file, GSMTAP_PORT_SIM1, IP_OVER_UDP_PORT_SIM1)
        writer_cpup_sim2 = PcapWriter(args.pcap_file_sim2, GSMTAP_PORT_SIM2, IP_OVER_UDP_PORT_SIM2)

    current_parser = parsers[args.type]()
    current_parser.setHandler(handler)
    current_parser.setWriter(writer_cpup_sim1, writer_cpup_sim2)

    if args.type == 'sec':
        current_parser.setParameter({'model': args.model})

    # Run process
    if args.serial or args.usb:
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
