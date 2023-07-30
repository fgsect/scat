#!/usr/bin/env python3
# coding: utf8

import usb
import scat.util as util
import logging

class USBIO:
    def __init__(self):
        self.usb_dev = None
        self.block_until_data = True

    def __enter__(self):
        return self

    def read(self, read_size, decode_hdlc = False):
        buf = b''
        try:
            buf = self.r_handle.read(read_size)
            buf = bytes(buf)
        except usb.core.USBError:
            return b''
        if decode_hdlc:
            buf = util.unwrap(buf)
        return buf

    def write(self, write_buf, encode_hdlc = False):
        if encode_hdlc:
            write_buf = util.wrap(write_buf)
        self.w_handle.write(write_buf)

    def write_then_read_discard(self, write_buf, read_size = 0x1000, encode_hdlc = False):
        self.write(write_buf, encode_hdlc)
        self.read(read_size)

    def probe_device_by_vid_pid(self, vid, pid):
        print('Trying USB device with vid:pid {:#06x}:{:#06x}'.format(vid, pid))
        if pid is None:
            self.dev = usb.core.find(idVendor=vid)
        else:
            self.dev = usb.core.find(idVendor=vid, idProduct=pid)
        if self.dev is None:
            raise ValueError('Device not found')

    def probe_device_by_bus_dev(self, bus, dev):
        print('Trying USB device at address {:03d}:{:03d}'.format(bus, dev))
        self.dev = usb.core.find(bus=bus, address=dev)
        if self.dev is None:
            raise ValueError('Device not found')

    def guess_device(self):
        # 0x0408: Samsung
        # 0x1004: LG
        # 0x2931: Jolla
        vid_list = [0x1004, 0x04e8, 0x2931]
        self.dev = None

        for vid in vid_list:
            dev = usb.core.find(idVendor=vid)
            if dev is not None:
                self.dev = dev
                break

        if self.dev is None:
            raise ValueError('Device not found')

    def claim_interface(self, interface):
        # Nexus 5: Interface #2 is DIAG
        # GS6: Interface #4
        self.usb_cfg = self.dev.get_active_configuration()
        print(self.usb_cfg)
        self.intf = self.usb_cfg[(interface, 0)]
        self.w_handle = usb.util.find_descriptor(self.intf, custom_match =
                lambda e: usb.util.endpoint_direction(e.bEndpointAddress) ==
                usb.util.ENDPOINT_OUT)
        self.r_handle = usb.util.find_descriptor(self.intf, custom_match =
                lambda e: usb.util.endpoint_direction(e.bEndpointAddress) ==
                usb.util.ENDPOINT_IN)

    def set_configuration(self, config):
        self.dev.set_configuration(config)

    def __exit__(self, exc_type, exc_value, traceback):
        if self.usb_dev is not None:
            usb.util.dispose_resources(self.usb_dev)

    @staticmethod
    def list_usb_devices():
        # find all USB devices
        if usb.core.find() is not None:
            devs = usb.core.find(find_all=True)
            print('List of USB devices:')
            # loop through devices
            for dev in devs:
                manufacturer = ""
                product = ""
                try:
                    manufacturer = usb.util.get_string(dev, dev.iManufacturer)
                    product = usb.util.get_string(dev, dev.iProduct)
                except ValueError:
                    logger = logging.getLogger('scat.usbio')
                    logger.log(logging.WARNING, "Warning: Unable to get product name or manufacturer. "
                                                "Missing permissions? Try with sudo")

                print('Bus {:03d} Device {:03d}: ID {:04X}:{:04X}'.format(dev.bus, dev.address, dev.idVendor,
                                                                          dev.idProduct), manufacturer, product)
        else:
            print('No USB device found')
