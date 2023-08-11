#!/usr/bin/env python3

from scat.parsers.qualcomm import diagcmd
import scat.util as util
from binascii import hexlify
import struct
from collections import namedtuple
import logging
import json

try:
    from pycrate_asn1dir import RRCNR, RRCLTE
except Exception as e:
    print(e)

class DiagNrLogParser:
    def __init__(self, parent):
        self.parent = parent

        self.process = {
            # NR
            0xB822: lambda x, y, z: self.parse_nr_mib_info(x, y, z), # NR RRC MIB Info
            0xB826: lambda x, y, z: self.parse_cacombos(x, y, z), # NR RRC Supported CA Combos
            0xB821: lambda x, y, z: self.parse_nr_ota_sibs_mibs(x,y,z) # NR RRC OTA
        }

    def parse_nr_mib_info(self, pkt_header, pkt_body, args):
        pkt_ver = struct.unpack('<I', pkt_body[0:4])[0]

        item_struct = namedtuple('QcDiagNrMibInfo', 'pci nrarfcn props')
        scs_map = {
            0: 15,
            1: 30,
            2: 60,
            3: 120,
        }

        scs_str = ''
        if pkt_ver == 0x03: # Version 3
            item = item_struct._make(struct.unpack('<HI4s', pkt_body[4:14]))
            sfn = (item.props[0]) | (((item.props[1] & 0b11000000) >> 6) << 8)
            scs = (item.props[3] & 0b11000000) >> 6
        elif pkt_ver == 0x20000: # Version 131072
            item = item_struct._make(struct.unpack('<HI5s', pkt_body[4:15]))
            sfn = (item.props[0]) | (((item.props[1] & 0b11000000) >> 6) << 8)
            scs = (item.props[3] & 0b10000000) >> 7 | ((item.props[4] & 0b00000001) << 1)
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown NR MIB Information packet version {}'.format(pkt_ver))
                self.parent.logger.log(logging.WARNING, "Body: {}".format(util.xxd_oneline(pkt_body)))
            return

        if scs in scs_map:
            scs_str = '{} kHz'.format(scs_map[scs])

        if len(scs_str) > 0:
            stdout = 'NR MIB: NR-ARFCN {}, PCI {:4d}, SFN: {}, SCS: {}'.format(item.nrarfcn, item.pci, sfn, scs_str)
        else:
            stdout = 'NR MIB: NR-ARFCN {}, PCI {:4d}, SFN: {}'.format(item.nrarfcn, item.pci, sfn)
        return {'stdout': stdout}

    def parse_cacombos(self, pkt_header, pkt_body, args):
        self.parent.logger.log(logging.WARNING, "0xB826 " + util.xxd_oneline(pkt_body))
    
    def parse_nr_ota_sibs_mibs(self, pkt_header, pkt_body, args):
        try:
            (pkt_ver, unk) = struct.unpack('<B3s', pkt_body)
            sib_dict = {}
            mib_dict = {}
            if(pkt_ver == 14):
                (pkt_ver, unk, rrc_rel, rrc_ver, bearer_id, pci, freq, frame_num, 
                pdu, sib_mask, null, length) = struct.unpack('<B3sBBBHI3sBB3sH', pkt_body[:23])
                pkt_body = pkt_body[23:]
                
                # https://lab.dobergroup.org.ua/libraries-and-modules/pycrate/-/wikis/Using-the-pycrate-asn1-runtime.md

                # NR SIB: RRC_BCCH_SCH_DL
                if(pdu==1):
                    # Decode data using PyCrate decoder! Could use just raw data and manual decoder/and or wireshark
                    sib_data = pkt_body
                    # print("sib data: ", hexlify(sib_data))
                    sib_nr = RRCNR.NR_RRC_Definitions.BCCH_DL_SCH_Message
                    sib_nr.from_uper(sib_data)
                    sib_dict = json.loads(sib_nr.to_json())
                    # print(sib_dict)
                    sib_dict["raw"] = str(hexlify(sib_nr.to_uper()))[2:-1]
                    
                
                # NR MIB: RRC_BCCH_BCH    
                elif(pdu==2):
                    mib_data = pkt_body
                    mib_nr = RRCNR.NR_RRC_Definitions.BCCH_BCH_Message
                    mib_nr.from_uper(mib_data)
                    mib_dict = json.loads(mib_nr.to_json())
                    mib_dict["raw"] = str(hexlify(mib_nr.to_uper()))[2:-1]
    
                else:
                    print("unknown pdu")

                return (sib_dict, mib_dict)

            elif(pkt_ver == 12):
                pass
            
            elif(pkt_ver == 9):
                pass

            else:
                print("unknown pkt type")

        except Exception as e:
            print("NR OTA Error: ", e)
            return None
        #     9: {
        #     HEADER_FMT: '<B3sBBBHIIBB3sH', 
        #     HEADER_LEN: 24,
        #     HEADER_FIELDS: ["pkt_ver", "unk", "rrc_rel", "rrc_ver", "bearer_id",
        #                "pci", "freq", "frame_num", "pdu", "sib_mask", "null",
        #                "length"]
        # },
        # 12: {
        #     HEADER_FMT: '<B3sBBBHI3sBB3sH',
        #     HEADER_LEN: 23,
        #     HEADER_FIELDS: ["pkt_ver", "unk", "rrc_rel", "rrc_ver", "bearer_id",
        #                "pci", "freq", "frame_num", "pdu", "sib_mask", "null",
        #                "length"]
        # },
        # 14: {
        #     HEADER_FMT: '<B3sBBBHI3sBB3sH',
        #     HEADER_LEN: 23,
        #     HEADER_FIELDS: ["pkt_ver", "unk", "rrc_rel", "rrc_ver", "bearer_id",
        #                "pci", "freq", "frame_num", "pdu", "sib_mask", "null",
        #                "length"]
        # } 

    
    # TODO: NR signal strength (rsrp, rsrq, etc.)
    def parse_nr_ml1_beam_database_update(self, pkt_header, pkt_body, args):
        pass

