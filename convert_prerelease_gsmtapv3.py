#!/usr/bin/python3

# Dependencies: scapy, python-pcapng (available through pip)

import argparse
import os
import struct
import math
import binascii
from enum import IntEnum, unique
from scapy.all import rdpcap, wrpcap, UDP, Raw, Ether
from pcapng import FileScanner
from pcapng.blocks import EnhancedPacket, SectionHeader
from pcapng.writer import FileWriter

gsmtapv2_v3_payload_type_map = {
    0x01: 0x0200, #define GSMTAP_TYPE_UM		0x01
    0x02: 0x0205, #define GSMTAP_TYPE_ABIS	0x02
    0x04: 0x0001, #define GSMTAP_TYPE_SIM		0x04	/* ISO 7816 smart card interface */
    0x0c: 0x0303, #define GSMTAP_TYPE_UMTS_RRC	0x0c
    0x0d: 0x0403, #define GSMTAP_TYPE_LTE_RRC	0x0d	/* LTE interface */
    0x0e: 0x0400, #define GSMTAP_TYPE_LTE_MAC	0x0e	/* LTE MAC interface */
    0x10: 0x0000, #define GSMTAP_TYPE_OSMOCORE_LOG	0x10	/* libosmocore logging */
    0x12: 0x0404, #define GSMTAP_TYPE_LTE_NAS		0x12	/* LTE Non-Access Stratum */
    0x20: 0x0504, # NR NAS - for internal testing
    0x21: 0x0503, # NR RRC - for internal testing
    0x22: 0x0500, # NR MAC - for internal testing
}

@unique
class gsmtapv3_metadata_tags(IntEnum):
    PACKET_TIMESTAMP = 0x0000
    CHANNEL_NUMBER = 0x0002
    BSIC_PSC_PCI = 0x0005

    SFN = 0x0008
    SUBFN = 0x0009
    
    END_OF_METADATA = 0xfffe

@unique
class gsmtapv3_lte_rrc_types(IntEnum):
    BCCH_BCH = 0x0001
    BCCH_BCH_MBMS = 0x0002
    BCCH_DL_SCH = 0x0003
    BCCH_DL_SCH_BR = 0x0004
    BCCH_DL_SCH_MBMS = 0x0005
    MCCH = 0x0006
    PCCH = 0x0007
    DL_CCCH = 0x0008
    DL_DCCH = 0x0009
    UL_CCCH = 0x000a
    UL_DCCH = 0x000b
    SC_MCCH = 0x000c

    SBCCH_SL_BCH = 0x0101
    SBCCH_SL_BCH_V2X = 0x0102

    BCCH_BCH_NB = 0x0201
    BCCH_BCH_NB_TDD = 0x0202
    BCCH_DL_SCH_NB = 0x0203
    PCCH_NB = 0x0204
    DL_CCCH_NB = 0x0205
    DL_DCCH_NB = 0x0206
    UL_CCCH_NB = 0x0207
    SC_MCCH_NB = 0x0208
    UL_DCCH_NB = 0x0209

@unique
class gsmtapv3_nr_rrc_types(IntEnum):
    BCCH_BCH = 0x0001
    BCCH_DL_SCH = 0x0002
    DL_CCCH = 0x0003
    DL_DCCH = 0x0004
    MCCH = 0x0005
    PCCH = 0x0006
    UL_CCCH = 0x0007
    UL_CCCH1 = 0x0008
    UL_DCCH = 0x0009

    SBCCH_SL_BCH = 0x0101
    SCCH = 0x0102

    RRC_RECONF = 0x0201
    RRC_RECONF_COMPLETE = 0x0202
    UE_MRDC_CAP = 0x0203
    UE_NR_CAP = 0x0204
    UE_RADIO_ACCESS_CAP_INFO = 0x0205
    UE_RADIO_PAGING_INFO = 0x0206
    SIB1 = 0x0207
    SIB2 = 0x0208
    SIB3 = 0x0209
    SIB4 = 0x020a
    SIB5 = 0x020b
    SIB6 = 0x020c
    SIB7 = 0x020d
    SIB8 = 0x020e
    SIB9 = 0x020f
    SIB10 = 0x0210
    SIB11 = 0x0211
    SIB12 = 0x0212
    SIB13 = 0x0213
    SIB14 = 0x0214
    SIB15 = 0x0215
    SIB16 = 0x0216
    SIB17 = 0x0217
    SIB18 = 0x0218
    SIB19 = 0x0219
    SIB20 = 0x021a
    SIB21 = 0x021b
    SIB22 = 0x021c
    SIB23 = 0x021d
    SIB24 = 0x021e
    SIB25 = 0x021f
    SIB17BIS = 0x0220

gsmtapv2_v3_umts_rrc_subtype_map =  {
     0: 0x0001, # GSMTAP_RRC_SUB_DL_DCCH_Message = 0,
     1: 0x0002, # GSMTAP_RRC_SUB_UL_DCCH_Message,
     2: 0x0003, # GSMTAP_RRC_SUB_DL_CCCH_Message,
     3: 0x0004, # GSMTAP_RRC_SUB_UL_CCCH_Message,
     4: 0x0005, # GSMTAP_RRC_SUB_PCCH_Message,
     5: 0x0006, # GSMTAP_RRC_SUB_DL_SHCCH_Message,
     6: 0x0007, # GSMTAP_RRC_SUB_UL_SHCCH_Message,
     7: 0x0008, # GSMTAP_RRC_SUB_BCCH_FACH_Message,
     8: 0x0009, # GSMTAP_RRC_SUB_BCCH_BCH_Message,
     9: 0x000a, # GSMTAP_RRC_SUB_MCCH_Message,
    10: 0x000b, # GSMTAP_RRC_SUB_MSCH_Message,
    11: 0x0101, # GSMTAP_RRC_SUB_HandoverToUTRANCommand,
    12: 0x0102, # GSMTAP_RRC_SUB_InterRATHandoverInfo,
    13: 0x0103, # GSMTAP_RRC_SUB_SystemInformation_BCH,
    14: 0x0104, # GSMTAP_RRC_SUB_System_Information_Container,
    15: 0x0105, # GSMTAP_RRC_SUB_UE_RadioAccessCapabilityInfo,
    16: 0x0106, # GSMTAP_RRC_SUB_MasterInformationBlock,
    17: 0x0107, # GSMTAP_RRC_SUB_SysInfoType1,
    18: 0x0108, # GSMTAP_RRC_SUB_SysInfoType2,
    19: 0x0109, # GSMTAP_RRC_SUB_SysInfoType3,
    20: 0x010a, # GSMTAP_RRC_SUB_SysInfoType4,
    21: 0x010b, # GSMTAP_RRC_SUB_SysInfoType5,
    22: 0x010c, # GSMTAP_RRC_SUB_SysInfoType5bis,
    23: 0x010d, # GSMTAP_RRC_SUB_SysInfoType6,
    24: 0x010e, # GSMTAP_RRC_SUB_SysInfoType7,
    25: 0x010f, # GSMTAP_RRC_SUB_SysInfoType8,
    26: 0x0110, # GSMTAP_RRC_SUB_SysInfoType9,
    27: 0x0111, # GSMTAP_RRC_SUB_SysInfoType10,
    28: 0x0112, # GSMTAP_RRC_SUB_SysInfoType11,
    29: 0x0113, # GSMTAP_RRC_SUB_SysInfoType11bis,
    30: 0x0114, # GSMTAP_RRC_SUB_SysInfoType12,
    31: 0x0115, # GSMTAP_RRC_SUB_SysInfoType13,
    32: 0x0116, # GSMTAP_RRC_SUB_SysInfoType13_1,
    33: 0x0117, # GSMTAP_RRC_SUB_SysInfoType13_2,
    34: 0x0118, # GSMTAP_RRC_SUB_SysInfoType13_3,
    35: 0x0119, # GSMTAP_RRC_SUB_SysInfoType13_4,
    36: 0x011a, # GSMTAP_RRC_SUB_SysInfoType14,
    37: 0x011b, # GSMTAP_RRC_SUB_SysInfoType15,
    38: 0x011c, # GSMTAP_RRC_SUB_SysInfoType15bis,
    39: 0x011d, # GSMTAP_RRC_SUB_SysInfoType15_1,
    40: 0x011e, # GSMTAP_RRC_SUB_SysInfoType15_1bis,
    41: 0x011f, # GSMTAP_RRC_SUB_SysInfoType15_2,
    42: 0x0120, # GSMTAP_RRC_SUB_SysInfoType15_2bis,
    43: 0x0121, # GSMTAP_RRC_SUB_SysInfoType15_2ter,
    44: 0x0122, # GSMTAP_RRC_SUB_SysInfoType15_3,
    45: 0x0123, # GSMTAP_RRC_SUB_SysInfoType15_3bis,
    46: 0x0124, # GSMTAP_RRC_SUB_SysInfoType15_4,
    47: 0x0125, # GSMTAP_RRC_SUB_SysInfoType15_5,
    48: 0x0126, # GSMTAP_RRC_SUB_SysInfoType15_6,
    49: 0x0127, # GSMTAP_RRC_SUB_SysInfoType15_7,
    50: 0x0128, # GSMTAP_RRC_SUB_SysInfoType15_8,
    51: 0x0129, # GSMTAP_RRC_SUB_SysInfoType16,
    52: 0x012a, # GSMTAP_RRC_SUB_SysInfoType17,
    53: 0x012b, # GSMTAP_RRC_SUB_SysInfoType18,
    54: 0x012c, # GSMTAP_RRC_SUB_SysInfoType19,
    55: 0x012d, # GSMTAP_RRC_SUB_SysInfoType20,
    56: 0x012e, # GSMTAP_RRC_SUB_SysInfoType21,
    57: 0x012f, # GSMTAP_RRC_SUB_SysInfoType22,
    58: 0x0130, # GSMTAP_RRC_SUB_SysInfoTypeSB1,
    59: 0x0131, # GSMTAP_RRC_SUB_SysInfoTypeSB2,
    60: 0x0132, # GSMTAP_RRC_SUB_ToTargetRNC_Container,
    61: 0x0133, # GSMTAP_RRC_SUB_TargetRNC_ToSourceRNC_Container,
}

gsmtapv2_v3_lte_rrc_subtype_map =  {
     0: 0x0008, # GSMTAP_LTE_RRC_SUB_DL_CCCH_Message = 0,
     1: 0x0009, # GSMTAP_LTE_RRC_SUB_DL_DCCH_Message,
     2: 0x000a, # GSMTAP_LTE_RRC_SUB_UL_CCCH_Message,
     3: 0x000b, # GSMTAP_LTE_RRC_SUB_UL_DCCH_Message,
     4: 0x0001, # GSMTAP_LTE_RRC_SUB_BCCH_BCH_Message,
     5: 0x0003, # GSMTAP_LTE_RRC_SUB_BCCH_DL_SCH_Message,
     6: 0x0007, # GSMTAP_LTE_RRC_SUB_PCCH_Message,
     7: 0x0006, # GSMTAP_LTE_RRC_SUB_MCCH_Message,
     8: 0x0002, # GSMTAP_LTE_RRC_SUB_BCCH_BCH_Message_MBMS,
     9: 0x0004, # GSMTAP_LTE_RRC_SUB_BCCH_DL_SCH_Message_BR,
    10: 0x0005, # GSMTAP_LTE_RRC_SUB_BCCH_DL_SCH_Message_MBMS,
    11: 0x000c, # GSMTAP_LTE_RRC_SUB_SC_MCCH_Message,
    12: 0x0101, # GSMTAP_LTE_RRC_SUB_SBCCH_SL_BCH_Message,
    13: 0x0102, # GSMTAP_LTE_RRC_SUB_SBCCH_SL_BCH_Message_V2X,
    14: 0x0205, # GSMTAP_LTE_RRC_SUB_DL_CCCH_Message_NB,
    15: 0x0206, # GSMTAP_LTE_RRC_SUB_DL_DCCH_Message_NB,
    16: 0x0207, # GSMTAP_LTE_RRC_SUB_UL_CCCH_Message_NB,
    17: 0x0209, # GSMTAP_LTE_RRC_SUB_UL_DCCH_Message_NB,
    18: 0x0201, # GSMTAP_LTE_RRC_SUB_BCCH_BCH_Message_NB,
    19: 0x0202, # GSMTAP_LTE_RRC_SUB_BCCH_BCH_Message_TDD_NB,
    20: 0x0203, # GSMTAP_LTE_RRC_SUB_BCCH_DL_SCH_Message_NB,
    21: 0x0204, # GSMTAP_LTE_RRC_SUB_PCCH_Message_NB,
    22: 0x0208, #
}

gsmtapv2_v3_nr_rrc_subtype_map =  {
     0: 0x0001, # BCCH BCH
     1: 0x0002, # BCCH DL SCH
     2: 0x0003, # DL CCCH
     3: 0x0004, # DL DCCH
     4: 0x0005, # MCCH
     5: 0x0006, # PCCH
     6: 0x0007, # UL CCCH
     7: 0x0008, # UL CCCH1
     8: 0x0009, # UL DCCH
     9: 0x0101, # SBCCH SL BCH
    10: 0x0102, # SCCH
    32: 0x0201, # RRCReconfiguration
    33: 0x0203, # UE MRDC Capability
    34: 0x0204, # UE NR Capability
    35: 0x0205, # UE Radio Access Capability
    36: 0x0206, # UE Radio Paging Capability
}

def modify_gsmtapv3_header_140(payload: bytes):
    if payload[0] != 0x03:
        return payload

    if len(payload) < 8:
        return payload

    # Version, Reserved, Header Length, Type, Subtype
    gsmtap_hdr = struct.unpack('!BBHHH', payload[0:8])

    if len(payload) < gsmtap_hdr[2] * 4:
        return payload

    gsmtap_tlv_col = payload[8:gsmtap_hdr[2] * 4]
    payload_body = payload[gsmtap_hdr[2] * 4:]

    i = 0
    while i < len(gsmtap_tlv_col):
        try:
            g_t, g_l = struct.unpack('!HH', gsmtap_tlv_col[i:i+4])
            i += 4
            i += g_l
        except:
            break
    gsmtap_tlv_col = gsmtap_tlv_col[:i] + struct.pack('!H', 0xfffe)

    header_len = 8 + len(gsmtap_tlv_col)

    gsmtap_hdr_new = struct.pack('!BBHHH',
        3,                           # Version
        0,                           # Reserved
        math.ceil(header_len/4),     # Header Length
        gsmtap_hdr[3],               # Type
        gsmtap_hdr[4],               # Subtype
        )

    return gsmtap_hdr_new + gsmtap_tlv_col + payload_body

def modify_gsmtapv3_header(payload: bytes):
    if not (payload[0] == 0x03 or (payload[0] == 0x02 and payload[2] in (0x20, 0x21))):
        return payload

    device_sec = 0
    device_usec = 0
    payload_body = b''
    gsmtap_v3_metadata = b''
    chan_number = 0
    pci = -1

    if payload[1] == 4:
        gsmtapv3_prerelease_header = struct.unpack('!BBBBHBBLBBBB', payload[0:16])
        chan_number = gsmtapv3_prerelease_header[4]
        payload_body = payload[16:]
    elif payload[1] == 7:
        gsmtapv3_prerelease_header = struct.unpack('!BBBBHBBLBBBB QL', payload[0:28])
        chan_number = gsmtapv3_prerelease_header[4]
        payload_body = payload[28:]
        device_sec = gsmtapv3_prerelease_header[12]
        device_usec = gsmtapv3_prerelease_header[13]
    elif payload[1] == 9:
        gsmtapv3_prerelease_header = struct.unpack('!BBBBHBBLBBBB QL LHH', payload[0:36])
        chan_number = gsmtapv3_prerelease_header[4]
        payload_body = payload[36:]
        device_sec = gsmtapv3_prerelease_header[12]
        device_usec = gsmtapv3_prerelease_header[13]
        if gsmtapv3_prerelease_header[14] > 0:
            chan_number = gsmtapv3_prerelease_header[14]
        pci = gsmtapv3_prerelease_header[15]
    else:
        print(f"[-] Invalid header length: {payload[1]}")
        return payload

    payload_type = 0x0000
    sub_type = 0x0000

    # payload type
    if gsmtapv3_prerelease_header[2] in gsmtapv2_v3_payload_type_map:
        payload_type = gsmtapv2_v3_payload_type_map[gsmtapv3_prerelease_header[2]]
    else:
        print(f"[-] Payload type not supported: {gsmtapv3_prerelease_header[2]}")
        return payload

    # subtype
    gsmtapv2_subtype = gsmtapv3_prerelease_header[8]
    if gsmtapv3_prerelease_header[2] == 0x01: # GSM UM
        if gsmtapv2_subtype & 0x80 == 0x80:
            sub_type = (gsmtapv2_subtype & 0x7f) | 0x100
        else:
            sub_type = gsmtapv2_subtype
    elif gsmtapv3_prerelease_header[2] == 0x0c: # UMTS RRC
        if gsmtapv2_subtype in gsmtapv2_v3_umts_rrc_subtype_map:
            sub_type = gsmtapv2_v3_umts_rrc_subtype_map[gsmtapv2_subtype]
        else:
            sub_type = 0x0000
    elif gsmtapv3_prerelease_header[2] == 0x0d: # LTE RRC
        if gsmtapv2_subtype in gsmtapv2_v3_lte_rrc_subtype_map:
            sub_type = gsmtapv2_v3_lte_rrc_subtype_map[gsmtapv2_subtype]
        else:
            sub_type = 0x0000
    elif gsmtapv3_prerelease_header[2] == 0x12: # LTE NAS
        sub_type = gsmtapv2_subtype
    elif gsmtapv3_prerelease_header[2] == 0x20: # NR NAS
        sub_type = gsmtapv2_subtype
    elif gsmtapv3_prerelease_header[2] == 0x21: # NR RRC
        if gsmtapv2_subtype in gsmtapv2_v3_nr_rrc_subtype_map:
            sub_type = gsmtapv2_v3_nr_rrc_subtype_map[gsmtapv2_subtype]
        else:
            print("Unknown NR RRC subtype {}".format(gsmtapv2_subtype))
            sub_type = 0x0000

    header_len = 8

    t = gsmtapv3_metadata_tags
    if device_sec > 0:
        gsmtap_v3_metadata += struct.pack('!HHQL', t.PACKET_TIMESTAMP, 12, device_sec, device_usec * 1000)
        header_len += 16

    if gsmtapv3_prerelease_header[2] in (0x01, 0x03, 0x08, 0x09, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x21):
        gsmtap_v3_metadata += struct.pack('!HHL', t.CHANNEL_NUMBER, 4, chan_number)
        header_len += 8

    if pci > 0:
        gsmtap_v3_metadata += struct.pack('!HHH', t.BSIC_PSC_PCI, 2, pci)
        header_len += 6

    if gsmtapv3_prerelease_header[7] > 0:
        gsmtap_v3_metadata += struct.pack('!HHL', t.SFN, 4, gsmtapv3_prerelease_header[7])
        header_len += 8

    if gsmtapv3_prerelease_header[10] > 0:
        gsmtap_v3_metadata += struct.pack('!HHH', t.SUBFN, 2, gsmtapv3_prerelease_header[10])
        header_len += 6
    
    gsmtap_v3_metadata += struct.pack('!H', t.END_OF_METADATA)
    header_len += 2

    gsmtap_hdr = struct.pack('!BBHHH',
        3,                           # Version
        0,                           # Reserved
        math.ceil(header_len/4),     # Header Length
        payload_type,                # Type
        sub_type,                    # Subtype
        )
    gsmtap_hdr += gsmtap_v3_metadata

    return gsmtap_hdr + payload_body


def process_pcap(input_file: str, output_file: str, is_140: bool):
    """Handles plain .pcap files using Scapy only (no metadata preservation)."""
    packets = rdpcap(input_file)

    for pkt in packets:
        if UDP in pkt and pkt[UDP].dport == 4729 and Raw in pkt:
            payload = pkt[Raw].load
            if is_140:
                new_payload = modify_gsmtapv3_header_140(payload)
            else:
                new_payload = modify_gsmtapv3_header(payload)
            if new_payload != payload:
                pkt[Raw].load = new_payload
                del pkt[UDP].len
                del pkt[UDP].chksum

    wrpcap(output_file, packets)
    print(f"[✓] .pcap processed and written to: {output_file}")


def process_pcapng(input_file: str, output_file: str, is_140: bool):
    """Handles .pcapng files using pcapng + scapy (with metadata preservation)."""
    with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
        scanner = FileScanner(infile)
        writer = None
        shb = None

        for block in scanner:
            if isinstance(block, SectionHeader):
                shb = block

            if not isinstance(block, EnhancedPacket):
                if writer is None:
                    writer = FileWriter(outfile, block)
                writer.write_block(block)
                continue

            pkt_bytes = block.packet_data

            try:
                pkt = Ether(pkt_bytes)
            except Exception:
                writer.write_block(block)
                continue

            if UDP in pkt and pkt[UDP].dport == 4729 and Raw in pkt:
                raw = pkt[Raw].load
                if is_140:
                    new_raw = modify_gsmtapv3_header_140(raw)
                else:
                    new_raw = modify_gsmtapv3_header(raw)
                if new_raw != raw:
                    pkt[Raw].load = new_raw
                    del pkt['IP'].len
                    del pkt['IP'].chksum
                    del pkt[UDP].len
                    del pkt[UDP].chksum
                    pkt_bytes = bytes(pkt)
                    block = EnhancedPacket(
                        interface_id=block.interface_id,
                        timestamp=block.timestamp,
                        packet_data=pkt_bytes,
                        original_len=len(pkt_bytes),
                        options=block.options,
                        endianness=shb.endianness,
                        section=shb
                    )

            writer.write_block(block)

    print(f"[✓] .pcapng processed and written to: {output_file}")


def main():
    parser = argparse.ArgumentParser(description="Modify UDP/4729 packets in .pcap or .pcapng file.")
    parser.add_argument('--input', '-i', required=True, help="Input capture file (.pcap or .pcapng)")
    parser.add_argument('--output', '-o', help="Optional output file (default: *_modified.ext)")
    parser.add_argument('--scat140', '-1', action="store_true", help="Parse input file using GSMTAPv3 definition of SCAT 1.4.0")

    args = parser.parse_args()
    input_file = args.input
    output_file = args.output
    is_140 = args.scat140

    if not os.path.isfile(input_file):
        print(f"[!] File not found: {input_file}")
        return

    # Determine file extension
    _, ext = os.path.splitext(input_file)
    ext = ext.lower()

    # Auto-name output file if not provided
    if not output_file:
        output_file = input_file.replace(ext, f"_modified{ext}")

    if ext == ".pcapng":
        process_pcapng(input_file, output_file, is_140)
    elif ext == ".pcap":
        process_pcap(input_file, output_file, is_140)
    else:
        print(f"[!] Unsupported file type: {ext}")
        print("    Supported: .pcap, .pcapng")


if __name__ == "__main__":
    main()
