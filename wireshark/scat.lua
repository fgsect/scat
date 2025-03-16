-- register IP to handle ports 47290, default port used by SCAT to send IP packet
-- Extend Wireshark's default GSMTAP dissector for SCAT specific data

local gsmtap_wrapper_proto = Proto("gsmtap_extra", "Extra analysis of the GSMTAP protocol");

-- Extra fields for GSMTAP header
local F_gsmtap_subtype = ProtoField.uint8("gsmtap.sub_type", "Subtype", base.DEC)
local F_gsmtap_device_time = ProtoField.absolute_time("gsmtap.device_time", "Device Time")
gsmtap_wrapper_proto.fields = {F_gsmtap_subtype, F_gsmtap_device_time}

-- Extra fields for GSMTAPv3 header
local F_gsmtapv3_version = ProtoField.uint8("gsmtapv3.version", "Version", base.DEC)
local F_gsmtapv3_header_len = ProtoField.uint16("gsmtapv3.hdr_len", "Header length", base.DEC)
local F_gsmtapv3_type = ProtoField.uint16("gsmtapv3.type", "Type", base.HEX)
local F_gsmtapv3_subtype = ProtoField.uint16("gsmtapv3.sub_type", "Subtype", base.HEX)
table.insert(gsmtap_wrapper_proto.fields, F_gsmtapv3_version)
table.insert(gsmtap_wrapper_proto.fields, F_gsmtapv3_header_len)
table.insert(gsmtap_wrapper_proto.fields, F_gsmtapv3_type)
table.insert(gsmtap_wrapper_proto.fields, F_gsmtapv3_subtype)

local F_gsmtapv3_md_tlv_type = ProtoField.uint16("gsmtapv3.tlv_type", "Metadata Type")
local F_gsmtapv3_md_tlv_len = ProtoField.uint16("gsmtapv3.tlv_len", "Metadata Length")
local F_gsmtapv3_md_tlv_val = ProtoField.bytes("gsmtapv3.tlv_val", "Metadata Value")
table.insert(gsmtap_wrapper_proto.fields, F_gsmtapv3_md_tlv_type)
table.insert(gsmtap_wrapper_proto.fields, F_gsmtapv3_md_tlv_len)
table.insert(gsmtap_wrapper_proto.fields, F_gsmtapv3_md_tlv_val)

-- Dissectors
local ip_dissector = Dissector.get("ip")
local udp_port_table = DissectorTable.get("udp.port")

-- Fields
local f_gsmtap_version = Field.new("gsmtap.version")
local f_gsmtap_type = Field.new("gsmtap.type")
local f_header_len = Field.new("gsmtap.hdr_len")

-- Current Wireshark version
local major, minor, micro = get_version():match("(%d+)%.(%d+)%.(%d+)")

local dlist = Dissector.list()

local function check_and_get_dissector(name)
    for i=1, #dlist do
        if dlist[i] == name then
            return Dissector.get(name)
        end
    end
    print("Cannot find dissector " .. name .. ", falling back to data")
    return Dissector.get("data")
end

-- Subtype description
local lte_rrc_subtypes = {
    [ 0] = { check_and_get_dissector("lte_rrc.dl_ccch"), "DL CCCH" },
    [ 1] = { check_and_get_dissector("lte_rrc.dl_dcch"), "DL DCCH" },
    [ 2] = { check_and_get_dissector("lte_rrc.ul_ccch"), "UL CCCH" },
    [ 3] = { check_and_get_dissector("lte_rrc.ul_dcch"), "UL DCCH" },
    [ 4] = { check_and_get_dissector("lte_rrc.bcch_bch"), "BCCH BCH" },
    [ 5] = { check_and_get_dissector("lte_rrc.bcch_dl_sch"), "BCCH DL-SCH" },
    [ 6] = { check_and_get_dissector("lte_rrc.pcch"), "PCCH" },
    [ 7] = { check_and_get_dissector("lte_rrc.mcch"), "MCCH" },
    [ 8] = { check_and_get_dissector("lte_rrc.bcch_bch.mbms"), "BCCH BCH MBMS" },
    [ 9] = { check_and_get_dissector("lte_rrc.bcch_dl_sch_br"), "BCCH DL-SCH BR" },
    [10] = { check_and_get_dissector("lte_rrc.bcch_dl_sch.mbms"), "BCCH DL-SCH MBMS" },
    [11] = { check_and_get_dissector("lte_rrc.sc_mcch"), "SC-MCCH" },
    [12] = { check_and_get_dissector("lte_rrc.sbcch_sl_bch"), "SBCCH SL-BCH" },
    [13] = { check_and_get_dissector("lte_rrc.sbcch_sl_bch.v2x"), "SBCCH SL-BCH V2X" },
    [14] = { check_and_get_dissector("lte_rrc.dl_ccch.nb"), "DL CCCH NB" },
    [15] = { check_and_get_dissector("lte_rrc.dl_dcch.nb"), "DL DCCH NB" },
    [16] = { check_and_get_dissector("lte_rrc.ul_ccch.nb"), "UL CCCH NB" },
    [17] = { check_and_get_dissector("lte_rrc.ul_dcch.nb"), "UL DCCH NB" },
    [18] = { check_and_get_dissector("lte_rrc.bcch_bch.nb"), "BCCH BCH NB" },
    [19] = { check_and_get_dissector("lte-rrc.bcch.bch.nb.tdd"), "BCCH BCH NB TDD" },
    [20] = { check_and_get_dissector("lte_rrc.bcch_dl_sch.nb"), "BCCH DL-SCH NB" },
    [21] = { check_and_get_dissector("lte_rrc.pcch.nb"), "PCCH NB" },
    [22] = { check_and_get_dissector("lte_rrc.sc_mcch.nb"), "SC-MCCH NB" }
}

local lte_nas_subtypes = {
    [ 0] = { check_and_get_dissector("nas-eps_plain"), "NAS/EPS plain" },
    [ 1] = { check_and_get_dissector("nas-eps"), "NAS/EPS with security" }
}

local lte_mac_subtypes = {
    [ 0] = { check_and_get_dissector("mac-lte-framed"), "LTE MAC" },
}

local original_gsmtap_dissector

local gsmtapv3_types = {
    [0x0000] = "libosmocore logging",
    [0x0001] = "ISO 7816 smartcard",
    [0x0002] = "Baseband diagnostics",
    [0x0003] = "Radio signal status report",
    [0x0004] = "TETRA V+D",
    [0x0005] = "TETRA V+D burst",
    [0x0006] = "GMR-1 air interface (MES-MS<->GTS)",
    [0x0007] = "E1/T1",
    [0x0008] = "WiMAX burst",
    [0x0200] = "GSM Um (MS<->BTS)",
    [0x0201] = "GSM Um burst (MS<->BTS)",
    [0x0202] = "GPRS RLC/MAC",
    [0x0203] = "GPRS LLC",
    [0x0204] = "GPRS SNDCP",
    [0x0205] = "GSM Abis (BTS<->BSC)",
    [0x0206] = "GSM RLP",
    [0x0300] = "UMTS MAC",
    [0x0301] = "UMTS RLC",
    [0x0302] = "UMTS PDCP",
    [0x0303] = "UMTS RRC",
    [0x0400] = "LTE MAC",
    [0x0401] = "LTE RLC",
    [0x0402] = "LTE PDCP",
    [0x0403] = "LTE RRC",
    [0x0404] = "NAS-EPS",
    [0x0500] = "NR MAC",
    [0x0501] = "NR RLC",
    [0x0502] = "NR PDCP",
    [0x0503] = "NR RRC",
    [0x0504] = "NAS-5GS"
}

local gsmtapv3_metadata_tags = {
    [0x0000] = { "Packet timestamp", "gsmtapv3.packet_timestamp", ftypes.ABSOLUTE_TIME },
    [0x0001] = { "Packet comment", "gsmtapv3.packet_comment", ftypes.STRING },
    [0x0002] = { "Channel number", "gsmtapv3.channel_number", ftypes.UINT32 },
    [0x0003] = { "Frequency (Hz)", "gsmtapv3.frequency", ftypes.UINT64 },
    [0x0004] = { "Band indicator", "gsmtapv3.band_indicator", ftypes.UINT16 },
    [0x0005] = { "Multiplexing information (BSIC/PSC/PCI)", "gsmtapv3.multiplex", ftypes.UINT16 },

    [0x0006] = { "GSM timeslot", "gsmtapv3.gsm_timeslot", ftypes.UINT8 },
    [0x0007] = { "GSM subslot", "gsmtapv3.gsm_subslot", ftypes.UINT8 },
    [0x0008] = { "System frame number", "gsmtapv3.sfn", ftypes.UINT32 },
    [0x0009] = { "Subframe number", "gsmtapv3.subfn", ftypes.UINT16 },
    [0x000a] = { "Hyperframe number", "gsmtapv3.hfn", ftypes.UINT16 },
    [0x000d] = { "Antenna number", "gsmtapv3.antenna_num", ftypes.UINT8 },

    [0x0100] = { "Signal level", "gsmtapv3.signal_level", ftypes.FLOAT },
    [0x0101] = { "RSSI", "gsmtapv3.rssi", ftypes.FLOAT },
    [0x0102] = { "SNR", "gsmtapv3.snr", ftypes.FLOAT },
    [0x0103] = { "SINR", "gsmtapv3.sinr", ftypes.FLOAT },
    [0x0104] = { "RSCP", "gsmtapv3.rscp", ftypes.FLOAT },
    [0x0105] = { "ECIO", "gsmtapv3.ecio", ftypes.FLOAT },
    [0x0106] = { "RSRP", "gsmtapv3.rsrp", ftypes.FLOAT },
    [0x0107] = { "RSRQ", "gsmtapv3.rsrq", ftypes.FLOAT },
    [0x0108] = { "SS-RSRP", "gsmtapv3.ss_rsrp", ftypes.FLOAT },
    [0x0109] = { "CSI-RSRP", "gsmtapv3.csi_rsrp", ftypes.FLOAT },
    [0x010a] = { "SRS-RSRP", "gsmtapv3.srs_rsrp", ftypes.FLOAT },
    [0x010b] = { "SS-RSRQ", "gsmtapv3.ss_rsrq", ftypes.FLOAT },
    [0x010c] = { "CSI-RSRQ", "gsmtapv3.csi_rsrq", ftypes.FLOAT },
    [0x010d] = { "SS-SINR", "gsmtapv3.ss_sinr", ftypes.FLOAT },
    [0x010e] = { "CSI-SINR", "gsmtapv3.csi_sinr", ftypes.FLOAT },

    [0x0200] = { "Ciphering key (CK)", "gsmtapv3.ck", ftypes.NONE },
    [0x0201] = { "Integrity key (IK)", "gsmtapv3.ik", ftypes.NONE },
    [0x0202] = { "NAS encryption key (K_NASenc)", "gsmtapv3.k_nasenc", ftypes.NONE },
    [0x0203] = { "NAS integrity key (K_NASint)", "gsmtapv3.k_nasint", ftypes.NONE },
    [0x0204] = { "RRC encryption key (K_RRCenc)", "gsmtapv3.k_rrcenc", ftypes.NONE },
    [0x0205] = { "RRC integrity key (K_RRCint)", "gsmtapv3.k_rrcint", ftypes.NONE },
    [0x0206] = { "User plane encryption key (K_UPenc)", "gsmtapv3.k_upenc", ftypes.NONE },
    [0x0207] = { "User plane integrity key (K_UPint)", "gsmtapv3.k_upint", ftypes.NONE }
}

proto_fields_metadata = {}

for k, v in pairs(gsmtapv3_metadata_tags) do
    -- if not(v[3] == ftypes.NONE) then
        proto_fields_metadata[k] = ProtoField.new(v[1], v[2], v[3])
        table.insert(gsmtap_wrapper_proto.fields, proto_fields_metadata[k])
    -- end
end

local gsmtapv3_lte_rrc_subtypes = {
    [0x0001] = { check_and_get_dissector("lte_rrc.bcch_bch"), "BCCH BCH" },
    [0x0002] = { check_and_get_dissector("lte_rrc.bcch_bch.mbms"), "BCCH BCH MBMS" },
    [0x0003] = { check_and_get_dissector("lte_rrc.bcch_dl_sch"), "BCCH DL-SCH" },
    [0x0004] = { check_and_get_dissector("lte_rrc.bcch_dl_sch_br"), "BCCH DL-SCH BR" },
    [0x0005] = { check_and_get_dissector("lte_rrc.bcch_dl_sch.mbms"), "BCCH DL-SCH MBMS" },
    [0x0006] = { check_and_get_dissector("lte_rrc.mcch"), "MCCH" },
    [0x0007] = { check_and_get_dissector("lte_rrc.pcch"), "PCCH" },
    [0x0008] = { check_and_get_dissector("lte_rrc.dl_ccch"), "DL CCCH" },
    [0x0009] = { check_and_get_dissector("lte_rrc.dl_dcch"), "DL DCCH" },
    [0x000a] = { check_and_get_dissector("lte_rrc.ul_ccch"), "UL CCCH" },
    [0x000b] = { check_and_get_dissector("lte_rrc.ul_dcch"), "UL DCCH" },
    [0x000c] = { check_and_get_dissector("lte_rrc.sc_mcch"), "SC-MCCH" },

    [0x0101] = { check_and_get_dissector("lte_rrc.sbcch_sl_bch"), "SBCCH SL-BCH" },
    [0x0102] = { check_and_get_dissector("lte_rrc.sbcch_sl_bch.v2x"), "SBCCH SL-BCH V2X" },

    [0x0201] = { check_and_get_dissector("lte_rrc.bcch_bch.nb"), "BCCH BCH NB" },
    [0x0202] = { check_and_get_dissector("lte-rrc.bcch.bch.nb.tdd"), "BCCH BCH NB TDD" },
    [0x0203] = { check_and_get_dissector("lte_rrc.bcch_dl_sch.nb"), "BCCH DL-SCH NB" },
    [0x0204] = { check_and_get_dissector("lte_rrc.pcch.nb"), "PCCH NB" },
    [0x0205] = { check_and_get_dissector("lte_rrc.dl_ccch.nb"), "DL CCCH NB" },
    [0x0206] = { check_and_get_dissector("lte_rrc.dl_dcch.nb"), "DL DCCH NB" },
    [0x0207] = { check_and_get_dissector("lte_rrc.ul_ccch.nb"), "UL CCCH NB" },
    [0x0208] = { check_and_get_dissector("lte_rrc.sc_mcch.nb"), "SC-MCCH NB" },
    [0x0209] = { check_and_get_dissector("lte_rrc.ul_dcch.nb"), "UL DCCH NB" }
}

local gsmtapv3_nas_eps_subtypes = {
    [0x0000] = { check_and_get_dissector("nas-eps"), "NAS/EPS plain" },
    [0x0001] = { check_and_get_dissector("nas-eps"), "NAS/EPS" }
}

local gsmtapv3_nr_rrc_subtypes = {
    [0x0001] = { check_and_get_dissector("nr-rrc.bcch.bch"), "BCCH BCH" },
    [0x0002] = { check_and_get_dissector("nr-rrc.bcch.dl.sch"), "BCCH DL-SCH" },
    [0x0003] = { check_and_get_dissector("nr-rrc.dl.ccch"), "DL CCCH" },
    [0x0004] = { check_and_get_dissector("nr-rrc.dl.dcch"), "DL DCCH" },
    [0x0005] = { check_and_get_dissector("nr-rrc.mcch"), "MCCH" },
    [0x0006] = { check_and_get_dissector("nr-rrc.pcch"), "PCCH" },
    [0x0007] = { check_and_get_dissector("nr-rrc.ul.ccch"), "UL CCCH" },
    [0x0008] = { check_and_get_dissector("nr-rrc.ul.ccch1"), "UL CCCH1" },
    [0x0009] = { check_and_get_dissector("nr-rrc.ul.dcch"), "UL DCCH" },

    [0x0101] = { check_and_get_dissector("nr-rrc.sbcch.sl.bch"), "SBCCH SL-BCH" },
    [0x0102] = { check_and_get_dissector("nr-rrc.scch"), "SCCH" },

    [0x0201] = { check_and_get_dissector("nr-rrc.rrc_reconf"), "RRCReconfiguration" },
    [0x0202] = { check_and_get_dissector("nr-rrc.rrc_reconf_compl"), "RRCReconfigurationComplete" },
    [0x0203] = { check_and_get_dissector("nr-rrc.ue_mrdc_cap"), "UE MRDC Capabilities" },
    [0x0204] = { check_and_get_dissector("nr-rrc.ue_nr_cap"), "UE NR Capabilities" },
    [0x0205] = { check_and_get_dissector("nr-rrc.ue_radio_access_cap_info"), "UE Radio Access Capability" },
    [0x0206] = { check_and_get_dissector("nr-rrc.ue_radio_paging_info"), "UE Radio Paging Information" },
    [0x0207] = { check_and_get_dissector("nr-rrc.sib1"), "SIB1" },
    [0x0208] = { check_and_get_dissector("nr-rrc.sib2"), "SIB2" },
    [0x0209] = { check_and_get_dissector("nr-rrc.sib3"), "SIB3" },
    [0x020a] = { check_and_get_dissector("nr-rrc.sib4"), "SIB4" },
    [0x020b] = { check_and_get_dissector("nr-rrc.sib5"), "SIB5" },
    [0x020c] = { check_and_get_dissector("nr-rrc.sib6"), "SIB6" },
    [0x020d] = { check_and_get_dissector("nr-rrc.sib7"), "SIB7" },
    [0x020e] = { check_and_get_dissector("nr-rrc.sib8"), "SIB8" },
    [0x020f] = { check_and_get_dissector("nr-rrc.sib9"), "SIB9" },
    [0x0210] = { check_and_get_dissector("nr-rrc.sib10"), "SIB10" },
    [0x0211] = { check_and_get_dissector("nr-rrc.sib11"), "SIB11" },
    [0x0212] = { check_and_get_dissector("nr-rrc.sib12"), "SIB12" },
    [0x0213] = { check_and_get_dissector("nr-rrc.sib13"), "SIB13" },
    [0x0214] = { check_and_get_dissector("nr-rrc.sib14"), "SIB14" },
    [0x0215] = { check_and_get_dissector("nr-rrc.sib15"), "SIB15" },
    [0x0216] = { check_and_get_dissector("nr-rrc.sib16"), "SIB16" },
    [0x0217] = { check_and_get_dissector("nr-rrc.sib17"), "SIB17" },
    [0x0218] = { check_and_get_dissector("nr-rrc.sib18"), "SIB18" },
    [0x0219] = { check_and_get_dissector("nr-rrc.sib19"), "SIB19" },
    [0x021a] = { check_and_get_dissector("nr-rrc.sib20"), "SIB20" },
    [0x021b] = { check_and_get_dissector("nr-rrc.sib21"), "SIB21" },
    [0x021c] = { check_and_get_dissector("nr-rrc.sib22"), "SIB22" },
    [0x021d] = { check_and_get_dissector("nr-rrc.sib23"), "SIB23" },
    [0x021e] = { check_and_get_dissector("nr-rrc.sib24"), "SIB24" },
    [0x021f] = { check_and_get_dissector("nr-rrc.sib25"), "SIB25" },
    [0x0220] = { check_and_get_dissector("nr-rrc.sib17bis"), "SIB17bis" }
}

local gsmtapv3_gsm_band_indicators = {
    [0x0002] = "PCS 1900",
    [0x0003] = "DCS 1800",
    [0x0005] = "GSM 850",
    [0x0008] = "GSM 900",

    [0xf000] = "T-GSM 380",
    [0xf001] = "T-GSM 410",
    [0xf002] = "GSM 450",
    [0xf003] = "GSM 480",
    [0xf004] = "GSM 710",
    [0xf005] = "GSM 750",
    [0xf006] = "T-GSM 810"
}

local gsmtapv3_nas_5gs_subtypes = {
    [0x0000] = { check_and_get_dissector("nas-5gs"), "NAS/5GS plain" },
    [0x0001] = { check_and_get_dissector("nas-5gs"), "NAS/5GS" }
}

function gsmtapv3_parse_metadata(t, hdr_buffer, hdr_len)
    local offset = 0

    while offset < (hdr_len) do
        if (offset + 4) > hdr_len then
            break
        end

        local type = hdr_buffer(offset, 2):uint()
        local len = hdr_buffer(offset + 2, 2):uint()
        local type_string
        local type_info
        if len == 0 then
            offset = offset + 2
            break
        end
        if gsmtapv3_metadata_tags[type] then
            type_string = string.format("Type: %s (0x%04x)", gsmtapv3_metadata_tags[type][1], type)
            type_info = gsmtapv3_metadata_tags[type][1]
        else
            type_string = string.format("Type: Unknown metadata (0x%04x)", type)
            type_info = "gsmtapv3.tlv_val"
        end
        t:add(F_gsmtapv3_md_tlv_type, hdr_buffer(offset, 2)):set_text(type_string)
        t:add(F_gsmtapv3_md_tlv_len, hdr_buffer(offset+2, 2)):set_text(string.format("Length: %d", len))
        offset = offset + 4

        md_field = proto_fields_metadata[type]
        md_tag = gsmtapv3_metadata_tags[type]
        if md_tag[3] == ftypes.UINT16 then
            t:add(md_field, hdr_buffer(offset, 2))
        elseif md_tag[3] == ftypes.UINT32 then
            t:add(md_field, hdr_buffer(offset, 4))
        elseif md_tag[3] == ftypes.UINT64 then
            t:add(md_field, hdr_buffer(offset, 8))
        elseif md_tag[3] == ftypes.STRING then
            t:add(md_field, hdr_buffer(offset, len):string(ENC_UTF_8))
        elseif md_tag[3] == ftypes.FLOAT then
            t:add(md_field, hdr_buffer(offset, 4))
        else
            if type == 0x0000 then
                -- "Packet timestamp"
                if len == 12 then
                    -- sec 8, usec 4
                    time_sec = hdr_buffer(offset, 8):uint64():tonumber()
                    time_nsec = hdr_buffer(offset+8, 4):uint()
                    t:add(md_field, hdr_buffer(offset, len), NSTime.new(time_sec, time_nsec))
                end
            else
                t:add(F_gsmtapv3_md_tlv_val, hdr_buffer(offset, len)):set_text(string.format("Value: %s", tostring(hdr_buffer(offset, len):bytes())))
            end
        end

        offset = offset + len

    end
end

function gsmtap_wrapper_proto.dissector(tvbuffer, pinfo, treeitem)
    -- GSMTAPv3
    local version = tvbuffer(0, 1):uint()
    if version == 3 then
        local hdr_len = tvbuffer(2, 2):uint()
        local type = tvbuffer(4, 2):uint()
        local subtype = tvbuffer(6, 2):uint()

        local hdr_buffer = tvbuffer:range(0, 4 * hdr_len)
        local gsmtap_data = tvbuffer:range(4 * hdr_len)

        local t = treeitem:add(gsmtap_wrapper_proto, tvbuffer())
        local itemtext = "Unknown"
        if gsmtapv3_types[type] then
            itemtext = gsmtapv3_types[type]
        end

        local child, version_value = t:add(F_gsmtapv3_version, tvbuffer(0, 1))
        local child, hdr_len_value = t:add(F_gsmtapv3_header_len, tvbuffer(2, 2))
                                   :set_text(string.format("Header length: %d bytes", hdr_len * 4))
        local child, type_value = t:add(F_gsmtapv3_type, tvbuffer(4, 2))
                                   :set_text(string.format("Type: 0x%04x (%s)", type, itemtext))

        pinfo.cols.protocol = "GSMTAPv3"
        if type == 0x0403 then
            pinfo.cols.info = ""
            itemtext = "Unknown"
            if gsmtapv3_lte_rrc_subtypes[subtype] then
                itemtext = gsmtapv3_lte_rrc_subtypes[subtype][2]
            end
            local child, subtype_value = t:add(F_gsmtapv3_subtype, tvbuffer(6, 2))
                                    :set_text(string.format("Subtype: 0x%04x (%s)", subtype, itemtext))
            gsmtapv3_parse_metadata(t, tvbuffer(8, 4 * hdr_len - 8), 4 * hdr_len - 8)
            gsmtapv3_lte_rrc_subtypes[subtype][1]:call(gsmtap_data:tvb(), pinfo, treeitem)
        elseif type == 0x0404 then
            pinfo.cols.info = ""
            itemtext = "Unknown"
            if gsmtapv3_nas_eps_subtypes[subtype] then
                itemtext = gsmtapv3_nas_eps_subtypes[subtype][2]
            end
            local child, subtype_value = t:add(F_gsmtapv3_subtype, tvbuffer(6, 2))
                                    :set_text(string.format("Subtype: 0x%04x (%s)", subtype, itemtext))
            gsmtapv3_parse_metadata(t, tvbuffer(8, 4 * hdr_len - 8), 4 * hdr_len - 8)
            gsmtapv3_nas_eps_subtypes[subtype][1]:call(gsmtap_data:tvb(), pinfo, treeitem)
        elseif type == 0x0503 then
            pinfo.cols.info = ""
            itemtext = "Unknown"
            if gsmtapv3_nr_rrc_subtypes[subtype] then
                itemtext = gsmtapv3_nr_rrc_subtypes[subtype][2]
            end
            local child, subtype_value = t:add(F_gsmtapv3_subtype, tvbuffer(6, 2))
                                    :set_text(string.format("Subtype: 0x%04x (%s)", subtype, itemtext))
            gsmtapv3_parse_metadata(t, tvbuffer(8, 4 * hdr_len - 8), 4 * hdr_len - 8)
            gsmtapv3_nr_rrc_subtypes[subtype][1]:call(gsmtap_data:tvb(), pinfo, treeitem)
        elseif type == 0x0504 then
            pinfo.cols.info = ""
            itemtext = "Unknown"
            if gsmtapv3_nas_5gs_subtypes[subtype] then
                itemtext = gsmtapv3_nas_5gs_subtypes[subtype][2]
            end
            local child, subtype_value = t:add(F_gsmtapv3_subtype, tvbuffer(6, 2))
                                    :set_text(string.format("Subtype: 0x%04x (%s)", subtype, itemtext))
            gsmtapv3_parse_metadata(t, tvbuffer(8, 4 * hdr_len - 8), 4 * hdr_len - 8)
            gsmtapv3_nas_5gs_subtypes[subtype][1]:call(gsmtap_data:tvb(), pinfo, treeitem)
        else
            pinfo.cols.info = "GSMTAPv3"
        end

        return
    end

    original_gsmtap_dissector:call(tvbuffer, pinfo, treeitem)
    -- Expose subitem field of GSMTAP header
    local subtreeitem = treeitem:add(gsmtap_wrapper_proto, tvbuffer)
    local subtype = tvbuffer(12, 1):uint()
    local itemtext = "Unknown"

    -- Add subtype description
    if f_gsmtap_type().value == 0x0d then
        -- LTE RRC
        if lte_rrc_subtypes[subtype] then
            itemtext = lte_rrc_subtypes[subtype][2]
        end
    elseif f_gsmtap_type().value == 0x12 then
        -- LTE NAS
        if lte_nas_subtypes[subtype] then
            itemtext = lte_nas_subtypes[subtype][2]
        end
    elseif f_gsmtap_type().value == 0x0e then
        -- LTE MAC
        itemtext = lte_mac_subtypes[0][2]
    end
    subtreeitem:add(F_gsmtap_subtype, tvbuffer(12, 1), subtype)
               :set_text(string.format("Subtype: %d (%s)", subtype, itemtext))

    if major and ((tonumber(major) <= 1) or
        (tonumber(major) == 2 and (tonumber(minor) < 6))) then
        -- Wireshark <2.6.0 do not support GSMTAP's LTE RRC/NAS dissection
        -- We have to register it by ourselves
        if f_gsmtap_type().value == 0x0d then
            if lte_rrc_subtypes[subtype] then
                lte_rrc_subtypes[subtype][1]:call(tvbuffer:range(f_header_len().value):tvb(), pinfo, treeitem)
            end
        elseif f_gsmtap_type().value == 0x0e then
            lte_mac_subtypes[0][1]:call(tvbuffer:range(f_header_len().value):tvb(), pinfo, treeitem)
        elseif f_gsmtap_type().value == 0x12 then
            if lte_nas_subtypes[subtype] then
                lte_nas_subtypes[subtype][1]:call(tvbuffer:range(f_header_len().value):tvb(), pinfo, treeitem)
            end
        end
    elseif major and ((tonumber(major) <= 1) or
        (tonumber(major) == 2 and ((tonumber(minor) <= 6) or (tonumber(minor) == 6 and tonumber(micro) < 5)))) then
        -- Wireshark <2.6.5 (probably) do not support newer LTE RRC channels
        if f_gsmtap_type().value == 0x0d then
            if subtype > 7 and lte_rrc_subtypes[subtype] then
                lte_rrc_subtypes[subtype][1]:call(tvbuffer:range(f_header_len().value):tvb(), pinfo, treeitem)
            end
        elseif f_gsmtap_type().value == 0x0e then
            lte_mac_subtypes[0][1]:call(tvbuffer:range(f_header_len().value):tvb(), pinfo, treeitem)
        end
    else
        -- Wireshark do not support LTE MAC yet
        if f_gsmtap_type().value == 0x0e then
            lte_mac_subtypes[0][1]:call(tvbuffer:range(f_header_len().value):tvb(), pinfo, treeitem)
        end
    end

end

original_gsmtap_dissector = udp_port_table:get_dissector(4729)

udp_port_table:add(47290, ip_dissector)
udp_port_table:add(4729, gsmtap_wrapper_proto)
