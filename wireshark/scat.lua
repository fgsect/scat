-- register IP to handle ports 47290, default port used by SCAT to send IP packet
-- Extend Wireshark's default GSMTAP dissector for SCAT specific data

local gsmtap_wrapper_proto = Proto("gsmtap_extra", "Extra analysis of the GSMTAP protocol");

-- Extra fields for GSMTAP header
local F_gsmtap_subtype = ProtoField.uint8("gsmtap.sub_type", "Subtype", base.DEC)
local F_gsmtap_device_time = ProtoField.absolute_time("gsmtap.device_time", "Device Time")
gsmtap_wrapper_proto.fields = {F_gsmtap_subtype, F_gsmtap_device_time}

-- Dissectors
local ip_dissector = Dissector.get("ip")
local lte_mac_dissector = Dissector.get("mac-lte")
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
    warn("Cannot find dissector " .. name .. ", falling back to data")
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

local original_gsmtap_dissector

function gsmtap_wrapper_proto.dissector(tvbuffer, pinfo, treeitem)
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
    end
    subtreeitem:add(F_gsmtap_subtype, tvbuffer(12, 1), subtype)
               :set_text(string.format("Subtype: %d (%s)", subtype, itemtext))

    -- GSMTAP v3: device timestamp
    -- Not an official extension of GSMTAP, hack used by SCAT
    if f_gsmtap_version().value == 3 then
        local time_sec = tvbuffer(16, 8):uint64():tonumber()
        local time_nsec = tvbuffer(24, 4):int() * 1000
        local nstime = NSTime.new(time_sec, time_nsec)
        subtreeitem:add(F_gsmtap_device_time, tvbuffer(16, 12), nstime)
                   :set_text("Device timestamp: " .. format_date(nstime:tonumber()))
    end

    if major and ((tonumber(major) <= 1) or
        (tonumber(major) == 2 and (tonumber(minor) < 6))) then
        -- Wireshark <2.6.0 do not support GSMTAP's LTE RRC/NAS dissection
        -- We have to register it by ourselves
        if f_gsmtap_type().value == 0x0d then
            if lte_rrc_subtypes[subtype] then
                lte_rrc_subtypes[subtype][1]:call(tvbuffer:range(f_header_len().value):tvb(), pinfo, treeitem)
            end
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
        end
    end

    -- TODO: LTE MAC information used by SCAT
end

original_gsmtap_dissector = udp_port_table:get_dissector(4729)

udp_port_table:add(47290, ip_dissector)
udp_port_table:add(4729, gsmtap_wrapper_proto)
