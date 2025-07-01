import os.path
import sys
import re
import struct
from models import Sip, Base, IngestionQueue
import database

PCAP_GLOBAL_HDR_LEN = 24
PCAP_PKT_HDR_LEN = 16
SCTP_DATA_HEADER_LEN = 16
SCTP_HEADER_LEN = 12
M3UA_HEADER_LEN = 8

ICE_IPS = [
    "10.10.200.146",
    "10.10.200.151",
    "10.20.200.146",
    "10.20.200.151"
]

POWER_NOVA_IPS = [
    "10.10.200.148",
    "10.20.200.148"
]

POWER_MEDIA_IPS = [
    "10.10.200.104",
    "10.20.200.104"
]

methods = [
    "INVITE",
    "ACK",
    "PRACK",
    "INFO",
    "BYE",
    "CANCEL",
    "REGISTER",
    "UPDATE"
]

header_fields = [
    "Call-ID",
    "i",
    "From",
    "f",
    "To",
    "t",
    "Supported",
    "k",
    "Require"
]

dlt_map = {0:   (lambda p: p[0:4]   == b'\x02\x00\x00\x00',  4),  # NULL
            1:   (lambda p: p[12:14] == b'\x08\x00',         14), # EN10MB
            109: (lambda p: p[0:4]   == b'\x02\x00\x00\x00', 12), # ENC
            113: (lambda p: p[14:16] == b'\x08\x00',         16), # LINUX_SLL
            141: (lambda p: True,                            0),  # MTP3 Q.704
            276: (lambda p: p[0:2]   == b'\x08\x00',         20)} # LINUX_SLL2

sip_incomplete_payload = {}
sip_packets = {}
sip_call_ids = {}
sip_sdp_owners_ice = {}
sip_sdp_owners_pm = {}

total_processed = 0
total_not_processed = 0


class SIPKey:
    src_ip = ""
    dst_ip = ""
    identification = 0

    def __init__(self, src_ip, dst_ip, identification):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.identification = identification

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.dst_ip == other.dst_ip \
                and self.src_ip == other.src_ip \
                and self.identification == other.identification
        return False

    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.identification))


def get_format_and_endian(pcap_global_hdr):
    if pcap_global_hdr[0:4] == b'\xd4\xc3\xb2\xa1':
        return "PCAP", "<"
    elif pcap_global_hdr[0:4] == b'\xa1\xb2\xc3\xd4':
        return "PCAP", ">"
    elif pcap_global_hdr[0:4] == b'\x0a\x0d\x0d\x0a':
        if pcap_global_hdr[8:12] == b'\x4d\x3c\x2b\x1a':
            return "PCAPNG", "<"
        elif pcap_global_hdr[8:12] == b'\x1a\x2b\x3c\x4d':
            return "PCAPNG", ">"
    raise Exception("The format of the file is not supported")


def get_sip(frame, dlt, header, packet, ttype):
    if dlt_map[dlt][0](packet):
        dlt_length = dlt_map[dlt][1]
    else:
        return True, None
    
    sip = Sip()

    pcap_filename = filename_orig
    time_epoch = header[0]
    useconds_epoch = header[1]

    start_index = 0

    # DLT length
    sll = packet[start_index:dlt_length]
    proto_type = struct.unpack("!H", sll[-2:])

    # 0x0800 = IPv4 (2048)
    # 0x0806 = ARP (2054)
    if proto_type == 2054:
        return True, None
    
    start_index += dlt_length

    # Calculating IPv4 header length
    ip_h_len, = struct.unpack("!B", packet[start_index:start_index + 1])
    ip_h_len = (ip_h_len & 15) * 4

    # IPv4 layer - 20-60 bytes
    ip_layer = packet[start_index:start_index + ip_h_len]
    start_index += ip_h_len
    
    # Geetting the IP total length
    ip_len, = struct.unpack("!H", ip_layer[2:4])

    # Get protocol and check if it is TCP (6)
    protocol, = struct.unpack("!B", ip_layer[9:10])
    if protocol != 17:
        return True, None

    src_oct01, src_oct02, src_oct03, src_oct04 = struct.unpack("!4B", ip_layer[12:16])
    dst_oct01, dst_oct02, dst_oct03, dst_oct04 = struct.unpack("!4B", ip_layer[16:20])

    src_ip = f"{src_oct01}.{src_oct02}.{src_oct03}.{src_oct04}"
    dst_ip = f"{dst_oct01}.{dst_oct02}.{dst_oct03}.{dst_oct04}"

    udp_layer = packet[start_index:start_index + 8]
    src_port, dst_port = struct.unpack("!2H", udp_layer[0:4])
    
    if src_port == 53 or dst_port == 53:
        return True, None

    start_index += 8
    
    # Calculating the UDP Payload Size
    payload_size = ip_len - (ip_h_len + 8)

    # sip Payload
    sip_layer = packet[start_index:start_index + payload_size]
    try:
        sip_layer = sip_layer.decode('utf-8')
        identification = int(ip_layer[4:6].hex(), 16)
        sipKey = SIPKey(src_ip, dst_ip, identification)

        frames_list = f"{frame}"

        if len(sip_incomplete_payload) > 0:
            sip_incomplete_payload_value = sip_incomplete_payload.get(sipKey)

            if sip_incomplete_payload_value != None:
                sip_layer = sip_incomplete_payload_value[0] + sip_layer
                frames_list = sip_incomplete_payload_value[1] + " " + frames_list

                sip_incomplete_payload.pop(sipKey, None)

        complete = ip_layer[6:7].hex() != '20'

        if not complete:
            sip_incomplete_payload[sipKey] = [sip_layer, frames_list]
            return False, None

        sip.pcap_filename = pcap_filename
        sip.frames_list = f"{frame}" if frames_list == "" else frames_list
        sip.time_epoch = time_epoch
        sip.useconds_epoch = useconds_epoch
        sip.src_ip = src_ip
        sip.dst_ip = dst_ip
        sipKey = None

    except Exception as e:
        # This is not a SIP packet
        # traceback.print_exc()
        return True, None
    sip_layer = sip_layer.splitlines()
        
    if len(sip_layer) < 2:
        return True, None

    sip_h = sip_layer[0].split()[0]
    
    # Common Fields
    sip.pcap_filename = pcap_filename

    has_sdp_owner = False

    # Parsing Methods
    if sip_h in methods:
        sip.method = sip_h
        for header in sip_layer:
            if ttype == "PN" and header[0:2] == "o=":
                sdp_owner = header[2:]
                sdp_owner_params = sdp_owner.split(" ")
                if len(sdp_owner_params) >= 3:
                    has_sdp_owner = True
                    sip.sdp_o_sessionid = sdp_owner_params[1]
                    sip.sdp_o_version = sdp_owner_params[2]
            sip_header = header.split(":")
            if len(sip_header) < 2:
                continue
            
            sip_h_key = sip_header[0]
            sip_h_value = sip_header[1].strip()
            
            if sip_h_key in header_fields:
                match sip_h_key:
                    case "From":
                        sip_from_user = re.search(r'(sip|tel):.\w+', header)[0]
                        sip.from_user = sip_from_user.split(":")[1]
                        if re.fullmatch(r"^[0-9]{13}$", sip.from_user):
                            sip.from_original = sip.from_user
                            sip.from_user = sip.from_user[4:]
                    case "f":
                        sip_from_user = re.search(r'(sip|tel):.\w+', header)[0]
                        sip.from_user = sip_from_user.split(":")[1]
                        if re.fullmatch(r"^[0-9]{13}$", sip.from_user):
                            sip.from_original = sip.from_user
                            sip.from_user = sip.from_user[4:]
                    case "To":
                        sip_to_user = re.search(r'(sip|tel):.\w+', header)[0]
                        sip.to_user = sip_to_user.split(":")[1]
                        if re.fullmatch(r"^[0-9]{13}$", sip.to_user):
                            sip.to_original = sip.to_user
                            sip.to_user = sip.to_user[4:]
                    case "t":
                        sip_to_user = re.search(r'(sip|tel):.\w+', header)[0]
                        sip.to_user = sip_to_user.split(":")[1]
                        if re.fullmatch(r"^[0-9]{13}$", sip.to_user):
                            sip.to_original = sip.to_user
                            sip.to_user = sip.to_user[4:]
                    case "Call-ID":
                        sip.call_id = sip_h_value
                    case "i":
                        sip.call_id = sip_h_value
                    case "Require":
                        sip.require = sip_h_value
                    case "Supported":
                        sip.supported = sip_h_value
                    case "k":
                        sip.supported = sip_h_value
                    case _:
                        pass
        # return True, sip
    # Parsing Responses
    elif sip_h == 'SIP/2.0':
        sip.status_line = sip_layer[0]
        sip.status_code = int(sip_layer[0].split(" ")[1])
        for header in sip_layer:
            if ttype == "PN" and header[0:2] == "o=":
                sdp_owner = header[2:]
                sdp_owner_params = sdp_owner.split(" ")
                if len(sdp_owner_params) >= 3:
                    has_sdp_owner = True
                    sip.sdp_o_sessionid = sdp_owner_params[1]
                    sip.sdp_o_version = sdp_owner_params[2]
            sip_header = header.split(":")
            if len(sip_header) < 2:
                continue
            
            sip_h_key = sip_header[0]
            sip_h_value = sip_header[1].strip()
            
            if sip_h_key in header_fields:
                match sip_h_key:
                    case "From":
                        sip_from_user = re.search(r'(sip|tel):.\w+', header)[0]
                        sip.from_user = sip_from_user.split(":")[1]
                        if re.fullmatch(r"^[0-9]{13}$", sip.from_user):
                            sip.from_original = sip.from_user
                            sip.from_user = sip.from_user[4:]
                    case "f":
                        sip_from_user = re.search(r'(sip|tel):.\w+', header)[0]
                        sip.from_user = sip_from_user.split(":")[1]
                        if re.fullmatch(r"^[0-9]{13}$", sip.from_user):
                            sip.from_original = sip.from_user
                            sip.from_user = sip.from_user[4:]
                    case "To":
                        sip_to_user = re.search(r'(sip|tel):.\w+', header)[0]
                        sip.to_user = sip_to_user.split(":")[1]
                        if re.fullmatch(r"^[0-9]{13}$", sip.to_user):
                            sip.to_original = sip.to_user
                            sip.to_user = sip.to_user[4:]
                    case "t":
                        sip_to_user = re.search(r'(sip|tel):.\w+', header)[0]
                        sip.to_user = sip_to_user.split(":")[1]
                        if re.fullmatch(r"^[0-9]{13}$", sip.to_user):
                            sip.to_original = sip.to_user
                            sip.to_user = sip.to_user[4:]
                    case "Call-ID":
                        sip.call_id = sip_h_value
                    case "i":
                        sip.call_id = sip_h_value
                    case "Require":
                        sip.require = sip_h_value
                    case "Supported":
                        sip.supported = sip_h_value
                    case "k":
                        sip.supported = sip_h_value
                    case _:
                        pass
        # return True, sip
    else:
        # print(f"The SIP method {sip_h} in frame {frame} is not allowed")
        raise Exception(f"The SIP method {sip_h} in frame {frame} is not allowed")
    
    sip_packets[frame] = sip

    sip_call_list = []
    sip_call_list = sip_call_ids.get(sip.call_id)
    if sip_call_list == None:
        sip_call_list = []
    sip_call_list.append(frame)
    sip_call_ids[sip.call_id] = sip_call_list

    if has_sdp_owner:
        sdp_owner_key = sip.sdp_o_sessionid + " " + sip.sdp_o_version
        if not (sdp_owner_key == "0 0"):
            sdp_owner_call_list = []
            if (sip.src_ip in POWER_NOVA_IPS and sip.dst_ip in POWER_MEDIA_IPS) or \
                (sip.src_ip in POWER_MEDIA_IPS and sip.dst_ip in POWER_NOVA_IPS):
                sdp_owner_call_list = sip_sdp_owners_pm.get(sdp_owner_key)
                if sdp_owner_call_list == None:
                    sdp_owner_call_list = []
                sdp_owner_call_list.append(sip.call_id)
                sip_sdp_owners_pm[sdp_owner_key] = sdp_owner_call_list
            elif (sip.src_ip in POWER_NOVA_IPS and sip.dst_ip in ICE_IPS) or \
                (sip.src_ip in ICE_IPS and sip.dst_ip in POWER_NOVA_IPS):
                sdp_owner_call_list = sip_sdp_owners_ice.get(sdp_owner_key)
                if sdp_owner_call_list == None:
                    sdp_owner_call_list = []
                sdp_owner_call_list.append(sip.call_id)
                sip_sdp_owners_ice[sdp_owner_key] = sdp_owner_call_list
    return True, None


def process_pcap(pcap_file, pcap_global_hdr, endian, ttype):
    frame = 0
    sip_frames = 0
    not_processed = 0
    sip_list = []

    dlt, = struct.unpack(endian + "I", pcap_global_hdr[20:24])
    if dlt not in dlt_map:
        raise Exception(f"The dlt {dlt} is not supported")

    while True:
        try:
            # packet header
            pkt_hdr = pcap_file.read(PCAP_PKT_HDR_LEN)
            if len(pkt_hdr) != PCAP_PKT_HDR_LEN:
                break
            frame += 1

            # ts_sec, ts_usec, pkt_len, orig_len
            header = struct.unpack(endian + "4I", pkt_hdr)

            header = list(header)
            if len(str(header[1])) >= 6:
                header[1] = int(str(header[1])[0:6])
            header = tuple(header)

            # packet
            packet = pcap_file.read(header[2])

            complete, = get_sip(frame, dlt, header, packet, ttype)

            if not complete:
                continue
        except Exception:
            # print(f"frame {frame} not processed of the PCAP file {filename}")
            not_processed += 1
            continue
        sip_frames += 1
    print(f"sip_sdp_owners_pm has {len(sip_sdp_owners_pm)} sip_sdp_owners_ice has {len(sip_sdp_owners_ice)}")
    for key in sip_sdp_owners_pm.keys():
        pm_call_list = []
        pm_call_list = sip_sdp_owners_pm.get(key)
        ice_call_list = []
        ice_call_list = sip_sdp_owners_ice.get(key)
        if ice_call_list == None:
            print("ICE CALL LIST IS NONE")
            continue
        ice_call_id = ice_call_list[0];
        print(f"the key {key} has {pm_call_list} Power Media calls and {ice_call_list} ICE calls")
        for call_id in pm_call_list:
            sip_ice_call_list = []
            sip_ice_call_list = sip_call_ids.get(ice_call_id)
            sip_ice_call_frame = sip_ice_call_list[0]
            sip_ice = sip_packets.get(sip_ice_call_frame)
            if sip_ice == None:
                print(f"Something happens with the frame {sip_ice_call_frame}")
                continue
            sip_pm_call_list = []
            sip_pm_call_list = sip_call_ids.get(call_id)
            for sip_frame in sip_pm_call_list:
                sip_pm = sip_packets.get(sip_frame)
                if sip_pm == None:
                    print(f"Something happens with the frame {sip_frame}")
                    continue
                if not sip_pm.from_user == sip_ice.from_user:
                    sip_pm.from_original = sip_pm.from_user
                    sip_pm.from_user = sip_ice.from_user
                if not sip_pm.to_user == sip_ice.to_user:
                    sip_pm.to_original = sip_pm.to_user
                    sip_pm.to_user = sip_ice.to_user
                if sip_pm.method == "INVITE" and sip_pm.sdp_o_sessionid == "0" and sip_pm.sdp_o_version == "0":
                    sdp_owner_params = key.split(" ")
                    sip_pm.sdp_o_sessionid = sdp_owner_params[0]
                    sip_pm.sdp_o_version = sdp_owner_params[1]
    sip_list = list(sip_packets.values())
    print(f"sip_list length to be stored are {len(sip_list)}")
    i = 0
    while i < len(sip_list):
        diff = len(sip_list) - i
        if diff < 1000:
            db.bulk_save_objects(sip_list[i:i + diff], return_defaults = True)
            i += diff
        else:
            db.bulk_save_objects(sip_list[i:i + 1000], return_defaults = True)
            i += 1000
        db.commit()
    print(f"{sip_frames} processed / {not_processed} NOT processed SIP frames out of {frame} packets in the PCAP file {filename}.")

    global total_processed
    total_processed = sip_frames
    global total_not_processed
    total_not_processed = not_processed


def process_pcapng(pcapng_file, pcap_global_hdr, endian, ttype):
    frame = 0
    sip_frames = 0
    not_processed = 0
    sip_list = []

    # Section Header Block, as first block of the pcapng file
    # https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html#name-section-header-block-format
    block_len, = struct.unpack(endian + "I", pcap_global_hdr[4:8])
    section_hdr_block = pcap_global_hdr + pcapng_file.read(block_len - PCAP_GLOBAL_HDR_LEN)

    # Interface Description Block (block type = 1), as second block of the pcap file
    # https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html#name-interface-description-block-
    block_hdr = pcapng_file.read(8)
    block_type, block_len = struct.unpack(endian + "2I", block_hdr)
    if_description_block = block_hdr + pcapng_file.read(block_len - 8)
    dlt, = struct.unpack(endian + "H", if_description_block[8:10])
    # if_tsresol = 6, by default described on https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html#section-4.2-24.2.1
    if_tsresol = 6
    #   Options of Interface Description Block
    #   If Options is present in the block
    if block_len > 20:
        idb_options = if_description_block[16:block_len - 4]
        idb_idx = 0
        while True:
            if idb_idx >= len(idb_options):
                break
            option, option_len = struct.unpack(endian + "2H", idb_options[idb_idx:idb_idx + 4])
            if option == 9:
                if_tsresol, = struct.unpack(endian + "B", idb_options[idb_idx + 4: idb_idx + 4 + option_len])
            option_len += 0 if (option_len % 4) == 0 else 4 - (option_len % 4)
            idb_idx = idb_idx + 4 + option_len

    if dlt not in dlt_map:
        raise Exception(f"The dlt {dlt} is not supported")

    while True:
        # Looping the Enhanced Packet Block (block type = 6)
        # https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html#name-enhanced-packet-block
        try:
            block_hdr = pcapng_file.read(8)
            if len(block_hdr) != 8:
                break

            block_type, block_len = struct.unpack(endian + "2I", block_hdr)
            if not block_type == 6:
                pcapng_file.read(block_len - 8)
                continue

            frame += 1

            enhanced_pkt_block = block_hdr + pcapng_file.read(block_len - 8)
            
            # ts_higher, ts_lower, pkt_len, orig_len
            header = struct.unpack(endian + "4I", enhanced_pkt_block[12:28])
            ts_higher = struct.pack((">" if endian == "<" else endian) + "I", header[0])
            ts_lower = struct.pack((">" if endian == "<" else endian) + "I", header[1])
            ts, = struct.unpack((">" if endian == "<" else endian) + "Q", ts_higher + ts_lower)

            e_seconds = int(str(ts)[0:10])
            multiple_sec = 0
            if len(str(ts)[10:]) >= 6:
                multiple_sec = int(str(ts)[10:16])

            header = list(header)
            # header[0] = int(str(ts)[0:-1 * if_tsresol])
            header[0] = e_seconds
            # header[1] = int(str(ts)[-1 * if_tsresol:])
            header[1] = multiple_sec
            header = tuple(header)

            # packet
            packet = enhanced_pkt_block[28:28 + header[3]]

            complete, = get_sip(frame, dlt, header, packet, ttype)

            if not complete:
                continue
        except Exception:
            # print(f"frame {frame} not processed of the PCAPNG file {filename}")
            not_processed += 1
            continue
        sip_frames += 1
    print(f"sip_sdp_owners_pm has {len(sip_sdp_owners_pm)} sip_sdp_owners_ice has {len(sip_sdp_owners_ice)}")
    for key in sip_sdp_owners_pm.keys():
        pm_call_list = []
        pm_call_list = sip_sdp_owners_pm.get(key)
        ice_call_list = []
        ice_call_list = sip_sdp_owners_ice.get(key)
        if ice_call_list == None:
            print("ICE CALL LIST IS NONE")
            continue
        ice_call_id = ice_call_list[0];
        print(f"the key {key} has {pm_call_list} Power Media calls and {ice_call_list} ICE calls")
        for call_id in pm_call_list:
            sip_ice_call_list = []
            sip_ice_call_list = sip_call_ids.get(ice_call_id)
            sip_ice_call_frame = sip_ice_call_list[0]
            sip_ice = sip_packets.get(sip_ice_call_frame)
            if sip_ice == None:
                print(f"Something happens with the frame {sip_ice_call_frame}")
                continue
            sip_pm_call_list = []
            sip_pm_call_list = sip_call_ids.get(call_id)
            for sip_frame in sip_pm_call_list:
                sip_pm = sip_packets.get(sip_frame)
                if sip_pm == None:
                    print(f"Something happens with the frame {sip_frame}")
                    continue
                if not sip_pm.from_user == sip_ice.from_user:
                    sip_pm.from_original = sip_pm.from_user
                    sip_pm.from_user = sip_ice.from_user
                if not sip_pm.to_user == sip_ice.to_user:
                    sip_pm.to_original = sip_pm.to_user
                    sip_pm.to_user = sip_ice.to_user
                if sip_pm.method == "INVITE" and sip_pm.sdp_o_sessionid == "0" and sip_pm.sdp_o_version == "0":
                    sdp_owner_params = key.split(" ")
                    sip_pm.sdp_o_sessionid = sdp_owner_params[0]
                    sip_pm.sdp_o_version = sdp_owner_params[1]
    sip_list = list(sip_packets.values())
    print(f"sip_list length to be stored are {len(sip_list)}")
    i = 0
    while i < len(sip_list):
        diff = len(sip_list) - i
        if diff < 1000:
            db.bulk_save_objects(sip_list[i:i + diff], return_defaults = True)
            i += diff
        else:
            db.bulk_save_objects(sip_list[i:i + 1000], return_defaults = True)
            i += 1000
        db.commit()
    print(f"{sip_frames} processed / {not_processed} NOT processed SIP frames out of {frame} packets in the PCAPNG file {filename}.")

    global total_processed
    total_processed = sip_frames
    global total_not_processed
    total_not_processed = not_processed


if len(sys.argv) < 5:
    raise Exception("The pcap or pcapng file parameter was not specified")
filename = sys.argv[1]
filename_orig = sys.argv[2]
ttype = sys.argv[3] # traffic type

if not os.path.exists(filename):
    raise Exception("The pcap or pcapng file does not exist")

Base.metadata.create_all(database.engine)

with open(filename, "rb") as pcap_file:
    pcap_global_hdr = pcap_file.read(PCAP_GLOBAL_HDR_LEN)

    if len(pcap_global_hdr) != PCAP_GLOBAL_HDR_LEN:
        raise Exception("The size of the file is too short")

    format, endian = get_format_and_endian(pcap_global_hdr)
    print(f"The {filename} has {format} format")
    
    with database.get_db() as db:
        if format == "PCAP":
            process_pcap(pcap_file, pcap_global_hdr, endian, ttype)
        elif format == "PCAPNG":
            process_pcapng(pcap_file, pcap_global_hdr, endian, ttype)

    with database.get_db_ingestion() as db2:
        ingestion_id = sys.argv[4]
        db2.query(IngestionQueue).filter(IngestionQueue.id == ingestion_id).update(
            {'processed': total_processed, 'not_processed': total_not_processed})
        db2.commit()
