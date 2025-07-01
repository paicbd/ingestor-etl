import os.path
import sys
import struct
from models import Gtp, Base, IngestionQueue
import database

PCAP_GLOBAL_HDR_LEN = 24
PCAP_PKT_HDR_LEN = 16
SCTP_DATA_HEADER_LEN = 16
SCTP_HEADER_LEN = 12
M3UA_HEADER_LEN = 8
PACKET_START_INDEX = 8
PACKET_END_INDEX = 1500
MSISDN_IMSI_SEARCH_LEN = 280
MSISDN_START_PATTERN = '4c000600'
IMSI_MESSAGES = [16, 18]
MSISDN_MESSAGES = [32, 35]

dlt_map = {0: (lambda p: p[0:4] == b'\x02\x00\x00\x00', 4),  # NULL
           1: (lambda p: p[12:14] == b'\x08\x00', 14),  # EN10MB
           109: (lambda p: p[0:4] == b'\x02\x00\x00\x00', 12),  # ENC
           113: (lambda p: p[14:16] == b'\x08\x00', 16),  # LINUX_SLL
           141: (lambda p: True, 0),  # MTP3 Q.704
           276: (lambda p: p[0:2] == b'\x08\x00', 20)}  # LINUX_SLL2


total_processed = 0
total_not_processed = 0
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


def copy_msisdn(gtp_temp_list):
    msisdn = ""
    for gtp in gtp_temp_list:
        if gtp.msisdn == None or gtp.msisdn == "":
            continue
        msisdn = gtp.msisdn

    if msisdn == None or msisdn == "":
        return gtp_temp_list

    for gtp in gtp_temp_list:
        gtp.msisdn = msisdn

    return gtp_temp_list


def copy_imsi(gtp_temp_list):
    imsi = ""
    for gtp in gtp_temp_list:
        if gtp.imsi == None or gtp.imsi == "":
            continue
        imsi = gtp.imsi

    if imsi == None or imsi == "":
        return gtp_temp_list

    for gtp in gtp_temp_list:
        gtp.imsi = imsi

    return gtp_temp_list


def get_gtp(frame, dlt, header, packet):
    if dlt_map[dlt][0](packet):
        dlt_length = dlt_map[dlt][1]
    else:
        return None

    gtp = Gtp()

    pcap_filename = filename
    time_epoch = header[0]
    useconds_epoch = header[1]

    start_index = 0

    # DLT length
    sll = packet[start_index:dlt_length]
    proto_type = struct.unpack("!H", sll[-2:])

    # 0x0800 = IPv4 (2048)
    # 0x0806 = ARP (2054)
    if proto_type == 2054:
        return None

    start_index += dlt_length

    # Calculating IPv4 header length
    ip_h_len, = struct.unpack("!B", packet[start_index:start_index + 1])
    ip_h_len = (ip_h_len & 15) * 4

    # IPv4 layer - 20-60 bytes
    ip_layer = packet[start_index:start_index + ip_h_len]
    start_index += ip_h_len

    # ip_len, = struct.unpack("!B", ip_layer[3:4])
    ip_len = int(ip_layer[2:4].hex(), 16)

    # Get protocol and check if it is UDP (17)
    protocol, = struct.unpack("!B", ip_layer[9:10])
    if protocol != 17:
        return None

    src_oct01, src_oct02, src_oct03, src_oct04 = struct.unpack("!4B", ip_layer[12:16])
    dst_oct01, dst_oct02, dst_oct03, dst_oct04 = struct.unpack("!4B", ip_layer[16:20])

    src_ip = f"{src_oct01}.{src_oct02}.{src_oct03}.{src_oct04}"
    dst_ip = f"{dst_oct01}.{dst_oct02}.{dst_oct03}.{dst_oct04}"

    udp_len = ip_len - ip_h_len
    udp_layer = packet[start_index:start_index + udp_len]

    # Calculating the UDP Payload Size
    start_index += 8
    payload_size = ip_len - (ip_h_len + 8)
    gtp_layer = packet[start_index:start_index + payload_size]

    # Getting GTP Version by flags
    gtp_flags, = struct.unpack("!B", gtp_layer[0:1])

    # Common Fields
    gtp.pcap_filename = pcap_filename
    gtp.frames_list = f"{frame}"
    gtp.time_epoch = time_epoch
    gtp.useconds_epoch = useconds_epoch
    gtp.src_ip = src_ip
    gtp.dst_ip = dst_ip

    # GTPv1 Ingestion
    if gtp_flags == 50:

        imsi_valid_len = [96, 168, 175]
        gtp.gtp_version = "GTPv1"

        gtp_message_type = gtp_layer[1:2].hex()
        gtp_message_type = int(gtp_message_type, 16)

        msg_dic = {"16": "Create PDP context request",
                   "17": "Create PDP context response",
                   "18": "Update PDP context request",
                   "19": "Update PDP context response",
                   "20": "Delete PDP context request",
                   "21": "Delete PDP context response",
                   "26": "Error indication"}

        gtp.gtp_message = msg_dic[str(gtp_message_type)]

        gtp_len, = struct.unpack("!B", gtp_layer[3:4])

        gtp_teid = gtp_layer[4:8].hex()
        gtp.gtp_teid = int(gtp_teid, 16)

        # Response message types got Causes
        if gtp_message_type in [17, 19, 21]:
            gtp_cause, = struct.unpack("!B", gtp_layer[13:14])
            if gtp_cause == 128:
                gtp.gtp_cause = "Request accepted"
            else:
                gtp.gtp_cause = "Unknown: " + str(gtp_cause)

        if gtp_message_type in IMSI_MESSAGES:
            gtp.imsi = get_imsi(gtp_message_type, packet)

        gtp_seq_number = gtp_layer[8:10].hex()
        gtp.gtp_seq_number = int(gtp_seq_number, 16)

        # Only payloads with a valid length got IMSI

        if gtp_len in imsi_valid_len and gtp_message_type != 16:
            cod = gtp_layer[13:21].hex()
            gtp.imsi = TBCD_decode(cod)

        return gtp

    # GTPv2 Ingestion
    if gtp_flags == 72:
        gtp.gtp_version = "GTPv2"
        gtp_message_type, = struct.unpack("!B", gtp_layer[1:2])

        msg_dic = {"32": "Create Session Request",
                   "33": "Create Session Response",
                   "34": "Modify Bearer Request",
                   "35": "Modify Bearer Response",
                   "36": "Delete Session Request",
                   "37": "Delete Session Response",
                   "38": "Change Notification Request",
                   "39": "Change Notification Response",
                   "64": "Modify Bearer Command",
                   "66": "Delete Bearer Command",
                   "95": "Create Bearer Request",
                   "96": "Create Bearer Response",
                   "97": "Update Bearer Request",
                   "98": "Update Bearer Response",
                   "99": "Delete Bearer Request",
                   "100": "Delete Bearer Response"}

        gtp.gtp_message = msg_dic[str(gtp_message_type)]

        gtp_teid = gtp_layer[4:8].hex()
        gtp.gtp_teid = int(gtp_teid, 16)

        gtp_seq_number = gtp_layer[8:11].hex()
        gtp.gtp_seq_number = int(gtp_seq_number, 16)

        # Responses
        if gtp_message_type in [33, 35, 37, 98]:
            gtp_cause, = struct.unpack("!B", gtp_layer[16:17])
            if gtp_cause == 16:
                gtp.gtp_cause = "Request accepted"
            else:
                gtp.gtp_cause = "Unknown: " + str(gtp_cause)

        if gtp_message_type in MSISDN_MESSAGES:
            gtp.msisdn = get_msisdn(gtp_message_type, packet, gtp_layer)

        return gtp
    return None


def get_imsi(gtp_message_type, packet):
    gtp_packet = packet[PACKET_START_INDEX:PACKET_END_INDEX]
    encoded_gtp_layer = gtp_packet[1:MSISDN_IMSI_SEARCH_LEN].hex()
    imsi_pattern = ''

    # String matching the imsi information in the packet is variable depending on the message_type
    match gtp_message_type:
        case 16:
            imsi_pattern = '3210'
        case 18:
            imsi_pattern = '3212'

    # Getting the imsi packet information
    imsi_index = encoded_gtp_layer.find(imsi_pattern) + 26

    # Getting the imsi raw value, then it is decoded
    raw_imsi = encoded_gtp_layer[imsi_index: imsi_index + 16]
    imsi = TBCD_decode(raw_imsi)
    has_imsi = len(imsi) > 10
    if has_imsi:
        return imsi


def get_msisdn(gtp_message_type, packet, gtp_layer):
    gtp_packet = packet[PACKET_START_INDEX:PACKET_END_INDEX]
    encoded_gtp_layer = gtp_packet[100:MSISDN_IMSI_SEARCH_LEN].hex()

    # MSISDN value search is variable depending on the message_type
    match gtp_message_type:
        case 32:
            str_msisdn = MSISDN_START_PATTERN
            msisdn_index = encoded_gtp_layer.find(str_msisdn) + 8
            return TBCD_decode(encoded_gtp_layer[msisdn_index: msisdn_index + 12])
        case 35:
            return TBCD_decode(gtp_layer[22:28].hex())


def TBCD_decode(input):
    offset = 0
    output = ''
    while offset < len(input):
        if "f" not in input[offset:offset + 2]:
            bit = input[offset:offset + 2]  # Get two digits at a time
            bit = bit[::-1]  # Reverse them
            output = output + bit
            offset = offset + 2
        else:  # If f in bit strip it
            bit = input[offset:offset + 2]
            output = output + bit[1]
            return output
    return output


def process_pcap(pcap_file, pcap_global_hdr, endian):
    frame = 0
    gtp_frames = 0
    not_processed = 0
    key = 0
    gtp_dict = {}
    gtp_tmp_list = []
    gtp_list = []

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

            gtp = get_gtp(frame, dlt, header, packet)

            if gtp == None:
                continue
        except Exception:
            # print(f"frame {frame} not processed of the PCAP file {filename}")
            not_processed += 1
            continue
        gtp_frames += 1
        key = gtp.gtp_seq_number
        temp = gtp_dict.get(key)
        if temp != None:
            gtp_tmp_list = temp
        gtp_tmp_list.append(gtp)
        gtp_dict[key] = gtp_tmp_list

        gtp_tmp_list = []

    for key in gtp_dict.keys():
        value = gtp_dict.get(key)
        if len(value) > 1:
            value = copy_msisdn(value)
            value = copy_imsi(value)
        gtp_list.extend(value)
        if len(gtp_list) >= 1000:
            db.bulk_save_objects(gtp_list)
            db.commit()
            gtp_list.clear()
    if len(gtp_list) > 0:
        db.bulk_save_objects(gtp_list)
        db.commit()
    print(f"{gtp_frames} processed / {not_processed} NOT processed GTP frames out of {frame} packets in the PCAP file {filename}.")
    global total_processed
    total_processed = gtp_frames
    global total_not_processed
    total_not_processed = not_processed


def process_pcapng(pcapng_file, pcap_global_hdr, endian):
    frame = 0
    gtp_frames = 0
    not_processed = 0
    key = 0
    gtp_dict = {}
    gtp_tmp_list = []
    gtp_list = []

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

            gtp = get_gtp(frame, dlt, header, packet)

            if gtp == None:
                continue
        except Exception:
            # print(f"frame {frame} not processed of the PCAPNG file {filename}")
            not_processed += 1
            continue
        gtp_frames += 1
        key = gtp.gtp_seq_number
        temp = gtp_dict.get(key)
        if temp != None:
            gtp_tmp_list = temp
        gtp_tmp_list.append(gtp)
        gtp_dict[key] = gtp_tmp_list

        gtp_tmp_list = []

    for key in gtp_dict.keys():
        value = gtp_dict.get(key)
        if len(value) > 1:
            value = copy_msisdn(value)
            value = copy_imsi(value)
        gtp_list.extend(value)
        if len(gtp_list) >= 1000:
            db.bulk_save_objects(gtp_list)
            db.commit()
            gtp_list.clear()
    if len(gtp_list) > 0:
        db.bulk_save_objects(gtp_list)
        db.commit()
    print(f"{gtp_frames} processed / {not_processed} NOT processed GTP frames out of {frame} packets in the PCAPNG file {filename}.")

    global total_processed
    total_processed = gtp_frames
    global total_not_processed
    total_not_processed = not_processed


if len(sys.argv) < 3:
    raise Exception("The pcap or pcapng file parameter was not specified")
filename = sys.argv[1]

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
            process_pcap(pcap_file, pcap_global_hdr, endian)
        elif format == "PCAPNG":
            process_pcapng(pcap_file, pcap_global_hdr, endian)

    with database.get_db_ingestion() as db2:
        ingestion_id = sys.argv[2]
        db2.query(IngestionQueue).filter(IngestionQueue.id == ingestion_id).update({'processed': total_processed, 'not_processed': total_not_processed})
        db2.commit()
