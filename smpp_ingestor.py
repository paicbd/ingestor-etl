import os.path
import sys
import struct

from sqlalchemy.orm import sessionmaker

from models import Smpp, Base, IngestionQueue
import database
from binascii import hexlify
import io
from smpp.pdu.pdu_encoding import PDUEncoder
import traceback

PCAP_GLOBAL_HDR_LEN = 24
PCAP_PKT_HDR_LEN = 16
SCTP_DATA_HEADER_LEN = 16
SCTP_HEADER_LEN = 12
M3UA_HEADER_LEN = 8

dlt_map = {0:   (lambda p: p[0:4]   == b'\x02\x00\x00\x00',  4),  # NULL
            1:   (lambda p: p[12:14] == b'\x08\x00',         14), # EN10MB
            109: (lambda p: p[0:4]   == b'\x02\x00\x00\x00', 12), # ENC
            113: (lambda p: p[14:16] == b'\x08\x00',         16), # LINUX_SLL
            141: (lambda p: True,                            0),  # MTP3 Q.704
            276: (lambda p: p[0:2]   == b'\x08\x00',         20)} # LINUX_SLL2


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


def get_smpp(frame, dlt, header, packet):
    if dlt_map[dlt][0](packet):
        dlt_length = dlt_map[dlt][1]
    else:
        return None
    
    smpp_list = []

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
    
    # Geetting the IP total length
    ip_len, = struct.unpack("!H", ip_layer[2:4])

    # Get protocol and check if it is TCP (6)
    protocol, = struct.unpack("!B", ip_layer[9:10])
    if protocol != 6:
        return None

    src_oct01, src_oct02, src_oct03, src_oct04 = struct.unpack("!4B", ip_layer[12:16])
    dst_oct01, dst_oct02, dst_oct03, dst_oct04 = struct.unpack("!4B", ip_layer[16:20])

    src_ip = f"{src_oct01}.{src_oct02}.{src_oct03}.{src_oct04}"
    dst_ip = f"{dst_oct01}.{dst_oct02}.{dst_oct03}.{dst_oct04}"

    tcp_len, = struct.unpack("!B", packet[start_index + 12:start_index + 13])
    tcp_len = (tcp_len >> 4) * 4
    
    tcp_layer = packet[start_index:start_index + tcp_len]
        
    tcp_flags, = struct.unpack("!B", tcp_layer[13:14])

    src_port = int(tcp_layer[0:2].hex(), 16)
    dst_port = int(tcp_layer[2:4].hex(), 16)

    if tcp_flags != 24:
        return None

    start_index += tcp_len
    
    # Calculating the TCP Payload Size
    payload_size = ip_len - (ip_h_len + tcp_len)

    while (start_index + 4) < len(packet):
        smpp_length, = struct.unpack("!I", packet[start_index:start_index + 4])

        if smpp_length > payload_size:
            break
        # SMPP Payload
        smpp_layer = packet[start_index:start_index + smpp_length]

        # Decoding the Smpp Payload
        file = io.BytesIO(smpp_layer)
        pdu = None
        try:
            pdu = PDUEncoder().decode(file)
        except Exception as e:
            # print(f"{frame} {e}")
            # traceback.print_exc()
            pass

        if pdu.sequence_number >= 0:
            smpp = Smpp()
            if pdu.command_id == 'submit_sm' or pdu.command_id == 'data_sm' or pdu.command_id == 'deliver_sm':
                smpp.pcap_filename = pcap_filename
                smpp.frames_list = f"{frame}"
                smpp.time_epoch = time_epoch
                smpp.useconds_epoch = useconds_epoch
                smpp.src_ip = src_ip
                smpp.dst_ip = dst_ip
                smpp.command_id = pdu.command_id
                smpp.sequence_number = pdu.sequence_number
                smpp.source_addr = pdu.params['source_addr']
                smpp.destination_addr = pdu.params['destination_addr']
                smpp.src_port = src_port
                smpp.dst_port = dst_port
                smpp_list.append(smpp)
            elif pdu.command_id == 'submit_sm_resp' or pdu.command_id == 'deliver_sm_resp' or pdu.command_id == 'data_sm_resp':
                smpp.pcap_filename = pcap_filename
                smpp.frames_list = f"{frame}"
                smpp.time_epoch = time_epoch
                smpp.useconds_epoch = useconds_epoch
                smpp.src_ip = src_ip
                smpp.dst_ip = dst_ip
                smpp.command_id = pdu.command_id
                smpp.sequence_number = pdu.sequence_number
                smpp.command_status = pdu.status
                smpp.src_port = src_port
                smpp.dst_port = dst_port
                smpp_list.append(smpp)
            start_index += smpp_length
        else:
            return None

    if smpp_list == None or len(smpp_list) == 0:
        return None
    
    return smpp_list


def process_pcap(pcap_file, pcap_global_hdr, endian):
    frame = 0
    smpp_frames = 0
    not_processed = 0
    smpp_list = []

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

            smpp = get_smpp(frame, dlt, header, packet)

            if smpp == None or len(smpp) == 0:
                continue
        except Exception:
            # print(f"frame {frame} not processed of the PCAP file {filename}")
            not_processed += 1
            continue
        smpp_frames += len(smpp)
        smpp_list.extend(smpp)
        if len(smpp_list) >= 1000:
            db.bulk_save_objects(smpp_list)
            db.commit()
            smpp_list.clear()
    if len(smpp_list) > 0:
        db.bulk_save_objects(smpp_list)
        db.commit()

    global total_processed
    total_processed = smpp_frames
    global total_not_processed
    total_not_processed = not_processed

    print(f"{smpp_frames} processed / {not_processed} NOT processed SMPP frames out of {frame} packets in the PCAP file {filename}.")


def process_pcapng(pcapng_file, pcap_global_hdr, endian):
    frame = 0
    smpp_frames = 0
    not_processed = 0
    smpp_list = []
    smpp_dict = {}
    aux_smpp_list = []

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

            smpp = get_smpp(frame, dlt, header, packet)

            if smpp == None or len(smpp) == 0:
                continue
        except Exception:
            # print(f"frame {frame} not processed of the PCAPNG file {filename}")
            not_processed += 1
            continue
        smpp_frames += len(smpp)

        current_smpp = smpp[0] if len(smpp) == 1 else smpp[len(smpp) - 1]
        src_key_ports, dst_key_ports = get_smpp_key_ports(current_smpp)
        src_key_ips, dst_key_ips = get_smpp_key_ips(current_smpp)

        for current_chunk in smpp:
            key = f"{src_key_ips}{src_key_ports}{dst_key_ips}{dst_key_ports}{current_chunk.sequence_number}"

            aux_smpp = smpp_dict.get(key)

            if aux_smpp is not None:
                aux_smpp_list = aux_smpp

            aux_smpp_list.append(current_chunk)
            smpp_dict[key] = aux_smpp_list
            aux_smpp_list = []

    for key in smpp_dict.keys():
        value = smpp_dict.get(key)

        if len(value) > 1:
            value = copy_src_addr(value)
            value = copy_dst_addr(value)

        # To avoid saving a multiple traces with the same frame_list for reassembled cases
        found = False
        for frame_value in value:
            for smpp_in_list in smpp_list:
                if smpp_in_list.frames_list == frame_value.frames_list:
                    found = True
                    break

        if not found:
            smpp_list.extend(value)

        if len(smpp_list) >= 1000:
            db.bulk_save_objects(smpp_list)
            db.commit()
            smpp_list.clear()
    if len(smpp_list) > 0:
        db.bulk_save_objects(smpp_list)
        db.commit()
    print(f"{smpp_frames} processed / {not_processed} NOT processed SMPP frames out of {frame} packets in the PCAPNG file {filename}.")

    global total_processed
    total_processed = smpp_frames
    global total_not_processed
    total_not_processed = not_processed

def get_smpp_key_ports(current_smpp):

    src_key_port = current_smpp.src_port if (
                current_smpp.command_id == "submit_sm" or current_smpp.command_id == "deliver_sm") \
        else current_smpp.dst_port

    dst_key_port = current_smpp.dst_port if (
                current_smpp.command_id == "submit_sm" or current_smpp.command_id == "deliver_sm") \
        else current_smpp.src_port

    return src_key_port, dst_key_port


def get_smpp_key_ips(current_smpp):

    src_key_ip = current_smpp.src_ip if (current_smpp.command_id == "submit_sm" or current_smpp.command_id == "deliver_sm") \
        else current_smpp.dst_ip

    dst_key_ip = current_smpp.dst_ip if (current_smpp.command_id == "submit_sm" or current_smpp.command_id == "deliver_sm") \
        else current_smpp.src_ip

    return src_key_ip, dst_key_ip


def copy_src_addr(smpp_temp_list):
    source_addr = ""
    for smpp in smpp_temp_list:
        if smpp.source_addr == None or smpp.source_addr == "":
            continue
        source_addr = smpp.source_addr

    if source_addr == None or source_addr == "":
        return smpp_temp_list

    for smpp in smpp_temp_list:
        smpp.source_addr = source_addr

    return smpp_temp_list


def copy_dst_addr(smpp_temp_list):
    destination_addr = ""
    for smpp in smpp_temp_list:
        if smpp.destination_addr == None or smpp.destination_addr == "":
            continue
        destination_addr = smpp.destination_addr

    if destination_addr == None or destination_addr == "":
        return smpp_temp_list

    for smpp in smpp_temp_list:
        smpp.destination_addr = destination_addr

    return smpp_temp_list

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
