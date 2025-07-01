import os.path
import sys
import re
import struct
from models import Diameter, Base, IngestionQueue
import database
import traceback

PCAP_GLOBAL_HDR_LEN = 24
PCAP_PKT_HDR_LEN = 16
SLL_LEN = 16
SCTP_HEADER_LEN = 12

diameter_list = []
diameter_dict = {}
sctp_dict = {}
tcp_dict = {}
diameter_full_length = {}
diameter_current_length = {}

dlt_map = {0:   (lambda p: p[0:4]   == b'\x02\x00\x00\x00',  4), # NULL
            1:   (lambda p: p[12:14] == b'\x08\x00',         14), # EN10MB
            109: (lambda p: p[0:4]   == b'\x02\x00\x00\x00', 12), # ENC
            113: (lambda p: p[14:16] == b'\x08\x00',         16), # LINUX_SLL
            276: (lambda p: p[0:2]   == b'\x08\x00',         20)} # LINUX_SLL2


total_processed = 0
total_not_processed = 0
class DiameterKey:
    command_code = 0
    hop_by_hop_id = 0
    end_to_end_id = 0
    session_id = ""

    def __init__(self, command_code, hop_by_hop_id, end_to_end_id, session_id):
        self.command_code = command_code
        self.hop_by_hop_id = hop_by_hop_id
        self.end_to_end_id = end_to_end_id
        self.session_id = session_id

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.command_code == other.command_code and self.hop_by_hop_id == other.hop_by_hop_id \
                and self.end_to_end_id == other.end_to_end_id and self.session_id == other.session_id
        return False

    def __hash__(self):
        return hash((self.command_code, self.hop_by_hop_id, self.end_to_end_id, self.session_id))


class SCTPKey:
    stream_id = 0
    stream_seq_num = 0
    src_ip = ""
    dst_ip = ""
    
    def __init__(self, stream_id, stream_seq_num, src_ip, dst_ip):
        self.stream_id = stream_id
        self.stream_seq_num = stream_seq_num
        self.src_ip = src_ip
        self.dst_ip = dst_ip
    
    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.stream_id == other.stream_id and self.stream_seq_num == other.stream_seq_num \
                and self.src_ip == other.src_ip and self.dst_ip == other.dst_ip
        return False
    
    def __hash__(self):
        return hash((self.stream_id, self.stream_seq_num, self.src_ip, self.dst_ip))


class TCPKey:
    src_ip = ""
    src_port = 0
    dst_ip = ""
    dst_port = 0
    ack_number = 0

    def __init__(self, src_ip, src_port, dst_ip, dst_port, ack_number):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.ack_number = ack_number

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.dst_ip == other.dst_ip \
                and self.dst_port == other.dst_port and self.src_ip == other.src_ip \
                and self.src_port == other.src_port and self.ack_number == other.ack_number
        return False

    def __hash__(self):
        return hash((self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.ack_number))


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


def get_diameter(diameter_layer, frame):
    diameter = Diameter()
    diameter_version, = struct.unpack("!B", diameter_layer[0:1])
    if not diameter_version == 1:
        return True, None, None

    diameter_flags, = struct.unpack("!B", diameter_layer[4:5])
    diameter.request = True if (diameter_flags & 128) == 128 else False

    diameter_length, diameter_cmd = struct.unpack("!2I", diameter_layer[0:8])

    diameter_length = diameter_length & 16777215
    diameter_cmd = diameter_cmd & 16777215
    
    # if the SCTP payload is incomplete
    if diameter_length > len(diameter_layer):
        return False, None, None
    
    # Discarding Device-Watchdog Request and Answer
    if diameter_cmd == 280:
        return True, None, None

    diameter.command_code = diameter_cmd

    diameter.hop_by_hop_id, diameter.end_to_end_id = struct.unpack("!2I", diameter_layer[12:20])

    session_id = ""
    avp_index = 20
    # diameter.avp = "".join((hex(letter)[2:] if len(hex(letter)[2:]) == 2 else "0" + hex(letter)[2:]) for letter in diameter_layer[avp_index:])
    
    while avp_index < diameter_length:
        avp_code, avp_length = struct.unpack("!2I", diameter_layer[avp_index:avp_index + 8])
        avp_length = avp_length & 16777215
        if avp_length == 0:
            print(f"Wrong value in AVP length {avp_length} in frame numeber {frame}")
            break
        avp_padding = 0 if (avp_length % 4) == 0 else 4 - (avp_length % 4)
        avp_value = diameter_layer[avp_index + 8:avp_index + avp_length]
        avp_value_str = "0x" + "".join((hex(letter)[2:] if len(hex(letter)[2:]) == 2 else "0" + hex(letter)[2:]) for letter in avp_value[0:])
        avp_index += avp_length + avp_padding

        match avp_code:
            case 1: # User Name
                imsi_temp = avp_value.decode("utf-8")
                if len(imsi_temp) > 16:
                    m = re.search("^[0-9]+@", imsi_temp)
                    if m:
                        imsi_temp = m.group()[:-1]
                    else:
                        imsi_temp = None
                diameter.imsi = imsi_temp
            case 263: # Session Id
                session_id = avp_value.decode("utf-8")
            case 264: # Origin Host
                diameter.origin_host = avp_value.decode("utf-8")
            case 268: # Result Code
                diameter.result_code, = struct.unpack("!I", avp_value)
            case 283: # Destination Realm
                diameter.destination_realm = avp_value.decode("utf-8")
            case 293: # Destination Host
                diameter.destination_host = avp_value.decode("utf-8")
            case 296: # Origin Realm
                diameter.origin_realm = avp_value.decode("utf-8")
            case 297: # Experimental Result
                i = 0
                # Vendor Id 
                avp_code_266, avp_length_266 = struct.unpack("!2I", avp_value[i:8])
                avp_length_266 = avp_length_266 & 16777215
                avp_padding_266 = 0 if (avp_length_266 % 4) == 0 else 4 - (avp_length_266 % 4)
                avp_value_266, = struct.unpack("!I", avp_value[i + 8:i + avp_length_266])
                i += avp_length_266 + avp_padding_266
                # Experimental Result Code 298
                avp_code_298, avp_length_298 = struct.unpack("!2I", avp_value[i:i + 8])
                avp_length_298 = avp_length_298 & 16777215
                avp_padding_298 = 0 if (avp_length_298 % 4) == 0 else 4 - (avp_length_298 % 4)
                avp_value_298, = struct.unpack("!I", avp_value[i + 8:i + avp_length_298])
                diameter.exp_result_code = avp_value_298
            case 443: # Subscription Id
                i = 0
                # Subscription Id Type 450
                avp_code_450, avp_length_450 = struct.unpack("!2I", avp_value[i:8])
                avp_length_450 = avp_length_450 & 16777215
                avp_padding_450 = 0 if (avp_length_450 % 4) == 0 else 4 - (avp_length_450 % 4)
                avp_value_450, = struct.unpack("!I", avp_value[i + 8:i + avp_length_450])
                i += avp_length_450 + avp_padding_450
                # Subscription Id Data 444
                avp_code_444, avp_length_444 = struct.unpack("!2I", avp_value[i:i + 8])
                avp_length_444 = avp_length_444 & 16777215
                avp_padding_444 = 0 if (avp_length_444 % 4) == 0 else 4 - (avp_length_444 % 4)
                avp_value_444 = avp_value[i + 8:i + avp_length_444].decode("utf-8") 

                if avp_value_450 == 0:
                    diameter.msisdn = f"{avp_value_444}"
                elif avp_value_450 == 1:
                    diameter.imsi = f"{avp_value_444}"
    
    return True, session_id, diameter


def add_to_diameter_list(frame, header, packet):
    start_index = 0

    # Linux cooked capture (SLL) - 16 bytes
    sll = packet[start_index:SLL_LEN]
    
    sll_etype, = struct.unpack("!H", sll[14:16])
    
    if sll_etype != 2048:
        return None
    
    start_index += SLL_LEN

    # Calculating IPv4 header length
    ip_h_len, = struct.unpack("!B", packet[16:17])
    ip_h_len = (ip_h_len & 15) * 4

    # IPv4 layer - 20-60 bytes
    ip_layer = packet[start_index:start_index + ip_h_len]
    start_index += ip_h_len

    # Get protocol and check if it is SCTP (132) or TCP (6)
    protocol, = struct.unpack("!B", ip_layer[9:10])

    src_oct01, src_oct02, src_oct03, src_oct04 = struct.unpack("!4B", ip_layer[12:16])
    dst_oct01, dst_oct02, dst_oct03, dst_oct04 = struct.unpack("!4B", ip_layer[16:20])
    
    src_ip = f"{src_oct01}.{src_oct02}.{src_oct03}.{src_oct04}"
    dst_ip = f"{dst_oct01}.{dst_oct02}.{dst_oct03}.{dst_oct04}"

    complete = False
    session_id = ""
    diamKey = None
    sctpKey = None
    diameter = None
    diameter_layer = None
    if protocol == 132:
        sctp_header = packet[start_index:start_index + SCTP_HEADER_LEN]
        sctp_chunk_padding = 0
        start_index += SCTP_HEADER_LEN

        src_port, = struct.unpack("!H", sctp_header[0:2])
        dst_port, = struct.unpack("!H", sctp_header[2:4])

        if not (src_port == 3868 or dst_port == 3868):
            return None
        
        while start_index < len(packet):
            # Checking chunks if there is a Chunk Type DATA (0)
            sctp_chunk_type, = struct.unpack("!B", packet[start_index:start_index + 1])
            sctp_chunk_len, = struct.unpack("!H", packet[start_index + 2:start_index + 4])
            sctp_chunk_padding = 0 if (sctp_chunk_len % 4) == 0 else 4 - (sctp_chunk_len % 4)
            sctp_chunk_len += sctp_chunk_padding

            if sctp_chunk_type in [1, 2, 14]:
                return None
            elif sctp_chunk_type != 0:
                start_index += sctp_chunk_len
                continue
            
            sid, ssn = struct.unpack("!2H", packet[start_index + 8:start_index + 12])
            
            diameter_layer = packet[start_index + 16:start_index + sctp_chunk_len]
            sctpKey = SCTPKey(sid, ssn, src_ip, dst_ip)

            frames_list = f"{frame}"
            if len(sctp_dict) > 0:
                sctp_dict_value = sctp_dict.get(sctpKey)
                if sctp_dict_value != None:
                    diameter_layer = sctp_dict_value[0] + diameter_layer
                    frames_list = sctp_dict_value[1] + " " + frames_list
                    sctp_dict.pop(sctpKey, None)

            complete, session_id, diameter = get_diameter(diameter_layer, frame)

            if not complete:
                sctp_dict[sctpKey] = [diameter_layer, frames_list]
            
            if diameter == None:
                start_index += sctp_chunk_len
                continue

            diameter.frames_list = f"{frame}" if frames_list == "" else frames_list
            diameter.pcap_filename = filename
            diameter.time_epoch = header[0]
            diameter.useconds_epoch = header[1]
            diameter.src_ip = src_ip
            diameter.dst_ip = dst_ip

            start_index += sctp_chunk_len
            diamKey = None
            if diameter.request:
                diamKey = DiameterKey(diameter.command_code, diameter.hop_by_hop_id, diameter.end_to_end_id, session_id)
                diam_temp = diameter_dict.get(diamKey)
                if diam_temp == None:
                    diameter_dict[diamKey] = diameter
                else:
                    # SCTP retransmission because this transaction already exists
                    continue
            else:
                diamKey = DiameterKey(diameter.command_code, diameter.hop_by_hop_id, diameter.end_to_end_id, session_id)
                diam_temp = diameter_dict.get(diamKey)
                if diam_temp == None:
                    # if the request does not exist, then add the response to the dictionary to be processed later
                    diameter_dict[diamKey] = diameter
                else:
                    # if the request exists, then copy MSISDN and IMSI between request and response
                    # MSISDN
                    if diam_temp.msisdn != None and diam_temp.msisdn != "":
                        if diameter.msisdn == None or diameter.msisdn == "":
                            diameter.msisdn = diam_temp.msisdn
                    else:
                        if diameter.msisdn != None and diameter.msisdn != "":
                            diam_temp.msisdn = diameter.msisdn

                    # IMSI
                    if diam_temp.imsi != None and diam_temp.imsi != "":
                        if diameter.imsi == None or diameter.imsi == "":
                            diameter.imsi = diam_temp.imsi
                    else:
                        if diameter.imsi != None and diameter.imsi != "":
                            diam_temp.imsi = diameter.imsi

                    # adding request ready to be saved
                    diameter_list.append(diam_temp)
                    # adding response ready to be saved
                    diameter_list.append(diameter)
                    # delete the request from the dictionary to avoid another request with the same key
                    diameter_dict.pop(diamKey, None)
            
    elif protocol == 6:
        tcp_len, = struct.unpack("!B", packet[start_index + 12:start_index + 13])
        tcp_len = (tcp_len >> 4) * 4
        
        tcp_flags, = struct.unpack("!B", packet[start_index + 13:start_index + 14])
        if tcp_flags not in {16, 24}:
            return None

        tcp_layer = packet[start_index:start_index + tcp_len]
        src_port, dst_port = struct.unpack("!2H", tcp_layer[0:4])
        ack_number, = struct.unpack("!I", tcp_layer[8:12])

        if not (src_port == 3868 or dst_port == 3868):
            return None

        start_index += tcp_len
        diameter_layer = packet[start_index:]
        if diameter_layer == None or len(diameter_layer) == 0:
            return None
        tcpKey = TCPKey(src_ip, src_port, dst_ip, dst_port, ack_number)

        frames_list = f"{frame}"
        if len(tcp_dict) > 0:
            tcp_dict_value = tcp_dict.get(tcpKey)
            if tcp_dict_value != None:
                diameter_layer = tcp_dict_value[0] + diameter_layer
                frames_list = tcp_dict_value[1] + " " + frames_list
                tcp_dict.pop(tcpKey, None)

        complete, session_id, diameter = get_diameter(diameter_layer, frame)
            
        if not complete:
            tcp_dict[tcpKey] = [diameter_layer, frames_list]
        
        if diameter == None:
            return None

        diameter.frames_list = f"{frame}" if frames_list == "" else frames_list
        diameter.pcap_filename = filename
        diameter.time_epoch = header[0]
        diameter.useconds_epoch = header[1]
        diameter.src_ip = f"{src_oct01}.{src_oct02}.{src_oct03}.{src_oct04}"
        diameter.dst_ip = f"{dst_oct01}.{dst_oct02}.{dst_oct03}.{dst_oct04}"
        
        diamKey = None
        if diameter.request:
            diamKey = DiameterKey(diameter.command_code, diameter.hop_by_hop_id, diameter.end_to_end_id, session_id)
            diam_temp = diameter_dict.get(diamKey)
            if diam_temp == None:
                diameter_dict[diamKey] = diameter
        else:
            diamKey = DiameterKey(diameter.command_code, diameter.hop_by_hop_id, diameter.end_to_end_id, session_id)
            diam_temp = diameter_dict.get(diamKey)
            if diam_temp == None:
                # if the request does not exist, then add to the dictionary to be processed later
                diameter_dict[diamKey] = diameter
            else:
                # if the request exists, then copy MSISDN and IMSI between request and response
                # MSISDN
                if diam_temp.msisdn != None and diam_temp.msisdn != "":
                    if diameter.msisdn == None or diameter.msisdn == "":
                        diameter.msisdn = diam_temp.msisdn
                else:
                    if diameter.msisdn != None and diameter.msisdn != "":
                        diam_temp.msisdn = diameter.msisdn

                # IMSI
                if diam_temp.imsi != None and diam_temp.imsi != "":
                    if diameter.imsi == None or diameter.imsi == "":
                        diameter.imsi = diam_temp.imsi
                else:
                    if diameter.imsi != None and diameter.imsi != "":
                        diam_temp.imsi = diameter.imsi

                # adding request ready to be saved
                diameter_list.append(diam_temp)
                # adding response ready to be saved
                diameter_list.append(diameter)
                # delete the request from the dictionary to avoid another request with the same key
                diameter_dict.pop(diamKey, None)


def process_pcap(pcap_file, pcap_global_hdr, endian):
    frame = 0
    diameter_frames = 0
    not_processed = 0
    # print(pcap_global_hdr)
    # print("".join((hex(letter)[2:] if len(hex(letter)[2:]) == 2 else "0" + hex(letter)[2:]) for letter in pcap_global_hdr))
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

            add_to_diameter_list(frame, header, packet)

        except Exception:
            # print(f"frame {frame} not processed of the PCAP file {filename}")
            not_processed += 1
            continue
    i = 0
    while i < len(diameter_list):
        diff = len(diameter_list) - i
        if diff < 1000:
            db.bulk_save_objects(diameter_list[i:i + diff])
            i += diff
        else:
            db.bulk_save_objects(diameter_list[i:i + 1000])
            i += 1000
        db.commit()
        
    req = 0
    res = 0
    for k in diameter_dict.keys():
        v = diameter_dict.get(k)
        if v.request:
            req += 1
        else:
            res += 1

    print(f"requests not processed: {req}, responses not processed: {res}")
    
    diameter_frames = len(diameter_list) + len(diameter_dict)

    print(f"{diameter_frames} processed / {not_processed} NOT processed diameter frames out of {frame} packets in the PCAP file {filename}.")
    global total_processed
    total_processed = diameter_frames
    global total_not_processed
    total_not_processed = not_processed


def process_pcapng(pcapng_file, pcap_global_hdr, endian):
    frame = 0
    diameter_frames = 0
    not_processed = 0

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
                if_tsresol, = struct.unpack(endian + "B", idb_options[idb_idx + 4: idb_idx + option_len])
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

            add_to_diameter_list(frame, header, packet)
            
        except Exception as e:
            # print(f"frame {frame} not processed of the PCAPNG file {filename}")
            # print(f"{frame} {e}")
            # traceback.print_exc()
            not_processed += 1
            continue
    i = 0
    while i < len(diameter_list):
        diff = len(diameter_list) - i
        if diff < 1000:
            db.bulk_save_objects(diameter_list[i:i + diff])
            i += diff
        else:
            db.bulk_save_objects(diameter_list[i:i + 1000])
            i += 1000
        db.commit()
        
    req = 0
    res = 0
    for k in diameter_dict.keys():
        v = diameter_dict.get(k)
        db.add(v)
        if v.request:
            req += 1
        else:
            res += 1
    db.commit()

    print(f"requests not processed: {req}, responses not processed: {res} in the PCAPNG file {filename}.")
    
    diameter_frames = len(diameter_list) + len(diameter_dict)

    print(f"{diameter_frames} processed / {not_processed} NOT processed diameter frames out of {frame} packets in the PCAPNG file {filename}.")
    global total_processed
    total_processed = diameter_frames
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
        db2.query(IngestionQueue).filter(IngestionQueue.id == ingestion_id).update(
            {'processed': total_processed, 'not_processed': total_not_processed})
        db2.commit()
