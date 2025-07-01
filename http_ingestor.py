import os.path
import sys
import re
import struct
from models import Http, Base, IngestionQueue
import database
import xmltodict

PCAP_GLOBAL_HDR_LEN = 24
PCAP_PKT_HDR_LEN = 16
SCTP_DATA_HEADER_LEN = 16
SCTP_HEADER_LEN = 12
M3UA_HEADER_LEN = 8

dlt_map = {0:   (lambda p: p[0:4] == b'\x02\x00\x00\x00',  4),  # NULL
           1:   (lambda p: p[12:14] == b'\x08\x00',         14),  # EN10MB
           109: (lambda p: p[0:4] == b'\x02\x00\x00\x00', 12),  # ENC
           113: (lambda p: p[14:16] == b'\x08\x00',         16),  # LINUX_SLL
           141: (lambda p: True,                            0),  # MTP3 Q.704
           276: (lambda p: p[0:2] == b'\x08\x00',         20)}  # LINUX_SLL2


total_processed = 0
total_not_processed = 0
class TCPKey:
    src_ip = ""
    src_port = 0
    dst_ip = ""
    dst_port = 0

    def __init__(self, src_ip, src_port, dst_ip, dst_port):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.dst_ip == other.dst_ip \
                and self.dst_port == other.dst_port and self.src_ip == other.src_ip \
                and self.src_port == other.src_port
        return False

    def __hash__(self):
        return hash((self.dst_ip, self.dst_port, self.src_ip, self.src_port))


class TCP():
    frames_list = ""
    time_epoch = 0
    useconds_epoch = 0
    src_ip = ""
    src_port = 0
    dst_ip = ""
    dst_port = 0
    seq_number = 0
    ack_number = 0
    payload = b""
    is_http = False
    is_request = False
    pcap_filename = ""

    def __init__(self):
        pass


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


def get_tcp(frame, dlt, header, packet):
    if dlt_map[dlt][0](packet):
        dlt_length = dlt_map[dlt][1]
    else:
        return None, None

    tcp = TCP()

    tcp.frames_list = f"{frame}"
    tcp.pcap_filename = filename
    tcp.time_epoch = header[0]
    tcp.useconds_epoch = header[1]

    start_index = 0

    # DLT length
    sll = packet[start_index:dlt_length]
    proto_type = struct.unpack("!H", sll[-2:])

    # 0x0800 = IPv4 (2048)
    # 0x0806 = ARP (2054)
    if proto_type == 2054:
        return None, None

    start_index += dlt_length

    # Calculating IPv4 header length
    ip_h_len, = struct.unpack("!B", packet[start_index:start_index + 1])
    ip_h_len = (ip_h_len & 15) * 4

    # IPv4 layer - 20-60 bytes
    ip_layer = packet[start_index:start_index + ip_h_len]
    start_index += ip_h_len

    # Get protocol and check if it is TCP (6)
    protocol, = struct.unpack("!B", ip_layer[9:10])
    if protocol != 6:
        return None, None

    tcp_flags, = struct.unpack("!B", packet[start_index + 13:start_index + 14])
    if tcp_flags not in [ 16, 24 ]:
        return None, None

    src_oct01, src_oct02, src_oct03, src_oct04 = struct.unpack(
        "!4B", ip_layer[12:16])
    dst_oct01, dst_oct02, dst_oct03, dst_oct04 = struct.unpack(
        "!4B", ip_layer[16:20])

    tcp.src_ip = f"{src_oct01}.{src_oct02}.{src_oct03}.{src_oct04}"
    tcp.dst_ip = f"{dst_oct01}.{dst_oct02}.{dst_oct03}.{dst_oct04}"

    tcp_len, = struct.unpack("!B", packet[start_index + 12:start_index + 13])
    tcp_len = (tcp_len >> 4) * 4
    
    # if there is no payload
    if (dlt_length + ip_h_len + tcp_len) == len(packet):
        return None, None

    tcp_layer = packet[start_index:start_index + tcp_len]

    start_index += tcp_len

    tcp.src_port, tcp.dst_port = struct.unpack("!2H", tcp_layer[0:4])
    tcp.seq_number, tcp.ack_number = struct.unpack("!2I", tcp_layer[4:12])

    key = TCPKey(tcp.src_ip, tcp.src_port, tcp.dst_ip, tcp.dst_port)

    tcp.payload = packet[start_index:]
    http_str = None
    try:
        http_str = tcp.payload.decode("utf-8")
    except Exception:
        pass

    if http_str == None:
        return None, None
    
    http_split = None
    try:
        http_split = http_str.split("\r\n")
    except Exception:
        pass
    
    # this packet is a candidate if it needs to be reassembled with a previous TCP payload
    if http_split == None or len(http_split) <= 1:
        return key, tcp

    m_req = re.search("http\/1.[01]$", http_split[0].lower())
    m_res = re.search("http\/1.[01] [1-5][0-9]{2}", http_split[0].lower())

    if m_req != None or m_res != None:
        tcp.is_http = True
        if m_res == None:
            tcp.is_request = True

    return key, tcp


def get_http(tcp: TCP, type):
    http = Http()
    
    http.frames_list = tcp.frames_list
    http.time_epoch = tcp.time_epoch
    http.useconds_epoch = tcp.useconds_epoch
    http.src_ip = tcp.src_ip
    http.src_port = tcp.src_port
    http.dst_ip = tcp.dst_ip
    http.dst_port = tcp.dst_port
    http.tcp_sequence = tcp.seq_number
    http.tcp_acknowledge = tcp.ack_number
    http.http_is_request = tcp.is_request
    http.pcap_filename = tcp.pcap_filename
    
    http_str = tcp.payload.decode("utf-8")

    http_split = http_str.split("\r\n")

    try:
        http_len = 0
        for header in http_split:
            if header.lower().__contains__("http/1.1") or header.lower().__contains__("http/1.0"):
                if http.http_is_request:
                    http.http_request_method = header.split(" ")[0].strip()
                    http.http_request_uri = f"http://{http.dst_ip}:{http.dst_port}{header.split(' ')[1].strip()} "
                else:
                    http.http_response_code = header.split(" ")[1].strip()
            if header.lower().__contains__("content-length"):
                http.http_content_length = int(header.split(":")[1].strip())
            if header.lower().__contains__("content-type"):
                if http.http_is_request:
                    http.http_content_type = header.split(":")[1].strip()
            http_len += len(header) + 2
            if len(header) == 0:
                break
        
        data = http_str[http_len:http_len + http.http_content_length]
        data = data.replace("\"natureOfAddresIndicator", "\" natureOfAddresIndicator")
        data = data.replace("\"numberingPlanIndicator", "\" numberingPlanIndicator")
        
        http_dict = xmltodict.parse(data)
        http.type = type
        match type:
            case "SMPP":
                if http_dict['smpp'] != None:
                    pass
                command_id = 0
                
                try:
                    http.smpp_seq_number = http_dict['smpp']['sequenceNumber']
                except Exception:
                    http.smpp_seq_number = None
                try:
                    command_id = int(http_dict['smpp']['commandId'])
                except Exception:
                    pass
                try:
                    http.smpp_src_addr = http_dict['smpp']['sourceAddress']['address']
                    if command_id == 5:
                        http.msisdn = http.smpp_src_addr
                except Exception:
                    http.smpp_src_addr = None
                try:
                    http.smpp_dst_addr = http_dict['smpp']['destAddress']['address']
                    if command_id == 4:
                        http.msisdn = http.smpp_dst_addr
                except Exception:
                    http.smpp_dst_addr = None
            case "CAMEL":
                if http_dict['dialog'] != None:
                    pass
                
                try:
                    http.tcap_otid = http_dict["dialog"]["@localId"]
                except Exception:
                    http.tcap_otid = None
                
                try:
                    http.tcap_dtid = http_dict["dialog"]["@remoteId"]
                except Exception:
                    http.tcap_dtid = None
                
                try:
                    http.imsi = http_dict["dialog"]["initialDP_Request"]["imsi"]["@number"]
                except Exception:
                    http.imsi = None
                    
                try:
                    http.camel_orig_address = http_dict["dialog"]["origAddress"]["gt"]["@digits"]
                except Exception:
                    http.camel_orig_address = None
                
                try:
                    http.camel_dest_address = http_dict["dialog"]["destAddress"]["gt"]["@digits"]
                except Exception:
                    http.camel_dest_address = None
                
            case "DIAMETER":
                if http_dict['diameter'] != None:
                    pass
                
                try:
                    http.diam_e2e_id = http_dict["diameter"]["e2e"]
                except Exception:
                    http.diam_e2e_id = None
                
                try:
                    avps = http_dict["diameter"]["avp"]
                except Exception:
                    avps = None
                
                for avp in avps:
                    match avp["@code"]:
                        case "1":
                            try:
                                http.imsi = avp["@value"]
                            except Exception:
                                http.imsi = None
                        case "263":
                            try:
                                http.diam_session_id = avp["@value"]
                            except Exception:
                                http.diam_session_id = None
                        case "264": # Origin Host
                            try:
                                http.diam_origin_host = avp["@value"]
                            except Exception:
                                http.diam_origin_host = None
                        case "268": # Result Code
                            try:
                                http.diam_result_code = avp["@value"]
                                if http.diam_result_code == "null":
                                    http.diam_result_code = 0
                            except Exception:
                                http.diam_result_code = None
                        case "283": # Destination Realm
                            try:
                                http.diam_destination_realm = avp["@value"]
                            except Exception:
                                http.diam_destination_realm = None
                        case "293": # Destination Host
                            try:
                                http.diam_destination_host = avp["@value"]
                            except Exception:
                                http.diam_destination_host = None
                        case "296": # Origin Realm
                            try:
                                http.diam_origin_realm = avp["@value"]
                            except Exception:
                                http.diam_origin_realm = None
                        case "443": # Subscription Id
                            v450 = 0
                            avps450 = None
                            code4XX = None
                            try:
                                avps450 = avp["avp"]
                            except Exception:
                                avps450 = None
                            for a in avps450:
                                try:
                                    code4XX = a["@code"]
                                except Exception:
                                    code4XX = None
                                if code4XX == "450":
                                    try:
                                        v450 = a["@value"]
                                    except Exception:
                                        v450 = -1
                                if code4XX == "444":
                                    if v450 == "0":
                                        try:
                                            http.msisdn = a["@value"]
                                        except Exception:
                                            http.msisdn = None
                                    elif v450 == "1":
                                        try:
                                            http.imsi = a["@value"]
                                        except Exception:
                                            http.imsi = a["@value"]
            case _:
                return None
    except Exception:
        return None
    return http


def process_pcap(pcap_file, pcap_global_hdr, endian, http_type):
    frame = 0
    http_frames = 0
    not_processed = 0
    rep_keys = 0
    http_req_list = []
    http_res_list = []
    tcp_dict = {}
    http_dict_2 = {}
    http_req_dict = {}
    tcp_temp = TCP()

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

            key, tcp = get_tcp(frame, dlt, header, packet)

            if key == None or tcp == None:
                continue

            # if the TCP packet is HTTP request or response, it adds to the dictionary
            if tcp.is_http:
                cross_key = None
                tcp_temp = tcp_dict.get(key)
                # if the TCP key already exists, then this is stored
                # in a separate dictionary to be processed at the end
                if tcp_temp != None:
                    # if this is a TCP retransmission, it ignores
                    if tcp.seq_number == tcp_temp.seq_number and tcp.ack_number == tcp_temp.ack_number:
                        continue
                    temp = get_http(tcp_temp, http_type)
                    # if this is HTTP packet with the expected payload
                    if temp != None:
                        cross_key = TCPKey(key.dst_ip, key.dst_port, key.src_ip, key.src_port)
                        tcp_temp_2 = tcp_dict.get(cross_key)
                        if tcp_temp_2 != None:
                            temp_2 = get_http(tcp_temp_2, http_type)
                        if tcp_temp.is_request:
                            http_dict_2[rep_keys] = [temp, temp_2]
                        else:
                            http_dict_2[rep_keys] = [temp_2, temp]
                        rep_keys += 1
                    tcp_dict.pop(key, None)
                    tcp_dict.pop(cross_key, None)
                    tcp_dict[key] = tcp
                else:
                    tcp_dict[key] = tcp
                
            # otherwise, there is more than one TCP payload to append it to an existent TCP packet
            else:
                tcp_temp = tcp_dict.get(key)
                
                # if the key does not exist in the dictionary then continue with next packet
                if tcp_temp == None:
                    continue
                
                # if the current sequence and acknowledge number are equals to the existent one,
                # then the packet is a TCP retransmission and will be ignored
                if tcp.seq_number == tcp_temp.seq_number and tcp.ack_number == tcp_temp.ack_number:
                    continue

                tcp_temp.payload += tcp.payload
                tcp_temp.frames_list += " " + tcp.frames_list
                tcp_dict[key] = tcp_temp
        except Exception:
            not_processed += 1
            continue
    
    # Convert TCP to HTTP object with an expected payload
    # The requests are stored in a dictionary with the same TCPKey
    # The responses are stored in a Http list, ready to send to the DB
    for k in tcp_dict.keys():
        http = get_http(tcp_dict.get(k), http_type)
        
        if http == None:
            continue
        
        http_frames += 1
        
        if http.http_is_request:
            http_req_dict[k] = http
        else:
            http_res_list.append(http)

    # Store the responses in the DB and getting the id autogenerated,
    # this will be associated with the respective request
    i = 0
    while i < len(http_res_list):
        diff = len(http_res_list) - i
        if diff < 1000:
            db.bulk_save_objects(http_res_list[i:i + diff], return_defaults = True)
            i += diff
        else:
            db.bulk_save_objects(http_res_list[i:i + 1000], return_defaults = True)
            i += 1000
        db.commit()

    # Link the response with its respective request
    i = 0
    while i < len(http_res_list):
        http = http_res_list[i]
        key = TCPKey(http.dst_ip, http.dst_port, http.src_ip, http.src_port)
        
        http_temp = http_req_dict.get(key)
        if http_temp != None:
            http_temp.http_response_in = http.id
            http_req_dict[key] = http_temp
        i += 1

    # Store the requests in the DB 
    http_req_list = list(http_req_dict.values())
    i = 0
    while i < len(http_req_list):
        diff = len(http_req_list) - i
        if diff < 1000:
            db.bulk_save_objects(http_req_list[i:i + diff])
            i += diff
        else:
            db.bulk_save_objects(http_req_list[i:i + 1000])
            i += 1000
        db.commit()

    # Store the responses with TCPKey duplicated
    for k in http_dict_2.keys():
        v = http_dict_2.get(k)
        if isinstance(v, list) and len(v) == 2:
            if v[1] != None:
                db.add(v[1])
                http_frames += 1
    db.commit()

    # Store the requests with TCPKey duplicated and
    # link the response with its respective request
    for k in http_dict_2.keys():
        v = http_dict_2.get(k)
        if isinstance(v, list) and len(v) == 2:
            req = v[0]
            res = v[1]
            if req != None:
                req.http_response_in = res.id
                db.add(v[0])
                http_frames += 1
    db.commit()

    print(f"{http_frames} processed / {not_processed} NOT processed HTTP frames out of {frame} packets in the PCAP file {filename}.")

    global total_processed
    total_processed = http_frames
    global total_not_processed
    total_not_processed = not_processed


def process_pcapng(pcapng_file, pcap_global_hdr, endian, http_type):
    frame = 0
    http_frames = 0
    not_processed = 0
    rep_keys = 0
    http_req_list = []
    http_res_list = []
    tcp_dict = {}
    http_dict_2 = {}
    http_req_dict = {}
    tcp_temp = TCP()

    # Section Header Block, as first block of the pcapng file
    # https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html#name-section-header-block-format
    block_len, = struct.unpack(endian + "I", pcap_global_hdr[4:8])
    section_hdr_block = pcap_global_hdr + \
        pcapng_file.read(block_len - PCAP_GLOBAL_HDR_LEN)

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
            option, option_len = struct.unpack(
                endian + "2H", idb_options[idb_idx:idb_idx + 4])
            if option == 9:
                if_tsresol, = struct.unpack(
                    endian + "B", idb_options[idb_idx + 4: idb_idx + 4 + option_len])
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
            ts_higher = struct.pack(
                (">" if endian == "<" else endian) + "I", header[0])
            ts_lower = struct.pack(
                (">" if endian == "<" else endian) + "I", header[1])
            ts, = struct.unpack(
                (">" if endian == "<" else endian) + "Q", ts_higher + ts_lower)

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

            key, tcp = get_tcp(frame, dlt, header, packet)

            if key == None or tcp == None:
                continue

            # if the TCP packet is HTTP request or response, it adds to the dictionary
            if tcp.is_http:
                cross_key = None
                tcp_temp = tcp_dict.get(key)
                # if the TCP key already exists, then this is stored
                # in a separate dictionary to be processed at the end
                if tcp_temp != None:
                    # if this is a TCP retransmission, it ignores
                    if tcp.seq_number == tcp_temp.seq_number and tcp.ack_number == tcp_temp.ack_number:
                        continue
                    temp = get_http(tcp_temp, http_type)
                    # if this is HTTP packet with the expected payload
                    if temp != None:
                        cross_key = TCPKey(key.dst_ip, key.dst_port, key.src_ip, key.src_port)
                        tcp_temp_2 = tcp_dict.get(cross_key)
                        if tcp_temp_2 != None:
                            temp_2 = get_http(tcp_temp_2, http_type)
                        if tcp_temp.is_request:
                            http_dict_2[rep_keys] = [temp, temp_2]
                        else:
                            http_dict_2[rep_keys] = [temp_2, temp]
                        rep_keys += 1
                    tcp_dict.pop(key, None)
                    tcp_dict.pop(cross_key, None)
                    tcp_dict[key] = tcp
                else:
                    tcp_dict[key] = tcp
                
            # otherwise, there is more than one TCP payload to append it to an existent TCP packet
            else:
                tcp_temp = tcp_dict.get(key)
                
                # if the key does not exist in the dictionary then continue with next packet
                if tcp_temp == None:
                    continue
                
                # if the current sequence and acknowledge number are equals to the existent one,
                # then the packet is a TCP retransmission and will be ignored
                if tcp.seq_number == tcp_temp.seq_number and tcp.ack_number == tcp_temp.ack_number:
                    continue

                tcp_temp.payload += tcp.payload
                tcp_temp.frames_list += " " + tcp.frames_list
                tcp_dict[key] = tcp_temp
        except Exception:
            not_processed += 1
            continue
    
    # Convert TCP to HTTP object with an expected payload
    # The requests are stored in a dictionary with the same TCPKey
    # The responses are stored in a Http list, ready to send to the DB
    for k in tcp_dict.keys():
        http = get_http(tcp_dict.get(k), http_type)
        
        if http == None:
            continue
        
        http_frames += 1
        
        if http.http_is_request:
            http_req_dict[k] = http
        else:
            http_res_list.append(http)

    # Store the responses in the DB and getting the id autogenerated,
    # this will be associated with the respective request
    i = 0
    while i < len(http_res_list):
        diff = len(http_res_list) - i
        if diff < 1000:
            db.bulk_save_objects(http_res_list[i:i + diff], return_defaults = True)
            i += diff
        else:
            db.bulk_save_objects(http_res_list[i:i + 1000], return_defaults = True)
            i += 1000
        db.commit()

    # Link the response with its respective request
    i = 0
    while i < len(http_res_list):
        http = http_res_list[i]
        key = TCPKey(http.dst_ip, http.dst_port, http.src_ip, http.src_port)
        
        http_temp = http_req_dict.get(key)
        if http_temp != None:
            http_temp.http_response_in = http.id
            http_req_dict[key] = http_temp
        i += 1

    # Store the requests in the DB 
    http_req_list = list(http_req_dict.values())
    i = 0
    while i < len(http_req_list):
        diff = len(http_req_list) - i
        if diff < 1000:
            db.bulk_save_objects(http_req_list[i:i + diff])
            i += diff
        else:
            db.bulk_save_objects(http_req_list[i:i + 1000])
            i += 1000
        db.commit()

    # Store the responses with TCPKey duplicated
    for k in http_dict_2.keys():
        v = http_dict_2.get(k)
        if isinstance(v, list) and len(v) == 2:
            if v[1] != None:
                db.add(v[1])
                http_frames += 1
    db.commit()

    # Store the requests with TCPKey duplicated and
    # link the response with its respective request
    for k in http_dict_2.keys():
        v = http_dict_2.get(k)
        if isinstance(v, list) and len(v) == 2:
            req = v[0]
            res = v[1]
            if req != None:
                req.http_response_in = res.id
                db.add(v[0])
                http_frames += 1
    db.commit()

    print(f"{http_frames} processed / {not_processed} NOT processed HTTP frames out of {frame} packets in the PCAPNG file {filename}.")

    global total_processed
    total_processed = http_frames
    global total_not_processed
    total_not_processed = not_processed


if len(sys.argv) < 4:
    raise Exception("The pcap or pcapng file parameter was not specified")
filename = sys.argv[1]
http_type = sys.argv[2]

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
            process_pcap(pcap_file, pcap_global_hdr, endian, http_type)
        elif format == "PCAPNG":
            process_pcapng(pcap_file, pcap_global_hdr, endian, http_type)

    with database.get_db_ingestion() as db2:
        ingestion_id = sys.argv[3]
        db2.query(IngestionQueue).filter(IngestionQueue.id == ingestion_id).update(
            {'processed': total_processed, 'not_processed': total_not_processed})
        db2.commit()
