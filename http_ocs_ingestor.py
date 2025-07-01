import os.path
import sys
import re
import struct
from models import HttpOcs, Base, IngestionQueue
import database
import xmltodict
from datetime import datetime

PCAP_GLOBAL_HDR_LEN = 24
PCAP_PKT_HDR_LEN = 16
SCTP_DATA_HEADER_LEN = 16
SCTP_HEADER_LEN = 12
M3UA_HEADER_LEN = 8

tcp_global_dict = {}
tcp_incomp_dict = {}

dlt_map = {0:   (lambda p: p[0:4] == b'\x02\x00\x00\x00',  4),  # NULL
           1:   (lambda p: p[12:14] == b'\x08\x00',         14),  # EN10MB
           109: (lambda p: p[0:4] == b'\x02\x00\x00\x00', 12),  # ENC
           113: (lambda p: p[14:16] == b'\x08\x00',         16),  # LINUX_SLL
           141: (lambda p: True,                            0),  # MTP3 Q.704
           276: (lambda p: p[0:2] == b'\x08\x00',         20)}  # LINUX_SLL2


total_processed = 0
total_not_processed = 0

operation_type = {
    "mo-acr-request",
    "mo-acr-response",
    "mo-idp-request",
    "mo-idp-response",
    "dest-change-request",
    "dest-change-response",
    "source-change-request-acr",
    "source-change-response-acr",
    "source-change-request-idp",
    "source-change-response-idp",
    "shadow-number-request",
    "shadow-number-response",
    "roaming_code",
    "volte-acr-request",
    "volte-acr-response",
    "volte-idp-request",
    "volte-idp-response"
}


class TCPKey:
    src_ip = ""
    src_port = 0
    dst_ip = ""
    dst_port = 0
    ack_or_seq = 0

    def __init__(self, src_ip, src_port, dst_ip, dst_port, ack_or_seq):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.ack_or_seq = ack_or_seq

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.dst_ip == other.dst_ip \
                and self.dst_port == other.dst_port and self.src_ip == other.src_ip \
                and self.src_port == other.src_port and self.ack_or_seq == other.ack_or_seq
        return False

    def __hash__(self):
        return hash((self.dst_ip, self.dst_port, self.src_ip, self.src_port, self.ack_or_seq))


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


def add_to_tcp_list(frame, dlt, header, packet):
    if dlt_map[dlt][0](packet):
        dlt_length = dlt_map[dlt][1]
    else:
        return

    tcp = TCP()

    tcp.frames_list = f"{frame}"
    tcp.pcap_filename = filename_orig
    tcp.time_epoch = header[0]
    tcp.useconds_epoch = header[1]

    start_index = 0

    # DLT length
    sll = packet[start_index:dlt_length]
    proto_type = struct.unpack("!H", sll[-2:])

    # 0x0800 = IPv4 (2048)
    # 0x0806 = ARP (2054)
    if proto_type == 2054:
        return

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
        return

    tcp_flags, = struct.unpack("!B", packet[start_index + 13:start_index + 14])
    if tcp_flags != 24:
        return

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
        return

    tcp_layer = packet[start_index:start_index + tcp_len]

    start_index += tcp_len

    tcp.src_port, tcp.dst_port = struct.unpack("!2H", tcp_layer[0:4])
    tcp.seq_number, tcp.ack_number = struct.unpack("!2I", tcp_layer[4:12])

    key = None

    tcp.payload = packet[start_index:]
    http_str = None
    try:
        http_str = tcp.payload.decode("utf-8")
    except Exception:
        pass

    if http_str == None:
        return
    
    http_split = None
    try:
        http_split = http_str.split("\r\n")
    except Exception:
        return
    
    # this packet is a candidate if it needs to be reassembled with a previous TCP payload
    # if http_split == None or len(http_split) <= 1:
    #     return key, tcp

    m_req = re.search("http\/1.[01]$", http_split[0].lower())
    m_res = re.search("http\/1.[01] [1-5][0-9]{2}", http_split[0].lower())

    if m_req != None or m_res != None:
        tcp.is_http = True
        if m_res == None:
            tcp.is_request = True
            key = TCPKey(tcp.src_ip, tcp.src_port, tcp.dst_ip, tcp.dst_port, tcp.ack_number)
            temp = tcp_global_dict.get(key)
            if temp == None:
                tcp_global_dict[key] = [tcp, None]
            else:
                temp_res = None
                if len(temp) > 1:
                    temp_res = temp[1]
                if temp[0] == None:
                    # Unlikely scenario because the request is processed first
                    tcp_global_dict[key] = [tcp, temp_res]
                # otherwise ignoring retransmissions
        else:
            key = TCPKey(tcp.dst_ip, tcp.dst_port, tcp.src_ip, tcp.src_port, tcp.seq_number)
            temp = tcp_global_dict.get(key)
            if temp == None:
                tcp_global_dict[key] = [None, tcp]
            else:
                temp_req = None
                if len(temp) > 1:
                    temp_req = temp[0]
                if temp[1] == None:
                    tcp_global_dict[key] = [temp_req, tcp]
                # otherwise ignoring retransmissions
    else:
        # It is unknown if the packet is a request or a response
        # if it needs to be reassembled with a previous TCP payload
        
        # Checking if the packet is part of a request
        key = TCPKey(tcp.src_ip, tcp.src_port, tcp.dst_ip, tcp.dst_port, tcp.ack_number)
        temp = tcp_global_dict.get(key)
        if temp == None:
            
            # Checking if the packet is part of a response
            key = TCPKey(tcp.dst_ip, tcp.dst_port, tcp.src_ip, tcp.src_port, tcp.seq_number)
            temp = tcp_global_dict.get(key)
            if temp == None:
                # HTTP packet incompleted
                tcp_incomp_dict[key] = tcp
            else:
                # concatenate to the response
                tcp_global_dict[key][1].frames_list = temp[1].frames_list + " " + tcp.frames_list
                tcp_global_dict[key][1].payload = temp[1].payload + tcp.payload
        else:
            if temp[0] == None:
                # HTTP packet incompleted
                tcp_incomp_dict[key] = tcp
            else:
                # concatenate to the request
                tcp_global_dict[key][0].frames_list = temp[0].frames_list + " " + tcp.frames_list
                tcp_global_dict[key][0].payload = temp[0].payload + tcp.payload
    return


def get_http_ocs(tcp: TCP):
    http = HttpOcs()
    
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
    
    http_str = None
    try:
        http_str = tcp.payload.decode("utf-8")
    except Exception:
        pass

    if http_str == None:
        return None
    
    http_split = None
    try:
        http_split = http_str.split("\r\n")
    except Exception:
        return None

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
        
        if http.http_content_length == None:
            http.http_content_length = 0
            http.type = "noContent"
            return http
        
        data = http_str[http_len:http_len + http.http_content_length]
        
        if len(data) == 0:
            http.type = "httpIncomplete"
            return http
        
        http_dict = xmltodict.parse(data)
        
        if type(http_dict).__name__ != "dict" or list(http_dict.keys()) == None or len(list(http_dict.keys())) == 0:
            return None
        
        http_type = list(http_dict.keys())[0]
        
        if http_type not in operation_type:
            return None
        
        http.type = http_type

        try:
            http.operation_id = http_dict[http_type]["@id"]
        except Exception:
            http.operation_id = None

        try:
            http.cdpa = http_dict[http_type]["cdpa"]
        except Exception:
            http.cdpa = None
        
        try:
            http.temp_cdpa = http_dict[http_type]["temp_cdpa"]
        except Exception:
            http.temp_cdpa = None

        try:
            http.msisdn = http_dict[http_type]["msisdn"]
        except Exception:
            http.msisdn = None

        try:
            http.rdn = http_dict[http_type]["rdn"]
        except Exception:
            http.rdn = None

        try:
            http.period_duration = int(http_dict[http_type]["periodduration"])
        except Exception:
            http.period_duration = None

        try:
            call_active = http_dict[http_type]["callactive"]
            if call_active != None and call_active.lower() == "true":
                http.call_active = True
            else:
                http.call_active = False
        except Exception:
            http.call_active = None

        try:
            start_time = http_dict[http_type]["starttime"]
            if type(start_time).__name__ == "list":
                http.start_time = start_time[0]
            else:
                http.start_time = start_time
        except Exception:
            http.start_time = None

        try:
            http.end_time = http_dict[http_type]["endtime"]
        except Exception:
            http.end_time = None

        try:
            http.status = http_dict[http_type]["status"]
        except Exception:
            http.status = None

        try:
            http.status_code = int(http_dict[http_type]["status_code"])
        except Exception:
            http.status_code = None

        try:
            http.max_call_period_duration = int(http_dict[http_type]["maxcallperiodduration"])
        except Exception:
            http.max_call_period_duration = None

        try:
            http.dtmf_route = http_dict[http_type]["dtmf_route"]
        except Exception:
            http.dtmf_route = None

        try:
            http.req_type = http_dict[http_type]["req_type"]
        except Exception:
            http.req_type = None

        try:
            http.shadow_number = http_dict[http_type]["shadow_number"]
        except Exception:
            http.shadow_number = None

        try:
            http.called = http_dict[http_type]["called"]
        except Exception:
            http.called = None

        try:
            http.calling = http_dict[http_type]["calling"]
        except Exception:
            http.calling = None

        try:
            http.msrn = http_dict[http_type]["msrn"]
        except Exception:
            http.msrn = None

        try:
            http.phone = http_dict[http_type]["phone"]
        except Exception:
            http.phone = None

        try:
            http.code = int(http_dict[http_type]["code"])
        except Exception:
            http.code = None

        try:
            http.result = int(http_dict[http_type]["result"])
        except Exception:
            http.result = None

        try:
            http.dual_num = http_dict[http_type]["dual_num"]
        except Exception:
            http.dual_num = None

        try:
            http.mcc = int(http_dict[http_type]["mcc"])
        except Exception:
            http.mcc = None

        try:
            http.mnc = int(http_dict[http_type]["mnc"])
        except Exception:
            http.mnc = None

        try:
            http.imsi = http_dict[http_type]["imsi"]
        except Exception:
            http.imsi = None
    except Exception:
        return None
    return http


def process_pcap(pcap_file, pcap_global_hdr, endian):
    frame = 0
    not_processed = 0
    http_req_list = []
    http_res_list = []
    http_req_dict = {}
    http_unlink_list = []

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

            add_to_tcp_list(frame, dlt, header, packet)
        except Exception:
            not_processed += 1
            continue
    
    # Convert TCP to HTTP object with an expected payload
    # The requests are stored in a dictionary with the same TCPKey
    # The responses are stored in a Http list, ready to send to the DB
    for k in tcp_global_dict.keys():
        v_list = tcp_global_dict.get(k)
        if v_list != None:
            # if request and response can be linked
            if v_list[0] != None and v_list[1] != None:
                http_req = get_http_ocs(v_list[0])
                http_res = get_http_ocs(v_list[1])
                if http_req != None and http_res != None:
                    # if the request exists, then copy MSISDN and IMSI between request and response
                    # MSISDN
                    if http_req.msisdn != None and http_req.msisdn != "":
                        if http_res.msisdn == None or http_res.msisdn == "":
                            http_res.msisdn = http_req.msisdn
                    else:
                        if http_res.msisdn != None and http_res.msisdn != "":
                            http_req.msisdn = http_res.msisdn
                    
                    # CALLED
                    if http_req.called != None and http_req.called != "":
                        if http_res.called == None or http_res.called == "":
                            http_res.called = http_req.called
                    else:
                        if http_res.called != None and http_res.called != "":
                            http_req.called = http_res.called
                    
                    # CALLING
                    if http_req.calling != None and http_req.calling != "":
                        if http_res.calling == None or http_res.calling == "":
                            http_res.calling = http_req.calling
                    else:
                        if http_res.calling != None and http_res.calling != "":
                            http_req.calling = http_res.calling
                    
                    # PHONE
                    if http_req.phone != None and http_req.phone != "":
                        if http_res.phone == None or http_res.phone == "":
                            http_res.phone = http_req.phone
                    else:
                        if http_res.phone != None and http_res.phone != "":
                            http_req.phone = http_res.phone

                    # IMSI
                    if http_req.imsi != None and http_req.imsi != "":
                        if http_res.imsi == None or http_res.imsi == "":
                            http_res.imsi = http_req.imsi
                    else:
                        if http_res.imsi != None and http_res.imsi != "":
                            http_req.imsi = http_res.imsi
                    
                    if http_req != None:
                        http_req_dict[k] = http_req
                    if http_res != None:
                        http_res_list.append(http_res)
                else:
                    if http_req != None:
                        http_unlink_list.append(http_req)
                    if http_res != None:
                        http_unlink_list.append(http_res)
            else:
                if v_list[0] != None:
                    http = get_http_ocs(v_list[0])
                    if http != None:
                        http_unlink_list.append(http)
                
                if v_list[1] != None:
                    http = get_http_ocs(v_list[1])
                    if http != None:
                        http_unlink_list.append(http)

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
        key = TCPKey(http.dst_ip, http.dst_port, http.src_ip, http.src_port, http.tcp_sequence)
        
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
        
    i = 0
    while i < len(http_unlink_list):
        diff = len(http_unlink_list) - i
        if diff < 1000:
            db.bulk_save_objects(http_unlink_list[i:i + diff])
            i += diff
        else:
            db.bulk_save_objects(http_unlink_list[i:i + 1000])
            i += 1000
        db.commit()
    
    http_frames = len(http_req_dict) + len(http_res_list) + len(http_unlink_list)

    print(f"{http_frames} processed / {not_processed} NOT processed HTTP frames out of {frame} packets in the PCAP file {filename}.")

    global total_processed
    total_processed = http_frames
    global total_not_processed
    total_not_processed = not_processed


def process_pcapng(pcapng_file, pcap_global_hdr, endian):
    frame = 0
    http_frames = 0
    not_processed = 0
    http_req_list = []
    http_res_list = []
    http_req_dict = {}
    http_unlink_list = []

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

            add_to_tcp_list(frame, dlt, header, packet)
        except Exception:
            not_processed += 1
            continue
    
    # Convert TCP to HTTP object with an expected payload
    # The requests are stored in a dictionary with the same TCPKey
    # The responses are stored in a Http list, ready to send to the DB
    for k in tcp_global_dict.keys():
        v_list = tcp_global_dict.get(k)
        if v_list != None:
            # if request and response can be linked
            if v_list[0] != None and v_list[1] != None:
                http_req = get_http_ocs(v_list[0])
                http_res = get_http_ocs(v_list[1])
                if http_req != None and http_res != None:
                    # if the request exists, then copy MSISDN and IMSI between request and response
                    # MSISDN
                    if http_req.msisdn != None and http_req.msisdn != "":
                        if http_res.msisdn == None or http_res.msisdn == "":
                            http_res.msisdn = http_req.msisdn
                    else:
                        if http_res.msisdn != None and http_res.msisdn != "":
                            http_req.msisdn = http_res.msisdn
                    
                    # CALLED
                    if http_req.called != None and http_req.called != "":
                        if http_res.called == None or http_res.called == "":
                            http_res.called = http_req.called
                    else:
                        if http_res.called != None and http_res.called != "":
                            http_req.called = http_res.called
                    
                    # CALLING
                    if http_req.calling != None and http_req.calling != "":
                        if http_res.calling == None or http_res.calling == "":
                            http_res.calling = http_req.calling
                    else:
                        if http_res.calling != None and http_res.calling != "":
                            http_req.calling = http_res.calling
                    
                    # PHONE
                    if http_req.phone != None and http_req.phone != "":
                        if http_res.phone == None or http_res.phone == "":
                            http_res.phone = http_req.phone
                    else:
                        if http_res.phone != None and http_res.phone != "":
                            http_req.phone = http_res.phone

                    # IMSI
                    if http_req.imsi != None and http_req.imsi != "":
                        if http_res.imsi == None or http_res.imsi == "":
                            http_res.imsi = http_req.imsi
                    else:
                        if http_res.imsi != None and http_res.imsi != "":
                            http_req.imsi = http_res.imsi
                    
                    if http_req != None:
                        http_req_dict[k] = http_req
                    if http_res != None:
                        http_res_list.append(http_res)
                else:
                    if http_req != None:
                        http_unlink_list.append(http_req)
                    if http_res != None:
                        http_unlink_list.append(http_res)
            else:
                if v_list[0] != None:
                    http = get_http_ocs(v_list[0])
                    if http != None:
                        http_unlink_list.append(http)
                
                if v_list[1] != None:
                    http = get_http_ocs(v_list[1])
                    if http != None:
                        http_unlink_list.append(http)

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
        key = TCPKey(http.dst_ip, http.dst_port, http.src_ip, http.src_port, http.tcp_sequence)
        
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
        
    i = 0
    while i < len(http_unlink_list):
        diff = len(http_unlink_list) - i
        if diff < 1000:
            db.bulk_save_objects(http_unlink_list[i:i + diff])
            i += diff
        else:
            db.bulk_save_objects(http_unlink_list[i:i + 1000])
            i += 1000
        db.commit()
    
    http_frames = len(http_req_dict) + len(http_res_list) + len(http_unlink_list)

    print(f"{http_frames} processed / {not_processed} NOT processed HTTP frames out of {frame} packets in the PCAP file {filename}.")

    global total_processed
    total_processed = http_frames
    global total_not_processed
    total_not_processed = not_processed

s_date = datetime.now()
if len(sys.argv) < 4:
    raise Exception("The pcap or pcapng file parameter was not specified")
filename = sys.argv[1]
filename_orig = sys.argv[2]

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

    e_date = datetime.now()
    with database.get_db_ingestion() as db2:
        ingestion_id = sys.argv[3]
        if ingestion_id == '0':
            if filename.find('DC01'):
                ingestion_id = 31
            elif filename.find('DC02'):
                ingestion_id = 32
            else:
                exit
        queue = IngestionQueue(filename = filename + '.gz'
                               , not_processed = total_not_processed
                               , processed = total_processed
                               , owner = 'server1'
                               , state = 2
                               , ingestion_instance_id = ingestion_id
                               , created_at = s_date
                               , processing_at = s_date
                               , processed_at = e_date
                               , updated_at = e_date)

        db2.add_all([queue])
        db2.query(IngestionQueue)
        db2.query(IngestionQueue).filter(IngestionQueue.id == ingestion_id).update(
            {'processed': total_processed, 'not_processed': total_not_processed})
        db2.commit()
