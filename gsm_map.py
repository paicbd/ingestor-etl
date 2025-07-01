import os.path
import sys
import struct
from models import GsmMap, Base, IngestionQueue
import database
from binascii import hexlify
from pycrate_asn1dir import TCAP_MAPv2v3

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

sccp_seg_dict = {}

total_processed = 0
total_not_processed = 0


def get_value(key_name, obj):
    if key_name == "" or key_name == None or obj == None:
        return None
    
    if type(obj).__name__ == "tuple" and len(obj) == 2 \
        and type(obj[0]).__name__ == "str" and obj[0] == key_name:
        return obj[1]
    
    if type(obj).__name__ == "tuple" or type(obj).__name__ == "list":
        for item in obj:
            valor = get_value(key_name, item)
            if not valor == None:
                return valor
    elif type(obj).__name__ == "dict":
        keys = list(obj.keys())
        for key in keys:
            value = obj[key]
            if key == key_name:
                return value
            if type(value).__name__ == "tuple" or type(value).__name__ == "list" or type(value).__name__ == "dict":
                valor = get_value(key_name, value)
                if not valor == None:
                    return valor
    else:
        return None
    
    return None


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


def get_gsm_map(frame, dlt, header, packet):
    if dlt_map[dlt][0](packet):
        dlt_length = dlt_map[dlt][1]
    else:
        return None
    
    gsm_map = GsmMap()

    gsm_map.frames_list = f"{frame}"
    gsm_map.pcap_filename = filename
    gsm_map.time_epoch = header[0]
    gsm_map.useconds_epoch = header[1]

    if not dlt == 141:
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

        # Get protocol and check if it is SCTP (132)
        protocol, = struct.unpack("!B", ip_layer[9:10])
        if protocol != 132:
            return None

        src_oct01, src_oct02, src_oct03, src_oct04 = struct.unpack("!4B", ip_layer[12:16])
        dst_oct01, dst_oct02, dst_oct03, dst_oct04 = struct.unpack("!4B", ip_layer[16:20])

        gsm_map.src_ip = f"{src_oct01}.{src_oct02}.{src_oct03}.{src_oct04}"
        gsm_map.dst_ip = f"{dst_oct01}.{dst_oct02}.{dst_oct03}.{dst_oct04}"

        sctp_header = packet[start_index:start_index + SCTP_HEADER_LEN]
        start_index += SCTP_HEADER_LEN

        sctp_data_chunk_hdr = packet[start_index:start_index + SCTP_DATA_HEADER_LEN]
        start_index += SCTP_DATA_HEADER_LEN

        # Checking chunks if there is a Chunk Type DATA (0)
        sctp_chunk_type, = struct.unpack("!B", sctp_data_chunk_hdr[0:1])
        if not sctp_chunk_type == 0:
            return None

        sctp_chunk_len, = struct.unpack("!H", sctp_data_chunk_hdr[2:4])
        sctp_payload_proto_id, = struct.unpack("!I", sctp_data_chunk_hdr[12:16])

        # If payload protocol identifier is not M3UA
        if not sctp_payload_proto_id == 3:
            return None

        m3ua_i = 0
        m3ua_layer = packet[start_index:]
        m3ua_mess_class, m3ua_mess_type, m3ua_mess_length = struct.unpack("!2BI", m3ua_layer[m3ua_i + 2:m3ua_i + 8])
        m3ua_i += 8

        if not (m3ua_mess_class == 1 and m3ua_mess_type == 1):
            return None

        if not len(m3ua_layer) == m3ua_mess_length:
            return None

        sccp_layer = []
        while True:
            # break condition, if is there padding or
            # the index parameter is higher or equals to the M3UA length
            if len(m3ua_layer) - m3ua_i < 4 or not m3ua_i < len(m3ua_layer):
                break

            param_tag, param_len = struct.unpack("!2H", m3ua_layer[m3ua_i:m3ua_i + 4])

            if param_tag == 528:
                m3ua_opc, m3ua_dpc, = struct.unpack("!2I", m3ua_layer[m3ua_i + 4:m3ua_i + 12])
                gsm_map.mtp3_opc = m3ua_opc
                gsm_map.mtp3_dpc = m3ua_dpc
                sccp_layer = m3ua_layer[m3ua_i + 16:m3ua_i + param_len]
            m3ua_i += param_len
    else:
        service_inf, = struct.unpack("!B", packet[0:1])
        mtp3_b = packet[1:5]
        mtp3_b = mtp3_b[::-1]
        mtp3, = struct.unpack("!I", mtp3_b)
        
        service_indicator = service_inf & 3
        
        # if service indicator is SCCP (3)
        if service_indicator == 3:
            # opc = (mtp3 & 268382208) >> 14
            opc = (mtp3 & 268419072) >> 14
            dpc = mtp3 & 16383
            
            gsm_map.mtp3_opc = opc
            gsm_map.mtp3_dpc = dpc
            
            sccp_layer = packet[5:]
    
    if len(sccp_layer) == 0:
        return None

    sccp_i = 0
    sccp_mess_type, = struct.unpack("!B", sccp_layer[sccp_i:sccp_i + 1])

    # if SCCP message type is not
    # a unitdata (9) or
    # an extended unitdata (17)
    # an extended unitdata service (18)
    if sccp_mess_type not in [9, 17, 18]:
        return None

    # Adding 5 bytes message_type (1 byte) + class (1) +
    # pointer01 (1) + pointer02 (1) + pointer03 (1)
    sccp_i += 5
    if sccp_mess_type in [17, 18]:
        sccp_i += 2

    sccp_called_addr_len, = struct.unpack("!B", sccp_layer[sccp_i:sccp_i + 1])
    sccp_i += sccp_called_addr_len + 1

    sccp_calling_addr_len, = struct.unpack("!B", sccp_layer[sccp_i:sccp_i + 1])
    segmentation = 0
    
    tcap_layer = []
    if sccp_calling_addr_len in [9, 10, 11, 12, 13]:
        sccp_i += sccp_calling_addr_len + 1
        sccp_data_len, = struct.unpack("!B", sccp_layer[sccp_i:sccp_i + 1])
        sccp_i += 1
        tcap_layer = sccp_layer[sccp_i:sccp_i + sccp_data_len]
        sccp_i += sccp_data_len
        # check if the SCCP layer has segmentation
        if len(sccp_layer) == sccp_i + 7:
            tag, = struct.unpack("!B", sccp_layer[sccp_i:sccp_i + 1])
            sccp_i += 1
            if tag == 16:
                # store tcap_layer as SCCP data
                tag_len, = struct.unpack("!B", sccp_layer[sccp_i:sccp_i + 1])
                sccp_i += 1
                if tag_len == 4:
                    # store if the packet is the first segmentation
                    segmentation, = struct.unpack("!B", sccp_layer[sccp_i:sccp_i + 1])
                    sccp_i += 1
                    is_first = segmentation >> 7
                    key, = struct.unpack("!I", b"\x00" + sccp_layer[sccp_i:sccp_i + 3])
                    sccp_i += 4
                    if is_first == 1:
                        sccp_seg_dict[key] = tcap_layer
                        return None
                    else:
                        tcap_temp = sccp_seg_dict.get(key)
                        # If there is not previous segmentation the TCAP layer is incompleted
                        # and it can not continue processing the packet, returning None
                        # otherwise it concatenates to the previous one
                        if tcap_temp == None:
                            return None
                        
                        if segmentation > 0:
                            sccp_seg_dict[key] = tcap_temp + tcap_layer
                            return None
                        else:
                            tcap_layer = tcap_temp + tcap_layer
                            sccp_seg_dict.pop(key, None)
    elif sccp_calling_addr_len == 4:
        return None
    else:
        sccp_data_len = sccp_calling_addr_len
        sccp_i += 1
        tcap_layer = sccp_layer[sccp_i:sccp_i + sccp_data_len]
        sccp_i += sccp_data_len
        sccp_calling_addr_len, = struct.unpack("!B", sccp_layer[sccp_i:sccp_i + 1])
        sccp_i += sccp_calling_addr_len + 1

    if len(sccp_layer) != sccp_i:
        return None
    
    tcap_decode = TCAP_MAPv2v3.TCAP_MAP_Messages.TCAP_MAP_Message
    error = None
    try:
        tcap_decode.from_ber(tcap_layer)
    except Exception as e:
        error = e
    
    if error != None and "TCAP-MAP-Message.abort" in error.args[0]:
        mess_type, = struct.unpack("!B", tcap_layer[0:1])
        if mess_type == 103:
            gsm_map.tcap_mess_type = "abort"
            dtid, len_dtid = struct.unpack("!2B", tcap_layer[2:4])
            t = tcap_layer[4: 4 + len_dtid]
            t = b"\x00" + t if len(t) == 3 else t
            if dtid == 73:
                tid, = struct.unpack("!I", t)
                gsm_map.tcap_dtid = tid
            return gsm_map
    
    if not type(tcap_decode()[0]).__name__ == "str":
        return None

    gsm_map.tcap_mess_type = tcap_decode()[0]

    otid = get_value("otid", tcap_decode()[1])
    if type(otid).__name__ == "bytes":
        otid = b'\x00' + otid if len(otid) == 3 else otid
        if len(otid) < 3:
            print(f"length of otid is lesser than 3, otid: {otid}, frame: {frame}")
        gsm_map.tcap_otid, = struct.unpack("!I", otid)
    
    dtid = get_value("dtid", tcap_decode()[1])
    if type(dtid).__name__ == "bytes":
        dtid = b'\x00' + dtid if len(dtid) == 3 else dtid
        if len(dtid) < 3:
            print(f"length of otid is lesser than 3, otid: {dtid}, frame: {frame}")
        gsm_map.tcap_dtid, = struct.unpack("!I", dtid)

    if gsm_map.tcap_mess_type == 'begin' or gsm_map.tcap_mess_type == 'continue':
        gsm_map.tcap_tid = gsm_map.tcap_otid

    if gsm_map.tcap_mess_type == 'end' or gsm_map.tcap_mess_type == 'abort':
        gsm_map.tcap_tid = gsm_map.tcap_dtid
    
    dialog = get_value("dialoguePortion", tcap_decode()[1])
    if not dialog == None and type(dialog).__name__ == "dict":
        gsm_map.tcap_result = get_value("result", dialog)
    
    opcode = get_value("opcode", tcap_decode()[1])
    if type(opcode).__name__ == "tuple":
        gsm_map.gsm_op_code = opcode[1]
    
    errcode = get_value("errcode", tcap_decode()[1])
    if type(errcode).__name__ == "tuple":
        gsm_map.gsm_error_code = errcode[1]
    
    imsi = get_value("imsi", tcap_decode()[1])
    if imsi == None:
        imsi = get_value("destinationReference", tcap_decode()[1])
    if imsi != None and (len(imsi) == 8 or len(imsi) == 9):
        imsi_bytes = str(hexlify(imsi[-8:]), "utf-8")
        imsi_str = ""
        for i in range(0, len(imsi_bytes), 2):
            imsi_str += imsi_bytes[i:i + 2][::-1]
        if imsi_str == "":
            imsi_str = None
        gsm_map.imsi = imsi_str[:-1]

    msisdn = None
    if gsm_map.gsm_op_code in [44, 46]:
        smRPUI = get_value("sm-RP-UI", tcap_decode()[1])
        if smRPUI != None and len(smRPUI) > 10:
            isSubmit, msisdnLen, msisdnDet = struct.unpack("3B", smRPUI[0:3])
            isSubmitInt = isSubmit & 3
            msisdnTON = (msisdnDet & 112) >> 4
            msisdnNPI = msisdnDet & 15
            if msisdnTON == 1 and msisdnNPI == 1:
                if isSubmitInt == 1:
                    msisdn = smRPUI[2:10]
                else:
                    msisdn = smRPUI[1:9]
    else:
        msisdn = get_value("msisdn", tcap_decode()[1])

    if msisdn != None and (len(msisdn) in [7, 8]):
        msisdn_bytes = str(hexlify(msisdn[-6:]), "utf-8")
        msisdn_str = ""
        for i in range(0, len(msisdn_bytes), 2):
            msisdn_str += msisdn_bytes[i:i + 2][::-1]
        if msisdn_str == "":
            msisdn_str = None
        gsm_map.msisdn = msisdn_str.replace("f", "")
    
    component_type = ""
    components = get_value("components", tcap_decode()[1])
    if not components == None and len(components) > 0:
        component_type = components[0][1][0]
    match component_type:
        case "invoke":
            gsm_map.gsm_component = 1
        case "returnResult":
            gsm_map.gsm_component = 2
        case "returnError":
            gsm_map.gsm_component = 3
        case "reject":
            gsm_map.gsm_component = 4

    return gsm_map


def process_pcap(pcap_file, pcap_global_hdr, endian):
    frame = 0
    ss7_frames = 0
    not_processed = 0
    ss7_list = []

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

            ss7 = get_gsm_map(frame, dlt, header, packet)

            if ss7 == None:
                continue
        except Exception:
            # print(f"frame {frame} not processed of the PCAP file {filename}")
            not_processed += 1
            continue
        ss7_frames += 1
        ss7_list.append(ss7)
        if len(ss7_list) == 1000:
            db.bulk_save_objects(ss7_list)
            db.commit()
            ss7_list.clear()
    if len(ss7_list) > 0:
        db.bulk_save_objects(ss7_list)
        db.commit()
    print(f"{ss7_frames} processed / {not_processed} NOT processed SS7 frames out of {frame} packets in the PCAP file {filename}.")

    global total_processed
    total_processed = ss7_frames
    global total_not_processed
    total_not_processed = not_processed


def process_pcapng(pcapng_file, pcap_global_hdr, endian):
    frame = 0
    ss7_frames = 0
    not_processed = 0
    ss7_list = []

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

            ss7 = get_gsm_map(frame, dlt, header, packet)

            if ss7 == None:
                continue
        except Exception:
            # print(f"frame {frame} not processed of the PCAP file {filename}")
            not_processed += 1
            continue
        ss7_frames += 1
        ss7_list.append(ss7)
        if len(ss7_list) == 1000:
            db.bulk_save_objects(ss7_list)
            db.commit()
            ss7_list.clear()
    if len(ss7_list) > 0:
        db.bulk_save_objects(ss7_list)
        db.commit()
    print(f"{ss7_frames} processed / {not_processed} NOT processed SS7 frames out of {frame} packets in the PCAPNG file {filename}.")
    global total_processed
    total_processed = ss7_frames
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
