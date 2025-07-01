import os.path
import sys
from models import Camel, Base, IngestionQueue
import database
import json

mess_type_dict = {
    0: "initialDP",
    16: "assistRequestInstructions",
    17: "establishTemporaryConnection",
    18: "disconnectForwardConnection",
    19: "connectToResource",
    20: "connect",
    22: "releaseCall",
    23: "requestReportBCSMEvent",
    24: "eventReportBCSM",
    31: "continue",
    56: "continueWithArgument",
    33: "resetTimer",
    34: "furnishChargingInformation",
    35: "applyCharging",
    36: "applyChargingReport",
    41: "callGap",
    44: "callInformationReport",
    45: "callInformationRequest",
    46: "sendChargingInformation",
    47: "playAnnouncement",
    48: "promptAndCollectUserInformation",
    49: "specializedResourceReport",
    53: "cancel",
    55: "activityTest",
    60: "initialDPSMS",
    61: "furnishChargingInformationSMS",
    62: "connectSMS",
    63: "requestReportSMSEvent",
    64: "eventReportSMS",
    65: "continueSMS",
    66: "releaseSMS",
    67: "resetTimerSMS",
    70: "activityTestGPRS",
    71: "applyChargingGPRS",
    72: "applyChargingReportGPRS",
    73: "cancelGPRS",
    74: "connectGPRS",
    75: "continueGPRS",
    76: "entityReleasedGPRS",
    77: "furnishChargingInformationGPRS",
    78: "initialDPGPRS",
    79: "releaseGPRS",
    80: "eventReportGPRS",
    81: "requestReportGPRSEvent",
    82: "resetTimerGPRS",
    83: "sendChargingInformationGPRS"
}

total_processed = 0
total_not_processed = 0

def get_value_from_array(a):
    if a == None:
        return None
    
    value = ""
    
    for x in a:
        value = value + x + " "
    
    return value


def get_value(key_name, obj):
    if key_name == "" or key_name == None or obj == None:
        return None
    
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


def get_camel(json_packet):
    if json_packet["_source"] == None:
        return None
    
    if json_packet["_source"]["layers"] == None:
        return None
    
    json_camel = json_packet["_source"]["layers"]
    
    camel = Camel()
    
    camel.frames_list = json_camel["frame.number"][0]
    
    epoch = json_camel["frame.time_epoch"][0].split(".")
    if epoch == None:
        return None
    
    camel.time_epoch = int(epoch[0])
    camel.useconds_epoch = int(epoch[1])
    
    camel.src_ip = None if "ip.src" not in json_camel else json_camel["ip.src"][0]
    camel.dst_ip = None if "ip.dst" not in json_camel else json_camel["ip.dst"][0]
    
    camel.mtp3_opc = None if "mtp3.opc" not in json_camel else int(json_camel["mtp3.opc"][0])
    if camel.mtp3_opc == None:
        camel.mtp3_opc = None if "m3ua.protocol_data_opc" not in json_camel else int(json_camel["m3ua.protocol_data_opc"][0])
    camel.mtp3_dpc = None if "mtp3.dpc" not in json_camel else int(json_camel["mtp3.dpc"][0])
    if camel.mtp3_dpc == None:
        camel.mtp3_dpc = None if "m3ua.protocol_data_dpc" not in json_camel else int(json_camel["m3ua.protocol_data_dpc"][0])
    
    camel.tcap_otid = None if "tcap.otid" not in json_camel else int(json_camel["tcap.otid"][0], 16)
    camel.tcap_dtid = None if "tcap.dtid" not in json_camel else int(json_camel["tcap.dtid"][0], 16)
    
    camel.gsm_cld_party_bcd_num = None if "gsm_a.dtap.cld_party_bcd_num" not in json_camel else json_camel["gsm_a.dtap.cld_party_bcd_num"][0]
    value = get_value_from_array(None if "e164.country_code" not in json_camel else json_camel["e164.country_code"])
    camel.called_party_number_digits = None if "e164.called_party_number.digits" not in json_camel else json_camel["e164.called_party_number.digits"][0]
    camel.calling_party_number_digits = None if "e164.calling_party_number.digits" not in json_camel else json_camel["e164.calling_party_number.digits"][0]
    value = get_value_from_array(None if "e164.msisdn" not in json_camel else json_camel["e164.msisdn"])
    camel.msisdn = None if value == None else value.strip()
    value = get_value_from_array(None if "e212.imsi" not in json_camel else json_camel["e212.imsi"])
    camel.imsi = None if value == None else value.strip()
    camel.camel_local = None if "camel.local" not in json_camel else int(json_camel["camel.local"][0])
    camel.camel_calling_party_number = None if "camel.callingPartyNumber" not in json_camel else json_camel["camel.callingPartyNumber"][0]
    camel.camel_called_party_number = None if "camel.CalledPartyNumber" not in json_camel else json_camel["camel.CalledPartyNumber"][0]
    camel.tcap_mess_type = mess_type_dict[camel.camel_local]

    camel.tcap_tid = camel.tcap_otid if camel.tcap_mess_type.lower() == 'initialdp' else camel.tcap_dtid

    camel.pcap_filename = pcapfile
    
    return camel

def find_json_by_key(id, json_repr):
    try:
        results = []
        def _decode_dict(a_dict):
            try:
                results.append(a_dict[id])
            except KeyError:
                pass
            return a_dict

        json.loads(json_repr, object_hook=_decode_dict)
        return results
    except Exception as ex:
        print(f'Error matching the JSON key value: {str(ex)}')
        return None


def get_camel_as_json(json_packet):
    try:
        json_packet = json.dumps(json_packet)
        camel = Camel()

        camel.frames_list = find_json_by_key("frame.number", json_packet)[0]

        epoch = find_json_by_key("frame.time_epoch", json_packet)[0].split(".")
        if epoch is None:
            return None

        camel.time_epoch = int(epoch[0])
        camel.useconds_epoch = int(epoch[1])

        camel.src_ip = find_json_by_key("ip.src", json_packet)[0]
        camel.dst_ip = find_json_by_key("ip.dst", json_packet)[0]

        camel.mtp3_opc = None if len(find_json_by_key("mtp3.opc", json_packet)) == 0 else int(find_json_by_key("mtp3.opc", json_packet)[0])
        if camel.mtp3_opc is None:
            camel.mtp3_opc = None if len(find_json_by_key("m3ua.protocol_data_opc", json_packet)) == 0 else int(
                find_json_by_key("m3ua.protocol_data_opc", json_packet)[0])

        camel.mtp3_dpc = None if len(find_json_by_key("mtp3.dpc", json_packet)) == 0 else int(
            find_json_by_key("mtp3.dpc", json_packet)[0])
        if camel.mtp3_dpc is None:
            camel.mtp3_dpc = None if len(find_json_by_key("m3ua.protocol_data_dpc", json_packet)) == 0 else int(
                find_json_by_key("m3ua.protocol_data_dpc", json_packet)[0])

        camel.tcap_otid = None if len(find_json_by_key("tcap.otid", json_packet)) == 0 else int(str(find_json_by_key("tcap.otid", json_packet)[0]).replace(':', ''), 16)
        camel.tcap_dtid = None if len(find_json_by_key("tcap.dtid", json_packet)) == 0 else int(str(find_json_by_key("tcap.dtid", json_packet)[0]).replace(':', ''), 16)

        camel.gsm_cld_party_bcd_num =  None if  len(find_json_by_key("gsm_a.dtap.cld_party_bcd_num", json_packet)) == 0 else \
            find_json_by_key("gsm_a.dtap.cld_party_bcd_num", json_packet)[0]

        camel.called_party_number_digits = None if len(find_json_by_key("e164.called_party_number.digits", json_packet)) == 0 else \
            find_json_by_key("e164.called_party_number.digits", json_packet)[0]

        camel.calling_party_number_digits = None if len(find_json_by_key("e164.calling_party_number.digits", json_packet)) == 0 else \
            find_json_by_key("e164.calling_party_number.digits", json_packet)[0]

        value = get_value_from_array(None if len(find_json_by_key("e164.msisdn", json_packet)) == 0 else find_json_by_key("e164.msisdn", json_packet)[0])
        camel.msisdn = None if value is None else value.replace(' ', '').strip()

        value = get_value_from_array(None if len(find_json_by_key("e212.imsi", json_packet)) == 0 else find_json_by_key("e212.imsi", json_packet)[0])
        camel.imsi = None if value is None else value.replace(' ', '').strip()

        camel.camel_local = None if len(find_json_by_key("camel.local", json_packet)) == 0 else int(find_json_by_key("camel.local", json_packet)[0])

        camel.camel_calling_party_number = None if len(find_json_by_key("camel.callingPartyNumber", json_packet)) == 0 else \
            find_json_by_key("camel.callingPartyNumber", json_packet)[0]

        camel.camel_called_party_number =None if len(find_json_by_key("camel.CalledPartyNumber", json_packet)) == 0 else \
            find_json_by_key("camel.CalledPartyNumber", json_packet)[0]

        camel.tcap_mess_type = mess_type_dict[camel.camel_local]

        camel.tcap_tid = camel.tcap_otid if camel.tcap_mess_type.lower() == 'initialdp' else camel.tcap_dtid

        camel.pcap_filename = pcapfile

        return camel
    except Exception as e:
        print(f'Error is {str(e)}')


def process_json(json_data):
    frame = 0
    camel_frames = 0
    not_processed = 0
    camel_list = []
    
    for json_packet in json_data:
        frame += 1
        try:
            camel = get_camel(json_packet)

            if camel == None:
                continue
        except Exception:
            # print(f"frame {frame} not processed of the JSON file {jsonfile}")
            not_processed += 1
            continue
        camel_frames += 1
        camel_list.append(camel)
        if len(camel_list) == 1000:
            db.bulk_save_objects(camel_list)
            db.commit()
            camel_list.clear()
    if camel_list != None and len(camel_list) > 0:
        db.bulk_save_objects(camel_list)
        db.commit()
    print(f"{camel_frames} processed / {not_processed} NOT processed Camel frames out of {frame} packets in the JSON file {jsonfile}")

    global total_processed
    total_processed = camel_frames
    global total_not_processed
    total_not_processed = not_processed

if len(sys.argv) < 4:
    raise Exception("The JSON file parameter was not specified")
jsonfile = sys.argv[1]
pcapfile = sys.argv[2]

if not os.path.exists(jsonfile):
    raise Exception("The JSON file does not exist")

Base.metadata.create_all(database.engine)

with open(jsonfile, "rb") as json_file:
    json_data = json.load(json_file)
    
    with database.get_db() as db:
        process_json(json_data)

    with database.get_db_ingestion() as db2:
        ingestion_id = sys.argv[3]
        db2.query(IngestionQueue).filter(IngestionQueue.id == ingestion_id).update({'processed': total_processed, 'not_processed': total_not_processed})
        db2.commit()
