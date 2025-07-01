#!/bin/bash
echo $(date)
protocol=dra
#path for python scripts
PyPath=/opt/paic/nbm_ingestion
#temporal files
tempDir=/opt/paic/nbm_ingestion/temp
#path received like PCAP_FILE
fullpath=$1
#only path wihtout file name
path=${fullpath%/*}
# online name of file
fileName=${fullpath##*/}
#only name wihtout type
Name=${fileName%\.*}
#type of the file
type=${fileName##*\.}
pcap=pcap
pcapng=pcapng
#validate if is pcap or pcapng
if [ $type = $pcap ]
then
	echo "convert to pcapng"
	cp $path/$fileName $path/$Name.$pcapng
else
	echo "no convert"
fi

#change to pcap format to continue with the next step
time tshark -F pcap -r $path/$Name.$pcapng -w $tempDir/$Name.$pcap

#use sigshark.py to divide the transacctions in packets
time python3 $PyPath/sigshark.py -f -i -t $tempDir/$Name.$pcap $tempDir/sigshark-$Name.$pcap

#create a json file with tshark with the minimun information
# next line commented on 2022-11-16
# time tshark -r $tempDir/sigshark-$Name.$pcap -Y diameter -e frame.time_epoch -e frame.number -e diameter.Origin-Host -e diameter.Destination-Realm -e diameter.Destination-Host -e diameter.Origin-Realm -e e212.imsi -e diameter.Result-Code -e diameter.cmd.code -e diameter.hopbyhopid -e ip.dst -e diameter.Session-Id -e diameter.User-Name -e e212.mnc -e ip.src -e diameter.endtoendid -e diameter.applicationId -e diameter.Experimental-Result-Code -e diameter.avp -e diameter.avp.code -e e164.msisdn -E separator=, -E occurrence=a -T json -x > $tempDir/tshark-$Name.json
time python main.py $tempDir/sigshark-$Name.$pcap

echo "json with tshark"
#cat $path/tshark-$Name.json | time python3 parser.py $path/tshark-$Name.json  > $path/final-$Name.json

#parse the json with parser py and ingest to druid with kafka
# next line commented on 2022-11-16
# cat $tempDir/tshark-$Name.json | time python3 $PyPath/parser.py $fullpath | /opt/kafka_2.13-3.3.1/bin/kafka-console-producer.sh --bootstrap-server ec2-3-129-17-65.us-east-2.compute.amazonaws.com:9092 --topic $2


#cat $tempDir/tshark-$Name.json | time python3 $PyPath/parser.py $fullpath > $tempDir/tshark-$Name-after-parser.json

echo "Ingested"

#/opt/kafka/bin/kafka-console-producer.sh --broker-list 50.116.40.86:9092 --topic {TOPIC_NAME}

#delete the temporal files created
rm -rf $tempDir/sigshark-$Name.pcap $tempDir/tshark-$Name.json $tempDir/$Name.$pcap
if [ $type = $pcap ]
then
        echo "Delete termporary pcapng file"
        rm -rf $path/$Name.$pcapng
else
        echo "Not necessary to delete temporary pcapng"
fi


echo "Temporay files deleted"
#echo $(date)