"""
**********************************************************

            WIRESHARK TSL V5 DECODER
        Program to decode wireshark pcap 
        dump and extract TSL V5 information. 
        available as commandline functions


        author: Farhan Chowdhry
        date_modified: 

**********************************************************
"""

import subprocess
import csv 

class decoded_packet():
    """
    class to store decoded packet information
    """
    def __init__(self, frame_num, date, ip_src, ip_dest, data):
        self.frame_num = frame_num
        self.date = date
        self.ip_src = ip_src
        self.ip_dest = ip_dest
        self.data = data

def convert_pcap(src_file, dest_file) -> None:
    """
    Convert pcap file to csv while keeping data column

    args: source file, destination file
    return: None

    """
    print("Converting pcap to csv...")
    command = (
        f"tshark -r {src_file} -T fields -e frame.number -e frame.time -e ip.src -e ip.dst -e frame.len -e ip.proto -e data.data -E header=y -E separator=, -E quote=d > {dest_file}"
    )
    subprocess.run(command, shell=True)
    print("Conversion complete.")

def TSL_V5_Decode(file, output_file) -> None:
    """
    Takes CSV file and create a new file with decoded TSL V5 packets

    args: csv file of wireshark data, output file to write to 
    return: None
    """
    print("Decoding TSL V5 packets...")
    decoded_packets = []

    # Open the CSV file and read the data column
    with open(file) as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        next(csv_reader)
        for row in csv_reader:
            packet = decoded_packet(row[0], row[1], row[2], row[3], row[6])
            data = row[6]
            if len(data) < 24:
                continue
            packet = parse_data(data, packet)
            decoded_packets.append(packet)
        csv_file.close()

    # Write the decoded packets to a new file

    with open(output_file, 'w') as output:
        writer = csv.writer(output)
        writer.writerow(["FRAME_NUM", "DATE", "SRC_IP", "DEST_IP", "DATA", "START", "PBC", "VER", "FLAG", "SCREEN", "INDEX", "CONTROL", "CONTDATA", "RIGHT_TALLY", "TEXT_TALLY", "LEFT_TALLY", "BRIGHTNESS", "CONTROL_DATA_FLAG"])
        for packet in decoded_packets:
            writer.writerow(packet.__dict__.values())
    
    print("Decoding complete.")


def parse_data(data, packet) -> decoded_packet:
    """
    Takes packet data and gives all TSL v5 information back 

    args: data of packet, decoded_packet class object to append to 
    returns: decoded_packet class object

    """
    #Based on TSL v5 protocol spec.
    packet.start = data[:4]
    packet.PBC = data[4:8]
    packet.Ver = data[8:10]
    packet.Flag = data[10:12]   
    packet.Screen = data[12:16]
    packet.index = data[16:20]
    packet.control = data[20:24]
    packet.contdata = data[24:] 
    
    # Convert the hex value to an integer
    control_value_int = int(data[20:24], 16)
    
    # Extract the bit values using bit masks and shifts
    packet.right_tally = (control_value_int & 0b0000000000000011)  # Bits 0-1
    packet.text_tally = (control_value_int & 0b0000000000001100) >> 2  # Bits 2-3
    packet.left_tally = (control_value_int & 0b0000000000110000) >> 4  # Bits 4-5
    packet.brightness = (control_value_int & 0b0000000001100000) >> 6  # Bits 6-7
    packet.control_data_flag = (control_value_int & 0b1000000000000000) >> 15  # Bit 15

    return packet

