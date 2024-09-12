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
import tsl_v5_processing as tslv5

def main():
    # MAIN VARIABLES, CHANGE THESE.
    src_file = "test.pcap" 
    wireshark_csv = "wireshark.csv"
    output = "output.csv"

    # Convert pcap to csv
    tslv5.convert_pcap(src_file, wireshark_csv)

    # Read csv file
    tslv5.TSL_V5_Decode(wireshark_csv, output)

if __name__ == "__main__":
    main()