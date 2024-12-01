# Author Shahyan Pervez Bharucha
'''"This code/software is provided 'as is' without any warranty, express or implied, including warranties of merchantability or fitness for a particular purpose."'''
import socket
import time
import binascii
HOST = '192.168.10.10'    # The remote host
PORT = 10001              # The same port as used by the server
# Protocol manual refernce link https://files.pepperl-fuchs.com/webcat/navi/productInfo/doct/tdoct8610__eng.pdf?v=20240116192218
# List to store unique IDD Data

'''This is a starter/example program that interfaces with Pepperl and Fuchs RFID read/write device IUR-F800-V1D-4A-FR2-02
RFID read/write device IUR-F800-V1D-4A-FR2-02 has several modes to transfer tag data via different physical mediums such as USB, Serial and Ethernet.
This is utilizing Ethernet as its physical layer, which as two modes. Notification mode and Buffer mode, below example uses Buffer mode which is a command and response model -> refernce page 115 for buffered read mode 
procedure
By using the “BRM” the reader itself reads data from every transponder which is
inside the antenna field. This mode must be enabled in the CFG1: Interface and
Mode configuration block and configured in the CFG11: Read Mode , Read Data
and CFG12: Read Mode  Filter configuration blocks.
The sampled transponder data sets are stored in a FIFO organized data buffer
inside the reader. The buffered read mode runs offline from any host commands
and it is immediately started after power up or a [0x63] RF Controller Reset
command.
Only two commands are necessary to read out sampled transponder data sets Read Buffer [0x22] and [0x32] Clear Data Buffer'''

unique_idd_list = [] # Declaring List variable to store unique idd Identifier Data (EPC or EPC+TID)

#CRC calculation procedure
def crc16(data: bytes, crc_preset: int = 0xFFFF, poly: int = 0x8408) -> int: # CRC16 from manual pg 19
    crc = crc_preset
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1
    return crc & 0xFFFF

#Method to send command depending on request send in the command ReadB -> Read Buffer, ClearB -> Clear Buffer, InitB -> Initialize Buffer (not used for this but included to give the idea to use command)
#If you go through comments in the method it will explain how a command is made with reference. 
def GetCommand(Command):

    if (Command == "ReadB"):
        stx = 0x02 #0x02 indicates the start of the data
        '''STX
        If the responded protocol of the reader starts with the STX sign (0x02) the
        protocol includes more than 255 Byte. Then the protocol length is defined by the
        2 Byte Parameter ALENGTH.
        '''
        MSB_ALENGHT = 0x00 
        LSB_ALENGHT = 0x09 #MSB + LSB tells the length of the command which is 9 bytes for READ Buffer
        '''ALENGTH (n = 8...65535)
        Number of protocol bytes including STX, ALENGTH and CRC16 pg 17'''
        COM_ADR = 0xFF  #decimal value 255
        '''COM-ADR
        0..254 address of device in bus mode The reader can be addressed via COM-ADR 255 at any time. pg 17'''
        Read_Buffer = 0x22 # read buffer command is 0x22
        DATA_SETS = [0x00,0xFF]
        '''DATA-SETS:
        Number of data sets to be transferred from the data buffer of the reader to the
        Host. If the data buffer does not contain the requested number of data sets, the
        reader responds with all available data sets and an error will occur. pg 157 '''

        Read_Buffer_Command_No_CRC = bytes([stx, MSB_ALENGHT, LSB_ALENGHT, COM_ADR, Read_Buffer, DATA_SETS[0], DATA_SETS[1]]) #forming the command to be sent for CRC16 check bytes
        
        crc_result = crc16(Read_Buffer_Command_No_CRC)
        crc_byteswapped = ((crc_result & 0x00FF) << 8) | ((crc_result & 0xFF00) >> 8) #performing a byteswap and below two lines are seprating the bytes to be sent via bytes in command
        crc_lsb = ((crc_result & 0xFF00)) >> 8
        crc_msb = ((crc_result & 0x00FF))
        crc_16 = f"{crc_byteswapped:04X}"

        print(f" The CRC-16 Generated for the command is {crc_16}")

        Read_Buffer_Command_With_CRC = bytes([stx, MSB_ALENGHT, LSB_ALENGHT, COM_ADR, Read_Buffer, DATA_SETS[0], DATA_SETS[1], crc_msb, crc_lsb ]) 

        return Read_Buffer_Command_With_CRC

    elif (Command == "ClearB"):
        stx = 0x02 #0x02 indicates the start of the data
        '''STX
        If the responded protocol of the reader starts with the STX sign (0x02) the
        protocol includes more than 255 Byte. Then the protocol length is defined by the
        2 Byte Parameter ALENGTH.
        '''
        MSB_ALENGHT = 0x00 
        LSB_ALENGHT = 0x07 #MSB + LSB tells the length of the command which is 7 bytes for clear Buffer
        '''ALENGTH (n = 8...65535)
        Number of protocol bytes including STX, ALENGTH and CRC16 pg 17'''
        COM_ADR = 0xFF  #decimal value 255
        '''COM-ADR
        0..254 address of device in bus mode The reader can be addressed via COM-ADR 255 at any time. pg 17'''
        Clear_Buffer = 0x32 # clear buffer command is 0x32
   

        Clear_Buffer_Command_No_CRC = bytes([stx, MSB_ALENGHT, LSB_ALENGHT, COM_ADR, Clear_Buffer]) #forming the command to be sent for CRC16 check bytes
        
        crc_result = crc16(Clear_Buffer_Command_No_CRC)
        crc_byteswapped = ((crc_result & 0x00FF) << 8) | ((crc_result & 0xFF00) >> 8)
        crc_lsb = ((crc_result & 0xFF00)) >> 8
        crc_msb = ((crc_result & 0x00FF))
        crc_16 = f"{crc_byteswapped:04X}"

        print(f" The CRC-16 Generated for the command is {crc_16}")

        Clear_Buffer_Command_With_CRC = bytes([stx, MSB_ALENGHT, LSB_ALENGHT, COM_ADR, Clear_Buffer, crc_msb, crc_lsb ]) 

        return Clear_Buffer_Command_With_CRC
    
    elif (Command == "InitB"):
        stx = 0x02 #0x02 indicates the start of the data
        '''STX
        If the responded protocol of the reader starts with the STX sign (0x02) the
        protocol includes more than 255 Byte. Then the protocol length is defined by the
        2 Byte Parameter ALENGTH.
        '''
        MSB_ALENGHT = 0x00 
        LSB_ALENGHT = 0x07 #MSB + LSB tells the length of the command which is 7 bytes for Initialize Buffer
        '''ALENGTH (n = 8...65535)
        Number of protocol bytes including STX, ALENGTH and CRC16 pg 17'''
        COM_ADR = 0xFF  #decimal value 255
        '''COM-ADR
        0..254 address of device in bus mode The reader can be addressed via COM-ADR 255 at any time. pg 17'''
        Initialize_Buffer = 0x33 # initialize buffer command is 0x32
   

        Initialize_Buffer_Command_No_CRC = bytes([stx, MSB_ALENGHT, LSB_ALENGHT, COM_ADR, Initialize_Buffer]) #forming the command to be sent for CRC16 check bytes
        
        crc_result = crc16(Initialize_Buffer_Command_No_CRC)
        crc_byteswapped = ((crc_result & 0x00FF) << 8) | ((crc_result & 0xFF00) >> 8)
        crc_lsb = ((crc_result & 0xFF00)) >> 8
        crc_msb = ((crc_result & 0x00FF))
        crc_16 = f"{crc_byteswapped:04X}"

        #print(f" The CRC-16 Generated for the command is {crc_16}")

        Initialize_Buffer_Command_With_CRC = bytes([stx, MSB_ALENGHT, LSB_ALENGHT, COM_ADR, Initialize_Buffer, crc_msb, crc_lsb ]) 

        return Initialize_Buffer_Command_With_CRC

    

#Below is the method which accepts the buffer data and parses it with refernce to pg 157 onwards
def Parser(RFIDData):
    # Convert hex data to raw bytes
    byte_data = binascii.unhexlify(RFIDData)

    # Parse each field based on the described format on Page 157
    stx = byte_data[0]  #  - STX
    msb_length = byte_data[1]  #  - MSB Length
    lsb_length = byte_data[2]  #  - LSB Length
    com_adr = byte_data[3]  #  - COM-ADR
    command = byte_data[4]  #  - Command
    Status = byte_data[5]  #  - Status
    tr_data1 = byte_data[6]  #  - TR-DATA1

    # Combine MSB and LSB length to get buffer length
    buffer_length = (msb_length << 8) | lsb_length

    # Print parsed values
    print(f"STX: 0x{stx:02X}")
    print(f"MSB Length: 0x{msb_length:02X}")
    print(f"LSB Length: 0x{lsb_length:02X}")
    print(f"Buffer Length: {buffer_length}")
    print(f"COM-ADR: 0x{com_adr:02X}")
    print(f"Command: 0x{command:02X}")
    print(f"Status: 0x{Status:02X}")
    print(f"TR-DATA1: 0x{tr_data1:02X}")

    if f"0x{Status:02X}" != "0x00":
        print(f"0x{Status:02X}")
        return f"0x{Status:02X}"
    
    # Parse TR-DATA1 for bitwise information
    extension = (tr_data1 >> 7) & 0x01
    date = (tr_data1 >> 6) & 0x01
    time = (tr_data1 >> 5) & 0x01
    ant = (tr_data1 >> 4) & 0x01
    byte_order_db = (tr_data1 >> 3) & 0x01
    db = (tr_data1 >> 1) & 0x01
    idd = tr_data1 & 0x01

    # Print TR-DATA1 bitwise information
    print("\nTR-DATA1 Bit Information:")
    print(f"Extension: {'Yes' if extension else 'No'}")
    print(f"Date: {'Yes' if date else 'No'}")
    print(f"Timer: {'Yes' if time else 'No'}")
    print(f"ANT: {'Yes' if ant else 'No'}")
    print(f"Byte Order DB: {'Yes' if byte_order_db else 'No'}")
    print(f"DB: {'Yes' if db else 'No'}")
    print(f"IDD: {'Yes' if idd else 'No'}")

    # Parse TR-DATA2 if Extension is 1, otherwise parse Data Sets
    if extension:
        tr_data2 = byte_data[7]
        ant_ext = (tr_data2 >> 4) & 0x01
        tag_statistics = (tr_data2 >> 3) & 0x01
        mac = (tr_data2 >> 1) & 0x01
        in_bit = tr_data2 & 0x01

        # Print TR-DATA2 bitwise information
        print("\nTR-DATA2 Bit Information:")
        print(f"ANT_EXT: {'Yes' if ant_ext else 'No'}")
        print(f"TAG_STATISTICS: {'Yes' if tag_statistics else 'No'}")
        print(f"MAC: {'Yes' if mac else 'No'}")
        print(f"IN: {'Yes' if in_bit else 'No'}")

        # Set the index for tag data based on TR-DATA2
        tag_data_start_index = 8

    else:
        # If Extension is 0, the next two bytes represent DATA sets 
        '''DATA-SETS:
        Number of data sets to be transferred from the data buffer of the reader to the
        Host. If the data buffer does not contain the requested number of data sets, the
        reader responds with all available data sets and an error will occur.'''
        data_sets = (byte_data[7] << 8) | byte_data[8]
        print(f"\nDATA Sets (Number of Tags): {data_sets}")

        # Set the index for tag data based on DATA sets
        tag_data_start_index = 9

    # Extract the tag data starting from tag_data_start_index to buffer_length
    tag_data = byte_data[tag_data_start_index:buffer_length + tag_data_start_index]

    # Print the tag data in hexadecimal format
    print(f"\nTag Data ({len(tag_data)} bytes): {binascii.hexlify(tag_data)}")

    # Data is parsed using reference to pg 159, following pages have decription of the each section
    # Initialize an index to traverse through the byte_data
    index = 0
    # Convert hex data to raw bytes
    byte_data = tag_data
    
    if command == 0x22:
        while index < len(byte_data)-2:
            # Step 1: Parse MSBRecLen and LSBRecLen
            msb_rec_len = byte_data[index]
            lsb_rec_len = byte_data[index + 1]
            total_length = (msb_rec_len << 8) | lsb_rec_len
            index += 2

            # Total length should be reduced by 2 as per the requirement
            length = total_length - 2

            # Step 2: Parse TR-TYP
            tr_typ = byte_data[index]
            index += 1

            # Step 3: Parse IDDIB
            iddib = byte_data[index]
            index += 1

            # Step 4: Parse IDD-LEN
            idd_len = byte_data[index]
            index += 1

            # Step 5: Parse IDD Data
            idd_data = byte_data[index:index + idd_len]
            index += idd_len

            # Check if IDD Data is unique
            if binascii.hexlify(idd_data).decode() not in unique_idd_list:
                unique_idd_list.append(binascii.hexlify(idd_data).decode())
                print(f"New unique IDD Data found: {binascii.hexlify(idd_data).decode()}")

            # Step 6: Parse DB-N
            db_n = (byte_data[index] << 8) | byte_data[index + 1]
            index += 2

            # Step 7: Parse DB-SIZE
            db_size = byte_data[index]
            index += 1

            # Step 8: Parse DB Data
            db_data = byte_data[index:index + db_size]
            db_data_ascii = db_data.decode('ascii', errors='replace')  # Decode to ASCII
            index += db_size

            # Step 9: Parse Time Data (4 bytes)
            hours = byte_data[index]
            minutes = byte_data[index + 1]
            milliseconds = (byte_data[index + 2] << 8) | byte_data[index + 3]
            index += 4

            # Step 10: Parse ANT (1 byte)
            ant_byte = byte_data[index]
            ant = {
                'Antenna 1': bool(ant_byte & 0x01),
                'Antenna 2': bool(ant_byte & 0x02),
                'Antenna 3': bool(ant_byte & 0x04),
                'Antenna 4': bool(ant_byte & 0x08)
            }
            index += 1

            # Print parsed data for the current tag
            print(f"Record Length: {total_length}")
            print(f"TR-TYP: 0x{tr_typ:02X}")
            print(f"IDDIB: 0x{iddib:02X}")
            print(f"IDD-LEN: {idd_len} bytes")
            print(f"IDD Data: {binascii.hexlify(idd_data).decode()}")
            print(f"Number of Data Blocks (DB-N): {db_n}")
            print(f"Data Block Size (DB-SIZE): {db_size} bytes")
            print(f"Data Block (DB) Data (ASCII): {db_data_ascii} ({binascii.hexlify(db_data).decode()})")
            print(f"Time: {hours:02d}:{minutes:02d}, {milliseconds} ms")
            print("ANT Information:")
            for key, value in ant.items():
                print(f"  {key}: {'Yes' if value else 'No'}")
            print('-' * 50)
    elif command == 0x32:
        print("Cleared Buffer")
    # Move to the next tag
    return f"0x{Status:02X}"


#GetCommand("ClearB")

NumofReads = 50

def main():
    for i in range(NumofReads):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.sendall(GetCommand("ReadB"))
            time.sleep(0.006)
            IncomingData = s.recv(1024)
            #print('Received', binascii.hexlify(IncomingData))
            Statuses = {
                        "0x92": "No valid Data",
                        "0x93": "Data Buffer Overflow",
                        "0x94": "More Data",
                        "0x95": "Tag Error",
                        "0x00": "OK"
                        }
            
            Status = Parser(binascii.hexlify(IncomingData))
            print(Status)
            print(f'The status returned from the Buffer Read command is { Statuses[Status]}')
            if Status != "0x92":
                s.sendall(GetCommand("ClearB"))
                time.sleep(0.006)
            time.sleep(1)
            s.close()

    print(unique_idd_list)

if __name__ == '__main__':
    main()