import struct
import socket
import argparse
import time
import datetime


timeout = 0.4 # 400 ms

syn_flag = 0b0100
ack_flag = 0b0010
fin_flag = 0b1000 
res_flag = 0b0000 
header_size = 8
max_data = 992 
header_format = "!HHHH"


def create_header(seq_num, ack_num, flags, recv_window): 
    """
    Description:
    This function will create an 8-byte header, with the given sequence number,
    acknowledgement number, flags and receiver window. 
    And pack these bytes into a header with struct.
    
    Arguments:
    - seq_num(int): Sequence number of the packet, to identify the order of the packets

    - ack_num(int): Acknowledgement number, to acknowledge the packets.

    - flags(int): Bit flags to indicate SYN, ACK, FIN

    - recv_window(int): This is the size of the receiver window. 

    
    Returns:
    The packed 8 byte header, containing all the input arguments. And can be attached to the packet.

    Exceptions:
    None, but struct.error on invalid input
    """
    return struct.pack("!HHHH", seq_num, ack_num, flags, recv_window)


def parse_header(header_bytes):
    """
    Description:
    This function will parse the DRTP header, into its components 
    which are sequence number, acknowledgment number, flags and receiver window. 
    
    Arguments:
    - header_bytes (bytes): The object that has all the bytes which the header contains of.

    Returns:
    Returns the 4 integers, where each is unpacked from the header.

    Exceptions
    None
    """
    return struct.unpack("!HHHH", header_bytes)


def create_packet(seq_num, ack_num, flags, recv_window, data=b""):
    """
    Description:
    This function creates a packet, by combining the header to the data. 
    Packet is created by adding the header, to the data. 
    
    Arguments:
    - seq_num(int): Sequence number of the packet, to identify the order of the packets

    - ack_num(int): Acknowledgement number, to acknowledge the packets.

    - flags(int): Bit flags to indicate SYN, ACK, FIN this to indicate the type of the packet. 

    - recv_window(int): This is the size of the receiver window.

    - data(bytes): This is the data, that is going to be included into the packet.

    Returns:
    The fully packed packet, containing the 8 byte header and the data, to send it. 
    
    Exceptions
    None
    """
    header = create_header(seq_num, ack_num, flags, recv_window)
    return header + data

def extract_packet(packet):
    """
    Description:
    Split the received packet, into data and header. 
    Saves the first 8 bytes as header.
    And saves the rest of the packet as data.
    
    
    Arguments:
    - packet(bytes): This is the full packet, header and data.
     

    Returns:
    - The values from the 8 byte header.
    - The remaining data after the header.
    
    
    Exceptions:
    None
    """
    header = packet[:header_size]
    data = packet[header_size:]
    return parse_header(header), data


def client_handshake(sock, server_address, sender_window):
    """
    Description:
    This function will perform the 3 way handshake (SYN, SYN-ACK, ACK) with the server to start the transmission of the data.
    To create this connection, the client sends a SYN packet to the server to start the connection setup.
    Then the client waits for a SYN-ACK packet from the server.
    If the SYN-ACK packet is received, the client then sends an ACK to establish the connection.
    The window size will be adjusted based on the receiver and sender's window size.
    
    Arguments:
    - sock(socket.socket): The UDP socket that is used to send and receive packets.
    - server_address(tuple): The server's IP-address and port number.
    - sender_window(int): This is the window size, that the client has specified. But can be adjusted based on the server's window size.


    Returns:
    - Returns the window size, that is going to be used in this communication.
    - If there is a timeout, the handshake will fail and nothing will be returned.
    
    Exceptions:
    - socket.timeout, if the server does not respond withing time.
    - If a packet is received, but does not have the expected SYN-ACK flags, there is sent an exception 
    """

    #Send SYN
    syn_packet = create_packet(1, 0, syn_flag, 0)
    sock.sendto(syn_packet, server_address)
    print("\nConnection Establishment Phase:\n")
    print("SYN packet is sent")

    #Wait for SYN-ACK
    sock.settimeout(timeout)
    try:
        data, _= sock.recvfrom(1024)
        (seq, ack, flags, recv_window), _= extract_packet(data)

        if flags & syn_flag and flags & ack_flag:
            print("SYN-ACK packet is received")
        else:
            raise Exception("Expected SYN-ACK, wrong")
        
    except socket.timeout:
        print("Timeout waiting for SYN-ACK")
        return None
    
    #Send ACK
    ack_packet = create_packet (2, seq + 1, ack_flag, 0)
    sock.sendto(ack_packet, server_address)
    print("ACK packet is sent")
    print("Connection established")

    #Window adjusted
    return min(sender_window, recv_window)


def client_send_file(sock, server_adress, file_path, window_size):
    """
    Description:
    This function handles the transmission of the file from the client to the server. 
    It uses sliding window protocol, with Go-Back-N functionality over UDP for realiable data transmission.
    It first calculates the amount of packets that are going to be sent.
    Then it creates, and sends all the packets.
    The client then listens for incoming ACKs, for the sent packets.
    If it receives an ACK, the new packets can be sent.
    It if doesnt receive an ACK, it will resend all the packets in the sliding window.
    
    Arguments:
    -sock(socket.socket): Socket used for communication between sender and receiver.
    -server_address(tuple): The server's IP-address and port number.
    -file_path(str): The path to the file that is going to be sent
    -window_size(int): The size of the sliding window. 


    Returns:
    -transfer_time(float): Total time that it took for the client to send the file.
    -total_sent_bytes(int): The total amount of bytes that were transferred.
    
    Exceptions:
    - socket.timeout:
      If the client does not receive an ACK in time, it will retransmit all the packets in that window.
    """

    with open(file_path, "rb") as f:
        file_data = f.read()

    total_chunks = (len(file_data) + max_data - 1) // max_data
    base = 1 
    next_seq = 1
    acked = set()
    packets = []
    start_time = time.time()

    #Create all the packets
    for i in range(total_chunks):
        chunk = file_data[i*max_data : (i+1)*max_data]
        packet = create_packet(i+1, 0, 0, 0, chunk)
        packets.append(packet)

    print("Data Transfer:\n")
    sock.settimeout(timeout)

    while base <= total_chunks:
        #Send everything that's inside the window
        while next_seq < base + window_size and next_seq <= total_chunks:
            sock.sendto(packets[next_seq - 1], server_adress)
            timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")
            print(f"{timestamp} -- packet with seq = {next_seq} is sent, sliding window = {{{', '.join(str(i) for i in range(base, next_seq+1))}}}")
            next_seq += 1

        try:
            data, _= sock.recvfrom(1024)
            (seq, ack, flags, recv_window), _=extract_packet(data)
            if flags & ack_flag:
                print(f"{timestamp} -- ACK for packet = {ack} is received")
                if ack >= base:
                    base = ack + 1

        except socket.timeout:
            print(f"{timestamp} -- RTO occured")
            #Resend the whole window
            for i in range(base, next_seq):
                sock.sendto(packets[i - 1], server_adress)
                print(f"{timestamp} -- retransmitting packet with seq = {i}")
        
    end_time = time.time()
    print("DATA finished \n")

    print("Connection Teardown: ")

    return end_time - start_time, len(file_data)


def client_teardown(sock, server_address):
    """
    Description:
    Handles the teardown of the connection. 
    The client will send a FIN packet, and wait for a FIN-ACK packet from the server to confirm that the connection can be closed.
    If a FIN-ACK packet is received before timeout, then the connection is closed.
    
    Arguments:
    - sock (socket.socket): UDP socket used for communication.
    - server_address (tuple): The IP-address and port number of the server.

    Returns:
    None
    
    Exceptions:
    - socket.timeout, if FIN-ACK is not received before timeout, prints "Timeout waiting for FIN-ACK"
    """

    #Creates a FIN-packet
    fin_packet = create_packet(0, 0, fin_flag, 0)
    sock.sendto(fin_packet, server_address)
    print("\nFIN packet is sent")

    try:
        sock.settimeout(timeout)
        data, _ = sock.recvfrom(1024)
        (seq, ack, flags, rwnd), _ = extract_packet(data)
        if flags & ack_flag and flags & fin_flag:
            print("FIN ACK packet is received")

    except socket.timeout:
        print("Timeout waiting for FIN-ACK")



def server_handshake(sock):
    """
    Description:
    In this function I have implemented the server side of the 3-way handshake with the client.
    The server waits for a SYN packet from the client.
    If it receives the SYN packet, it will send a SYN-ACK packet to the client. 
    And wait for an ACK to complete the handshake.
    When the connection is established, the IP-address and port number of the client is returned.
    
    Arguments:
    - sock (socket.socket): UDP socket for communication

    Returns:
    - addr(tuple): The clients IP-address and port number.
    
    Exceptions:
    None
    """
    while True:
        data, addr = sock.recvfrom(1024)
        (header, _) = extract_packet(data)
        seq, ack, flags, rwnd = header

        if flags & syn_flag:
            print("\nSYN packet is received")
            synack = create_packet(0, seq + 1, syn_flag | ack_flag, 15) 
            sock.sendto(synack, addr)
            print("SYN-ACK packet is sent")

        elif flags & ack_flag:
            print("ACK packet is received")
            print("Connection established")
            return addr 
        

        
def server_receive_files(sock, addr, output_file_path, discard_seq=None):
    """
    Description:
    In this function the server will receive files from the client, and write it to the output file. 
    This function is also responsible for discarding packets and send ACKs for received packets.
    The server will close the connection after receiving a FIN packet, by sending a FIN-ACK.
    
    
    Arguments:
    - sock(socket.socket): The socket used for communication
    - addr(tuple): The client's IP-address and port number
    - output_file_path(str): The path to the outputfile, the received data will be saved here.  
    - discard_seq(int): The sequence number of the packet which we wish to discard once.

    Output:
    - Writes the received file, to the the output file.
    - Prints the throughput value for the transmission.

    Returns:
    None
    
    Exceptions:
    If there are any errors, they will be printed to the console.
    """
    expected_seq = 1
    received_data = {}
    total_received = 0
    discard_once = True if discard_seq else False

    start_time = time.time()

    with open(output_file_path, "wb") as f:
        while True:
            try:
                data, _ = sock.recvfrom(2048)
                (header, payload) = extract_packet(data)
                seq, ack, flags, rwnd = header

                if flags & fin_flag:
                    print("FIN packet is received")
                    fin_ack = create_packet(0, 0, fin_flag | ack_flag, 0)
                    sock.sendto(fin_ack, addr)
                    print("FIN ACK packet is sent")
                    break

                if discard_seq and seq == discard_seq and discard_once:
                    discard_once = False
                    continue

                if seq == expected_seq:
                    timestamp = datetime.datetime.now().strftime("%H:%M:%S:%f")
                    print(f"{timestamp} -- packet {seq} is recieved")
                    f.write(payload)
                    ack_packet = create_packet(0, seq, ack_flag, 0)
                    sock.sendto(ack_packet, addr)
                    print(f"{timestamp} -- sending ack for the received {seq}")
                    expected_seq += 1
                    total_received += len(payload)
                
                else:
                    #Not correct order
                    print(f"{timestamp} -- out-of-order packet {seq} is received")

            except Exception as e:
                print("Error:", e)
                break
    end_time = time.time()
    duration = end_time - start_time
    throughput = (total_received * 8) / (duration * 1000000)
    print(f"\nThe throughput is {throughput:.2f} Mbps")
    print("Connection Closes")

        


def main():
    """
    Description:
    This is the main function of this application. It can handle both the server and the client based on input.
    It also performs the handshake, teardown, calculates the throughput, sets up sockets and sends or receives files.
    
    Arguments:
    None, uses arg-parse for input

    Input/Output: 
    Input:
    Read input from command line:
    - c (boolean): Run the code as client
    - s (boolean): Run the code as server
    - i (str): IP-address to connect to or bind.
    - p (int): Port-number to use
    - f (str): The file you want to send (client)
    - w (int): The window size that you will use, default 3 (client)
    - d (int): The sequence number of the packet that you want to discard once (server)
    
    Output:
    - Starts client/server based on input
    - Prints messages accordingly

    Returns:
    None
    
    Exceptions:
    - If the handshake fails, print "Handshake failed" and exit.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--client", action="store_true")
    parser.add_argument("-i", "--ip", type=str, default="10.0.1.2")
    parser.add_argument("-p", "--port", type=int, default=8088)
    parser.add_argument("-f", "--file", type=str, help="File to send")
    parser.add_argument("-w", "--window", type=int, default=3)
    parser.add_argument("-s", "--server", action="store_true")
    parser.add_argument("-d", "--discard", type=int, help="Sequence number to discard once")

    args = parser.parse_args()

    if args.client:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_address = (args.ip, args.port)

        #Handshake
        actual_window = client_handshake(sock, server_address, args.window)
        if actual_window is None:
            print("Handshake failed")
            return
        else:
            print("\n")
        
        duration, total_bytes = client_send_file(sock, server_address, args.file, actual_window)

        #Teardown
        client_teardown(sock, server_address)

        #Throughput calc
        throughput = (total_bytes * 8) / (duration * 1000000) #Mbps
        #print(f"\nThe throughput is {throughput:.2f} Mbps")
        print("Connection closes")

    elif args.server:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((args.ip, args.port))

        client_addr = server_handshake(sock)

        discard_seq = args.discard if args.discard else None
        server_receive_files(sock, client_addr, "received_" + str(time.time()) + ".jpg", discard_seq)

if __name__ == "__main__":
    main()
