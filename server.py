from datetime import datetime
import socket
import sys
import select

#constants
MAGIC_NO = 0x36FB.to_bytes(2, 'big')
PACKET_REQUEST_TYPE = 0x0001.to_bytes(2, 'big')
PACKET_RESPONSE_TYPE = 0x0002.to_bytes(2, 'big')
REQUEST_TYPES = [0x0001.to_bytes(2, 'big'), 0x0002.to_bytes(2, 'big')]
LANGUAGE_CODES = {1: "English", 2: "Māori", 3: "German"}
MONTH_NAMES = {
    "English": ["January", "February", "March", "April", "May", "June", \
                "July", "August", "September", "October", "November", "December"],
    "Māori": ["Kohi-tātea", "Hui-tanguru", "Poutū-te-rangi", "Paenga-whāwhā", \
                     "Haratua", "Pipiri", "Hōngingoi", "Here-turi-kōkā", "Mahuru", \
                        "Whiringa-ā-nuku", "Whiringa-ā-rangi", "Hakihea"],
    "German": ["Januar", "Februar", "März", "April", "Mai", "Juni", "Juli", \
               "August", "September", "Oktober", "November", "Dezember"]
}

def validate_ports(ports):
    """
    Validate the port numbers entered as parameters
    on the command line and exit if there's any error.
    """
    if len(ports) != 3:
        sys.exit("ERROR: Incorrect number of command line arguments")
    if len(set(ports)) != 3:
        sys.exit("ERROR: Duplicate ports given")
    for i in range(3):
        if ports[i].startswith('-') or not ports[i].isdigit():
            sys.exit(f"ERROR: Given port '{ports[i]}' is not a positive integer")
        ports[i] = int(ports[i])
        if ports[i] < 1024 or ports[i] > 64000:
            sys.exit(f"ERROR: Given port '{ports[i]}' is not in the range [1024, 64000]")

def bind_sockets(ports):
    """
    Open three UDP/datagram sockets and bind each of these
    to the three given port numbers. Handles any occurring 
    errors.
    """
    sockets = []
    for index, port in enumerate(ports):
        language = LANGUAGE_CODES[index + 1]
        print(f"Binding {language} to port {port}")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except socket.error:
            if sockets:
                for s in sockets:
                    s.close()
            sys.exit("ERROR: Socket creation failed")
        
        try:
            sock.bind(("localhost", port))
            sockets.append(sock)
        except socket.error:
            sock.close()
            if sockets:
                for s in sockets:
                    s.close()
            sys.exit("ERROR: Socket binding failed")
        
    return sockets

def validate_packet(packet):
    """Performs the necessary check if the DT-Response packet 
    is valid.
    """
    if len(packet) != 6:
        print("ERROR: Packet length incorrect for a DT_Request, dropping packet")
        return False
    if packet[0:2] != MAGIC_NO:
        print("ERROR: Packet magic number is incorrect, dropping packet")
        return False
    if packet[2:4] != PACKET_REQUEST_TYPE:
        print("ERROR: Packet is not a DT_Request, dropping packet")
        return False
    if packet[4:6] not in REQUEST_TYPES:
        print("ERROR: Packet has invalid type, dropping packet")
        return False
    return True

def create_response_packet(language, language_code, request_type, packet):
    """Create the response packet following the format
    specified.
    """
    now = datetime.now()

    if request_type == 0x0001:
        if language == "English":
            text = f"Today's date is {MONTH_NAMES[language][now.month-1]} {now.day}, {now.year}"
        elif language == "Māori":
            text = f"Ko te rā o tēnei rā ko {MONTH_NAMES[language][now.month-1]} {now.day}, {now.year}"
        else:
            text = f"Heute ist der {now.day}. {MONTH_NAMES[language][now.month-1]} {now.year}"
    else:
        if language == "English":
            text = f"The current time is {now.hour:02}:{now.minute:02}"
        elif language == "Māori":
            text = f"Ko te wā o tēnei wā {now.hour:02}:{now.minute:02}"
        else:
            text = f"Die Uhrzeit ist {now.hour:02}:{now.minute:02}"

    text_bytes = text.encode("utf-8")
    text_len = len(text_bytes)
    if text_len > 255:
        print("ERROR: Text too long, dropping packet")
        return
    
    response_packet = bytearray(13 + text_len)
    response_packet[0:2] = MAGIC_NO
    response_packet[2:4] = PACKET_RESPONSE_TYPE
    response_packet[4:6] = language_code.to_bytes(2, 'big')
    response_packet[6:8] = now.year.to_bytes(2, 'big')
    response_packet[8] = now.month
    response_packet[9] = now.day
    response_packet[10] = now.hour
    response_packet[11] = now.minute
    response_packet[12] = text_len
    response_packet[13:] = text_bytes

    return response_packet

def handle_request(sock, language_code):
    """
    Handles the request of the client from the server.
    """
    try:
        sock.settimeout(1)
        packet, addr = sock.recvfrom(1024)
    except socket.timeout:
        print("ERROR: Receiving timed out, dropping packet")
        return
    except socket.error:
        print("ERROR: Receiving failed, dropping packet")
        return
    
    if not validate_packet(packet):
        return
    
    request_type = int.from_bytes(packet[4:6], 'big')
    language = LANGUAGE_CODES[language_code]
    print(f"{language} received {'time' if request_type == 0x0002 else 'date'} request from {addr[0]}")

    response_packet = create_response_packet(language, language_code, request_type, packet)

    if response_packet:
        try:
            sock.sendto(response_packet, addr)
            print("Response sent")
            return
        except socket.error:
            print("ERROR: Sending failed, dropping packet")
            return

def run_server(ports):
    """
    Initializes the server for accepting requests from the client.

    """
    validate_ports(ports)
    sockets = bind_sockets(ports)

    try:
        while True:
            print("Waiting for requests...")
            readable, _, _ = select.select(sockets, [], [])
            for sock in readable:
                language_code = sockets.index(sock) + 1
                handle_request(sock, language_code)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"ERROR: {e}")
    finally:
        for sock in sockets:
            sock.close()
        
def main():
    """
    Main function that starts the whole server program.
    """
    run_server(sys.argv[1:])

if __name__ == "__main__":
    main()