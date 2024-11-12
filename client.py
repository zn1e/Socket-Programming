import socket
import sys

#constants
MAGIC_NO = 0x36FB
PACKET_REQUEST_TYPE = 0x0001
PACKET_RESPONSE_TYPE = 0x0002
DATE_REQUEST = 0x0001
TIME_REQUEST = 0x0002
LANGUAGES = {0x0001: "English", 0x0002: "Māori", 0x0003: "German"}

def validate_parameters(args):
    """
    Verify the command line arguments if it met the conditions.
    Otherwise, error is printed and system is exit immediately.
    """
    if len(args) != 4:
        sys.exit("ERROR: Incorrect number of command line arguments")

    request_type = args[1]
    if request_type not in ["date", "time"]:
        sys.exit(f"ERROR: Request type '{request_type}' is not valid")

    host = args[2]
    try:
       host_ip = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_DGRAM)[0][4][0]
    except socket.gaierror:
        sys.exit("ERROR: Hostname resolution failed")

    port = args[3]
    if port.startswith('-') or not port.isdigit():
        sys.exit(f"ERROR: Given port '{port}' is not a positive integer")
    port = int(port)
    if port < 1024 or port > 64000:
        sys.exit(f"ERROR: Given port '{port}' is not in the range [1024, 64000]")

    return request_type, host_ip, port           

def create_request_packet(request_type):
    """
    Create a DT-Request packet given the specified conditions.
    """
    packet = bytearray(6)
    packet[0:2] = MAGIC_NO.to_bytes(2, 'big')
    packet[2:4] = PACKET_REQUEST_TYPE.to_bytes(2, 'big')
    packet[4:6] = request_type.to_bytes(2, 'big')
    
    return packet

def send_and_receive_packet(sock, packet, server_address):
    """
    Send a packet to the server given in server address. If a packet
    arrives within one second, the packet is retrieve. Any error
    occurs are handled.
    """
    try:
        sock.sendto(packet, server_address)
        print(f"{'Time' if packet[4:6] == TIME_REQUEST.to_bytes(2, 'big') else 'Date'} request sent to {str(server_address[0])}:{server_address[1]}")
    except Exception as e:
        sock.close()
        sys.exit("ERROR: Sending failed")
    
    try:
        sock.settimeout(1)
        response, _ = sock.recvfrom(1024)
        return response
    except socket.timeout:
        sock.close()
        sys.exit("ERROR: Receiving timed out")
    except Exception as e:
        sock.close()
        sys.exit("ERROR: Receiving failed")

def validate_response1(sock, response):
    """
    First half of checking whether it is a proper DT-Response. If not, error message 
    is printed and the system is exited. Otherwise, the response is processed.
    """
    if len(response) < 13:
        sys.exit("ERROR: Packet is too small to be a DT_Response")

    if int.from_bytes(response[0:2], 'big') != MAGIC_NO:
        sys.exit("ERROR: Packet magic number is incorrect") 
    
    if int.from_bytes(response[2:4], 'big') != PACKET_RESPONSE_TYPE:
        sys.exit("ERROR: Packet is not a DT_Response")

    if int.from_bytes(response[4:6], 'big') not in [0x0001, 0x0002, 0x0003]:
        sys.exit("ERROR: Packet has invalid language")    

    if int.from_bytes(response[6:8], 'big') >= 2100:
        sys.exit("ERROR: Packet has invalid year")

    if not (1 <= response[8] <= 12):
        sys.exit("ERROR: Packet has invalid month")

def validate_response2(sock, response):
    """
    Second half of validating the response.
    """
    if not (1 <= response[9] <= 31):
        sys.exit("ERROR: Packet has invalid day")

    if not (0 <= response[10] <= 23):
        sys.exit("ERROR: Packet has invalid hour")

    if not (0 <= response[11] <= 59):
        sys.exit("ERROR: Packet has invalid minute")

    if len(response) != (13 + response[12]):
        sys.exit("ERROR: Packet text length is incorrect")       

    try:
        response[13:].decode("utf-8")
    except UnicodeDecodeError:
        sys.exit("ERROR: Packet has invalid text")
    
def parse_response(response):
    """
    Gets the necessary data for printing the status message.
    """
    language_code = int.from_bytes(response[4:6], 'big')
    year = int.from_bytes(response[6:8], 'big')
    month = response[8]
    day = response[9]
    hour = response[10]
    minute = response[11]
    length = response[12]
    text = response[13:].decode("utf-8")

    return language_code, year, month, day, hour, minute, text

def print_response(language_code, year, month, day, hour, minute, text):
    """
    Prints the status message given the format specified.
    """
    print(f"{LANGUAGES[language_code]} response received:")
    print(f"Text: {text}")
    print(f"Date: {day}/{month}/{year}")
    print(f"Time: {hour:02}:{minute:02}")

def main():
    """
    Main function that starts the client.
    """
    request_type, host, port = validate_parameters(sys.argv)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except socket.error:
        sys.exit("ERROR: Socket creation failed")

    packet = create_request_packet(DATE_REQUEST if request_type == "date" else TIME_REQUEST)
    server_address = (host, port)
    
    try:
        response = send_and_receive_packet(sock, packet, server_address)
        validate_response1(sock, response)
        validate_response2(sock, response)
        language_code, year, month, day, hour, minute, text = parse_response(response)
        print_response(language_code, year, month, day, hour, minute, text)
    finally:
        if sock is not None:
            sock.close()    

if __name__ == "__main__":
    main()