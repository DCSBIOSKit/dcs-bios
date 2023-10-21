from zeroconf import ServiceInfo, Zeroconf
import socket
import json
import base64
import select

def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip_address = s.getsockname()[0]
    s.close()
    return ip_address

slave_dict = {}  # Dictionary to store slave addresses and IDs

# Setup DCS-BIOS UDP Socket
IP_ADDRESS = "0.0.0.0"
UDP_PORT = 5010
BUFFER_SIZE = 4096
GROUP = "239.255.50.10"

dcs_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
dcs_socket.bind((IP_ADDRESS, UDP_PORT))
dcs_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(GROUP) + socket.inet_aton(IP_ADDRESS))

if __name__ == '__main__':
    zeroconf = Zeroconf()
    ip_address = get_ip_address()

    info = ServiceInfo(
        "_dcs-bios._udp.local.",
        "DCS-BIOS Service._dcs-bios._udp.local.",
        addresses=[socket.inet_aton(ip_address)],
        port=7779,
    )

    zeroconf.register_service(info)
    slave_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    slave_socket.bind(("0.0.0.0", 7779))

    print(f"Listening for connections on {ip_address}:7779")

    try:
        while True:
            # Create a list of sockets to monitor
            readable_sockets, _, _ = select.select([dcs_socket, slave_socket], [], [], 0.1)
            
            for s in readable_sockets:
                if s is dcs_socket:
                    # Receive DCS-BIOS Data
                    dcs_data, _ = dcs_socket.recvfrom(BUFFER_SIZE)
                    
                    for slave_addr in slave_dict.keys():
                        encoded_data = base64.b64encode(dcs_data).decode()
                        message = json.dumps({'message': encoded_data})
                        slave_socket.sendto(message.encode(), slave_addr)
                        print(f"Sent {message} to {slave_dict[slave_addr]} at address {slave_addr}")

                elif s is slave_socket:
                    data, slave_addr = slave_socket.recvfrom(BUFFER_SIZE)
                    parsed_data = json.loads(data.decode())  # Added .decode() to convert bytes to string before JSON parsing
                    message_base64 = parsed_data.get('message', None)  # Changed from 'id' to 'message'

                    if message_base64:
                        # Decode the base64 data and send it to DCS-BIOS
                        decoded_data = base64.b64decode(message_base64)
                        dcs_socket.sendto(decoded_data, ('localhost', 7778))
                        print(f"Forwarded message to DCS-BIOS: {decoded_data}")

                    slave_id = parsed_data.get('id', 'Unknown')
                    print(f"Received connection from {slave_id} at address {slave_addr}")

                    if slave_addr not in slave_dict:
                        slave_dict[slave_addr] = slave_id
                        message = json.dumps({'message': 'Hello, World'})
                        slave_socket.sendto(message.encode(), slave_addr)
    except KeyboardInterrupt:
        print("Kthxbai")
    finally:
        zeroconf.unregister_service(info)
        zeroconf.close()
