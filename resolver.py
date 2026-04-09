import socket

def forward_query(data):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.sendto(data, ('8.8.8.8', 53))
    response, addr = sock.recvfrom(512)
    sock.close()
    return response, addr[0]   # returns response AND source IP