import scapy.all as scapy #Network scanning Library
import impacket
import requests #Python Library to send HTTP requests
import httpx
import bs4 #Beautiful soup 4 is a HTML partser
import socket #Python Library to create sockets


def packet_callb(packet): #Function packet call back
    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP): #Checks for layer 3 (IP) and layer 4 (TCP)
        src_ip = packet[scapy.IP].src #Sets source IP
        dst_ip = packet[scapy.IP].dst #Sets Destination IP


        if packet.haslayer(scapy.Raw): #Checks for Data in the packet
            payload = packet[scapy.Raw].load.decode(errors="ignore") #Decodes data and assigns it to payload while ignoring errors
            if "HTTP" in payload: #Checks for HTTP in the data
                print(f"[HTTP Packet] {src_ip} -> {dst_ip}") #Prints a simplified packet EX. [HTTP Packet] 1.1.1.1 -> 2.2.2.2
                print(payload[:200]) #Prits the first two hundred characters of the payload



def scan_ports(target): #Function to scan protocol ports
    print(f"scanning {target} for open ports...") #Yap
    for port in range(1, 1025): #Range of well known ports
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #socket.socket creates a new object (A socket is a collection of settings and/or information to communicate with network protocols), AF_INET specifies IPv6, SOCK_STREAM specifies the function will use TCP
        s.settimeout(0.3) #Socket waits 0.3 seconds for a connection before timing out
        if s.connect_ex((target, port)) == 0: #Connect_ex attempts to conenct to a target, target is the address of the target, Port is the port which is used to make a connection, Checks for a return value of 0 which means the connection was succesful
            print(f"[OPEN] {target}:{port}") #If the connection is succesful prints this EX. [OPEN] 127.0.0.1:80
        s.close() #Ends the socket connection



def extract_links(url): #Function to extract links
    response = requests.get(url) #Creates string response to store sent GET requests
    soup = bs4.BeautifulSoup(response.text, "html.parser") #String soup stores the parsed responses
    links = [a["href"] for a in soup.find_all("a", href = True)] 
    return links #Returns the list of links




#Example of Network scanning function
scapy.sniff(filter="tcp", prn = packet_callb, store = 0, count = 10) #Filters scapy to only capturing TCP packets, prn is a parameter to callback function, Store = 0 makes sure no packets are stored to memory, Limits scapy to sniffing ten packets

#Example of port scan function
scan_ports("google.com")

#Example of Link Extraction function
print(extract_links("http://example.com"))
