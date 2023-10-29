
 
import argparse
import socket
import requests
from scapy.layers.dns import *
from scapy.all import *
from http.client import HTTPResponse
import base64
from urllib.parse import urlsplit


def parse_arguments():
    # Command-line argument parsing
    parser = argparse.ArgumentParser(description="DNS Forwarder with DoH and Domain Blocking")
    parser.add_argument("-d", dest="dest_ip", help="Destination DNS server IP")
    parser.add_argument("-f", dest="deny_list_file", help="File containing domains to block")
    parser.add_argument("-l", dest="log_file", help="Append-only log file")
    parser.add_argument("--doh", action="store_true", help="Use default upstream DoH server")
    parser.add_argument("--doh_server", help="Use this upstream DoH server")
    return parser.parse_args()

def load_deny_list(deny_list_file):
    """
    Load the deny list from the given file.
    """
    deny_list = set()
    if deny_list_file == None:
        print("No deny list provided")
        return deny_list
    try:
        with open(deny_list_file, 'r') as file:
            for line in file:
                line = line.strip()
                deny_list.add(line)
                deny_list.add(line+".")
    except Exception as e:
       print(e)
    return deny_list

def log_query(log_file, domain, query_type, allowed):
    """
    Log the DNS query in the specified format.
    """
 
    with open(log_file, 'a') as file:
        log_entry = f"{domain} {query_type} {'ALLOW' if allowed else 'DENY'}\n"
        file.write(log_entry)

def forward_dns_query(client_query, dest_ip, doh_server, doh_enabled):
    """
    Forward the DNS query to the appropriate resolver (DNS or DoH).
    """
    if doh_enabled:
        doh_url = f"https://{doh_server}/dns-query?dns={base64.urlsafe_b64encode(bytes(client_query)).decode('utf-8')}"
        response = requests.get(doh_url)
        if response.status_code == 200:

            return response.content
    else:

        dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dns_socket.sendto(client_query, (dest_ip, 53))
        response, _ = dns_socket.recvfrom(4096)
        dns_socket.close()
        return response

def get_qtype_from_DSQR(qd):
    qtype_mapping = {
        1: "A",
        2: "NS",
        3: "MD",
        4: "MF",
        5: "CNAME",
        6: "SOA",
         7: "MB",
        8: "MG",
        9: "MR",
        10: "NULL",
        11: "WKS",
        12: "PTR",
        13: "HINFO",
        14: "MINFO",
        15: "MX",
        16: "TXT",
        28: "AAAA",
    }
    query_type = qd.qtype
    try:
        query_type = int(query_type) 
    except:
        pass
    if isinstance(query_type,int):
        query_type = qtype_mapping[query_type]

    return query_type
        

def main():

    args = parse_arguments()
    print(args)
    deny_list = load_deny_list(args.deny_list_file)
    if deny_list == None:
        print("There is no deny list")
    # Create a UDP server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('0.0.0.0', 53))
    #server_socket.bind(('0.0.0.0', 5354))



    while True:
        client_query, client_address = server_socket.recvfrom(4096)
        client_query_type = "UNKNOWN"


        try:
            # Parse the DNS query using Scapy
            dns_query = DNS(client_query)
            print(dns_query.show())
            if len(dns_query.qd[0]) > 0:
                client_query_type =   get_qtype_from_DSQR(dns_query.qd[0])

            # Check if the domain is in the deny list
            domain = dns_query.qd[0].qname.decode('utf-8')
            if args.log_file == None:
                args.log_file = 'queries.log'
                   
            
            if domain in deny_list:
                # Respond with an NXDOMAIN message
                print(domain + "is denied access")
                response = DNS(id=dns_query.id, qr=1, rd=1, ra=0, qd=dns_query.qd, an=DNSQR(qname=domain))
                log_query(args.log_file, domain, client_query_type, False)
                print("Response:")
                print(response.show())
            else:
                # Forward the DNS query
                if args.dest_ip == None and (args.doh_server == None or args.doh == None):
                    args.doh = True
                    args.doh_server = '1.1.1.1'
        
                


                response_data = forward_dns_query(client_query, args.dest_ip, args.doh_server, args.doh)
                print(response_data)
                response = DNS(response_data)

                if response.qr == 0:
                    response.qr = 1
                print(response.qr)
               

               
                log_query(args.log_file, domain, client_query_type, True)

            print("Sending the response to socket")
            print(client_address)
            # Send the response to the client
            server_socket.sendto(bytes(response), client_address)

        except Exception as e:
            print(f"Error processing query: {e}")
            continue

if __name__ == "__main__":
    main()

