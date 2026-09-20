import socket
import argparse
def resolve_target(target) :
    try :
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        print("INVALID HOST NAME!")
        return None
def scan_port(ip , port):
    for i in port:
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
            result = sock.connect_ex((ip , i))
            if result == 0 :
                print(f"The port {i} is open!")
        except socket.timeout:
            print("Connection timeout!")
        finally:
            sock.close()
def parse_ports(ports_str):
    if "-" in ports_str:
        ports = ports_str.split("-")
        if len(ports) != 2:
            print("Invalid port format! Use start-end, example: 1-100")
            return
        try: 
            start = int(ports[0])
            end = int(ports[1])
        except ValueError :
            print("Invalid ports - must be numbers")
            return
        if start < 1 or start > 65535 or end < 1 or end > 65535:
            print("Ports must be between 1 and 65535!")
            return
        if start > end:
            print("The start port must be less than the end port!")
            return
        ports_for_scan = range(start , end+1)
    elif "," in ports_str:
        try :
            ports_for_scan = [int(port) for port in ports_str.split(",")]
        except ValueError :
            print("Invalid ports - must be numbers")
            return
        for port in ports_for_scan:
            if port < 1 or port > 65535:
                print("Ports must be between 1 and 65535!")
                return
    else:
        try :
            ports_for_scan = [int(ports_str)]
        except ValueError :
            print("Invalid ports - must be numbers")
            return
        if ports_for_scan[0] < 1 or ports_for_scan[0] > 65535:
            print("Ports must be between 1 and 65535!")
            return
    return ports_for_scan
def main():
    parser = argparse.ArgumentParser(description="--HOST NAME SCANNER--")
    parser.add_argument("--target",help="--target HOST NAME (example.com)--", type=str , required= True)
    parser.add_argument("--ports",help="--PORTS to test(--ports 1-100)--", type=str , required=True)
    args = parser.parse_args()
    ip = resolve_target(args.target)
    if not ip:
        return
    print(f"The IP of the host is : {ip}")
    port_list = parse_ports(args.ports)
    if port_list:
        scan_port(ip , port_list)
if __name__ == "__main__":
    main()