import socket
import argparse
import requests
import json
import datetime
def resolve_target(target) :
    try :
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        print("INVALID HOST NAME!")
        return None
def http_enum(ip , port):
    if port == 80:
        scheme = "http"
    elif port == 443:
        scheme = "https"
    else:
        return None
    url = f"{scheme}://{ip}:{port}"
    try:
        response = requests.get(url , timeout=2)
        return response
    except requests.RequestException:
        return None
def scan_port(ip , port):
    result = []
    for i in port:
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
            connection_result = sock.connect_ex((ip , i))
            if connection_result == 0 :
                port_info = {"port": i, "status": "open", "banner": None, "http_status": None, "server": None}
                if i == 80 or i == 443:
                    response = http_enum(ip, i)
                    if response:
                        print(f"Status : {response.status_code}")
                        print(f"Server : {response.headers.get('Server' , 'Not disclosed')}")
                        print(f"Content Type : {response.headers.get('Content-Type' , 'Not disclosed')}")
                        port_info["http_status"] = response.status_code
                        port_info["server"] = response.headers.get('Server' , 'Not disclosed')
                    else:
                        print("HTTP request failed!")
                else:
                    try : 
                        data = sock.recv(1024)
                        if data == b'':
                            print("No banner received!")
                        else:
                            print(f"Banner : {data.decode()}")
                            port_info["banner"] = data.decode()
                    except UnicodeDecodeError:
                        print("Banner could not be decoded as text!")
                    except socket.timeout:
                        print("Banner connection timeout!")
                result.append(port_info)
            else:
                result.append(
                    {
                        "port" : i,
                        "status" : "closed"
                    }
                )
        except socket.timeout:
            print("Connection timeout!")
        finally:
            sock.close()
    return result
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
    t = datetime.datetime.now()
    time = t.strftime("%Y-%m-%d | %H:%M:%S")
    if port_list:
        result = {
            "target" : args.target,
            "ip" : ip,
            "ports" : [],
            "timestamp" : time
        }
        ports = scan_port(ip,port_list)
        result["ports"].extend(ports)
        filename = f"reports/scan_{args.target}_{t.strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename,"w") as file:
            json.dump(result, file , indent=4)
if __name__ == "__main__":
    main()