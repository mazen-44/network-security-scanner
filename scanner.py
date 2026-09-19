import socket
import argparse
def resolve_target(target) :
    try :
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        print("INVALID HOST NAME!")
        return None
def main():
    parser = argparse.ArgumentParser(description="--HOST NAME SCANNER--")
    parser.add_argument("--target",help="--target HOST NAME (example.com)--", type=str , required= True)
    args = parser.parse_args()
    ip = resolve_target(args.target)
    if ip:
        print(f"The IP of the host is : {ip}")
if __name__ == "__main__":
    main()
