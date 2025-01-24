import socket, argparse, re, sys
parser = argparse.ArgumentParser(description = "-----Port Scanner-----")
parser.add_argument("-host",type=str,help="Provide Domain",required=True)

if sys.argv[3]=="-p":
    parser.add_argument("-p",type=str,help="Provide Port Number, Multiple Ports seperated by comma(,) or Range of Ports(1-100)",required=True)
else:
    parser.add_argument("-iL",type=str,help="Provide File Containing List of Ports",required=True)
a=parser.parse_args()

def run(po):
    try:
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.connect((a.host,po))
        #sock.timeout(15)
        sock.close()
        return True
    except:
        return False

def PortScan(ps):
    if run(ps):
        print("Port {} is Open".format(ps))
    else:
        print("Port {} is Closed".format(ps))

def ptconv(pp):
    if re.findall(".*,.*",pp):
        port = list(a.p.split(","))
        for i in port:
            PortScan(int(i))
    elif re.findall(".*-.*",pp):
        port = list(pp.split("-"))
        for i in range(int(port[0]),int(port[1])):
            PortScan(i)
    else:
        port = int(pp)
        PortScan(port)

def filelist():
    f = open(a.iL,"r")
    for i in f.readlines():
        PortScan(int(i.strip()))


if sys.argv[3]=="-p":
    ptconv(a.p)
elif sys.argv[3]=="-iL":
    filelist()


