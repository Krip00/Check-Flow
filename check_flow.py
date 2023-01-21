#!/usr/bin/python3
import sys
import os
import time
import maxminddb
import socket
import whois
import telegram

class List:
    """Class that define a list of object"""
    def __init__(self, name):
        self.items = []
        self.name = name

    def add_item(self, item):
        self.items.append(item)

    def remove_item(self, item):
        self.items.remove(item)

    def get_items(self):
        return self.items

    def is_listed(self, item):
        return item in self.items

    def read_list_from_file(self, file_name):
        with open(file_name, "r") as file:
            for line in file:
                self.add_item(line.strip())


class IpList(List):
    """Class that define a list of ip"""
    def __init__(self, name):
        super().__init__(name)

    def read_ip_from_file(self, file_name):
        with open(file_name, "r") as file:
            for line in file:
                ip = line.strip()
                if is_valid_ip(ip)==True:
                    self.add_item(ip)


class Whitelist(IpList):
    """class that allows us to use more than one whitelist"""
    def __init__(self, name):
        super().__init__(name)

class Blacklist(IpList):
    """Class that allows us to use more than one blacklist"""
    def __init__(self, name):
        super().__init__(name)




class Organization:
    """Class that allow us to check ip"""
    def __init__(self, path):
        self.path = path
        self.ip_to_company = {}

        with open(self.path) as f:
            for line in f:
                # Estrai l'IP e il nome dell'azienda dalla linea
                ip, company = line.strip().split(";")
                self.ip_to_company[ip] = company

    def add_ip_and_company(self, ip, company):
        # Aggiungi l'IP e il nome dell'azienda al vettore e al file di testo
        self.ip_to_company[ip] = company
        with open(self.path, "a") as f:
            f.write(f"{ip};{company}\n")

    def get_company(self, ip):
        # Restituisci il nome dell'azienda associato all'IP, se presente
        if is_valid_ip(ip)==True:
            if ip in self.ip_to_company:
                return self.ip_to_company[ip]
            elif test_org == "y":
                whois_info = whois.whois(ip)
                self.add_ip_and_company(ip, whois_info.org)
                return self.ip_to_company[ip]
            else:
                return 0
        else:
            print("This ip is not valid: ", ip)
            return -1


class Flow_original:
   """Class with only the original data"""
   def __init__(self, flow_data):
      self.flags = flow_data[0]
      self.label = flow_data[1]
      self.export_sysid = flow_data[2]
      self.size = flow_data[3]
      self.first = flow_data[4]
      self.last = flow_data[5]
      self.msec_first = flow_data[6]
      self.msec_last = flow_data[7]
      self.src_ip = flow_data[8]
      self.dst_ip = flow_data[9]
      self.src_port = flow_data[10]
      self.dst_port = flow_data[11]
      self.fdw_status = flow_data[12]
      self.tcp_flags = flow_data[13]
      self.proto = flow_data[14]
      self.tos_src = flow_data[15]
      self.packets_in = flow_data[16]
      self.bytes_in = flow_data[17]
      self.input_ = flow_data[18]
      self.output = flow_data[19]
      self.src_as = flow_data[20]
      self.dst_as = flow_data[21]
      self.icmp = flow_data[22]
      self.src_mask = flow_data[23]
      self.dst_mask = flow_data[24]
      self.dst_tos = flow_data[25]
      self.direction = flow_data[26]
      self.ip_next_hop = flow_data[27]
      self.ip_router = flow_data[28]
      self.engine_type = flow_data[29]
      self.engine_id = flow_data[30]
      self.received_at = flow_data[31]

   def __str__(self):
      return f"""
         Sorgente:              {self.src_ip}:{self.src_port}
         Destinatario:          {self.dst_ip}:{self.dst_port}
         Protocollo:            {self.proto}
         """



class Flow(Flow_original):
   """Derived class with the new data"""
   def __init__(self, flow_data):
      super().__init__(flow_data)
      self.src_app = []
      self.dst_app = []
      self.src_app.append(app_by_port(self.src_port))
      self.dst_app.append(app_by_port(self.dst_port))
      self.s_whitelist = is_ip_list(whitelist, self.src_ip)
      self.d_whitelist = is_ip_list(whitelist, self.dst_ip)
      self.s_blacklist = is_ip_list(blacklist, self.src_ip)
      self.d_blacklist = is_ip_list(blacklist, self.dst_ip)
      self.s_geo = check_ip_location(self.src_ip)
      self.d_geo = check_ip_location(self.dst_ip)
      self.d_org = org.get_company(self.dst_ip)
      self.s_org = org.get_company(self.src_ip)
      if self.s_blacklist[0]==True:
         send_alert(self.src_ip, self.s_geo)
      if self.d_blacklist[0]==True:
         send_alert(self.dst_ip, self.d_geo)



   def __str__(self):

      return f"""\033[92m
         Sorgente:              {self.src_ip}:{self.src_port}   App:    {self.src_app}
         E' in whitelist: {self.s_whitelist[0]};           E' in blacklist: {self.s_blacklist[0]};
         Organization:                          {self.s_org}
         Country:                               {self.s_geo[1]}  {self.s_geo[2]}\033[0m
         \033[91mDestinatario:          {self.dst_ip}:{self.dst_port}   App:    {self.dst_app}
         E' in whitelist: {self.d_whitelist[0]};           E' in blacklist: {self.d_blacklist[0]};
         Organization:                          {self.d_org}
         Country:                               {self.d_geo[1]}  {self.d_geo[2]}\033[0m
         \033[92mProtocollo:                            {self.proto}\033[0m
         \033[92mFlags:                                 {self.flags}\033[0m
         \033[91mLabel:                                 {self.label}\033[0m
         \033[92mExport_sysid:                          {self.export_sysid}\033[0m
         \033[91mSize:                                  {self.size}\033[0m
         \033[92mFirst:                                 {self.first}\033[0m
         \033[91mLast:                                  {self.last}\033[0m
         \033[92mMili seconds first seen:               {self.msec_first}\033[0m
         \033[91mMili seconds last seen:                {self.msec_last}\033[0m
         \033[92mFdw status:                            {self.fdw_status}\033[0m
         \033[91mTcp_flag:                              {self.tcp_flags}\033[0m
         \033[92mTos src:                               {self.tos_src}\033[0m
         \033[91mPackets in:                            {self.packets_in}\033[0m
         \033[92mBytes in:                              {self.bytes_in}\033[0m
         \033[91mInput:                                 {self.input_}\033[0m
         \033[92mOutput:                                {self.output}\033[0m
         \033[91mSrc as number:                         {self.src_as}\033[0m
         \033[92mDst as number:                         {self.dst_as}\033[0m
         \033[91mIcmp:                                  {self.icmp}\033[0m
         \033[92mSrc mask:                              {self.src_mask}\033[0m
         \033[91mDst mask:                              {self.dst_mask}\033[0m
         \033[92mDst tos:                               {self.dst_tos}\033[0m
         \033[91mDirection:                             {self.direction}\033[0m
         \033[92mIp next hop:                           {self.ip_next_hop}\033[0m
         \033[91mIp router:                             {self.ip_router}\033[0m
         \033[92mEngine type:                           {self.engine_type}\033[0m
         \033[91mEngine id:                             {self.engine_id}\033[0m
         \033[92mReceived at:                           {self.received_at}\033[0m
         """



#generate flowdata_temp from stdin
def flow_from_stdin(line):

   flags = " "
   label = " "
   export_sysid = " "
   size = " "
   first = " "
   last = " "
   msec_first = " "
   msec_last = " "
   s_ip = " "
   d_ip = " "
   s_port = " "
   d_port = " "
   fdw_status = " "
   tcp_flags = " "
   proto = " "
   tos_src = " "
   packets_in = " "
   bytes_in = " "
   input_ = " "
   output = " "
   src_as = " "
   dst_as = " "
   icmp = " "
   src_mask = " "
   dst_mask = " "
   dst_tos = " "
   direction = " "
   ip_next_hop = " "
   ip_router = " "
   engine_type = " "
   engine_id = " "
   received_at = " "


   if "Flags" in line:
      flags = (line.split("=")[1].strip())
   elif "label" in line:
      label = (line.split("=")[1].strip())
   elif "export sysid" in line:
      export_sysid = (line.split("=")[1].strip())
   elif "size" in line:
      size = (line.split("=")[1].strip())
   elif "first" in line:
      first = (line.split("=")[1].strip())
   elif "last" in line:
      last = (line.split("=")[1].strip())
   elif "msec_first" in line:
      msec_first = (line.split("=")[1].strip())
   elif "msec_last" in line:
      msec_last = (line.split("=")[1].strip())
   elif "src addr" in line:
      s_ip = (line.split("=")[1].strip())
   elif "dst addr" in line:
      d_ip = (line.split("=")[1].strip())
   elif "ICMP" in line:
      icmp = (line.split("=")[1].strip())
   elif "src port" in line:
      s_port = (line.split("=")[1].strip())
   elif "dst port" in line:
      d_port = (line.split("=")[1].strip())
   elif "fwd status" in line:
      fdw_status = (line.split("=")[1].strip())
   elif "tcp flags" in line:
      tcp_flags = (line.split("=")[1].strip())
   elif "proto" in line:
      proto = (line.split("=")[1].strip().split(" ")[1])
   elif "(src)tos" in line:
      tos_src = (line.split("=")[1].strip())
   elif "(in)packets" in line:
      packets_in = (line.split("=")[1].strip())
   elif "(in)bytes" in line:
      bytes_in = (line.split("=")[1].strip())
   elif "input" in line:
      input_ = (line.split("=")[1].strip())
   elif "output" in line:
      output = (line.split("=")[1].strip())
   elif "src as" in line:
      src_as = (line.split("=")[1].strip())
   elif "dst as" in line:
      dst_as = (line.split("=")[1].strip())
   elif "src mask" in line:
      src_mask = (line.split("=")[1].strip())
   elif "dst mask" in line:
      dst_mask = (line.split("=")[1].strip())
   elif "dst tos" in line:
      dst_tos = (line.split("=")[1].strip())
   elif "direction" in line:
      direction = (line.split("=")[1].strip())
   elif "ip next hop" in line:
      ip_next_hop = (line.split("=")[1].strip())
   elif "ip router" in line:
      ip_router = (line.split("=")[1].strip())
   elif "engine type" in line:
      engine_type = (line.split("=")[1].strip())
   elif "engine ID" in line:
      engine_id = (line.split("=")[1].strip())
   elif "received at" in line:
      received_at = (line.split("=")[1].strip())

   return (flags, label, export_sysid, size, first, last, msec_first, msec_last, s_ip, d_ip, s_port, d_port, fdw_status, tcp_flags, proto, tos_src, packets_in, bytes_in, input_, output, src_as, dst_as, icmp, src_mask, dst_mask, dst_tos, direction, ip_next_hop, ip_router, engine_type, engine_id, received_at)


#check if ip is in bwlist(black/white) and return the name of the list
def is_ip_list(bwlist, ip):
    for ip_bw in bwlist:
        if ip_bw.is_listed(ip) == True:
            return (True,ip_bw.name)
    return (False,"")


#check if is real ip
def is_valid_ip(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for item in parts:
        if not item.isdigit():
            return False
        if int(item) < 0 or int(item) > 255:
            return False
    return True


#check the application by port number
def app_by_port(port):
   try:
      return (socket.getservbyport(int(port)))
   except:
      return ("Not Found")


#check the location
def check_ip_location(ip):
    with maxminddb.open_database('/usr/share/GeoIP/GeoLite2-Country.mmdb') as reader:
       ipinfo=reader.get(ip)
       try:
           country = ipinfo["country"]["names"]["en"]
       except:
           country = ""
       try:
           iso_code = ipinfo["country"]["iso_code"]
       except:
           iso_code = ""
       return ( ip, country, iso_code)

#function that send alert on telegram
def send_alert(ip, geo):
    bot = telegram.Bot(token="5649189390:AAH_eLPA8sOJ39tLwFOMGPNCLthPnfzsWwA")
    bot.send_message(chat_id="@alert_co", text=f"Alert: L'ip {ip}, che si trova presso: {geo[1]}, è stato trovato in blacklist")


os.system('clear')
index=-1
flow = [None]*10000
flowdata = [None]*32


#Create a Blacklist and Whitelist instance
blacklist = [Blacklist]*1
whitelist = [Whitelist]*1
blacklist[0] = Blacklist("concorrenti")
whitelist[0] = Whitelist("social")
#Read the IP addresses from a file
blacklist[0].read_ip_from_file("/usr/share/list_db/blacklist.txt")
whitelist[0].read_ip_from_file("/usr/share/list_db/whitelist.txt")
#Create istance of db to check the organization
db_company = ("/usr/share/list_db/company.txt")
org = Organization(db_company)
#"y" to allow to check online for IP that are not present in the db
#test_org = "y"
test_org = "n"

for line in sys.stdin:
   #Flow Record is the keybord used to introduce a new flow
   if "Flow Record:" in line:
      #if is not the first
      if index != -1:
          flow[index] = Flow (flowdata)
          print('\033[94m',index, "- Flow\033[0m",flow[index])
      #standard
      if index < 9999:
         index+=1
      #out of max lenght
      else:
         index=0
   #Flow already started
   else:
      flowdata_temp = flow_from_stdin(line)
      for i in range(len(flowdata_temp)):
         if flowdata_temp[i] != " ":
            flowdata[i] = flowdata_temp[i]



"""
Below all the metadata received from nfdump with relative storage index(i) in array(flowdata)
i) flowdata --->  flowdata[i]
1) flags
2) label
3) export_sysid
4) size
5) first
6) last
7) msec_first
8) msec_last
9) s_ip
10) d_ip
11) s_port
12) d_port
13) fdw_status
14) tcp_flags
15) proto
16) tos_src
17) packets_in
18) bytes_in
19) input
20) output
21) src_as
22) dst_as
23) icmp
24) src_mask
25) dst_mask
26) dst_tos
27) direction
28) ip_next_hop
29) ip_router
30) engine_type
31) engine_id
32) received_at
"""