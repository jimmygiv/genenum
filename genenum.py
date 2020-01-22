#!/usr/bin/env python3
#This program uses the python-nmap module. Not to be confused with the nmap module, which doesn't work.
#I know this is incredibly confusing, but such is life.
#import default modules
#------------------------------------------------------------------------------------
try:
  from argparse import ArgumentParser
  from subprocess import PIPE,Popen
except:
  print("[*] Unable to import default modules. Exiting...")
  exit()
 
#define installer function, and import non-default modules
#------------------------------------------------------------------------------------
def installer(program):
  try:
    from pip import main as pipmain
  except:
    print("[*]Pip not installed")
    exit()
  pipmain(['install', program])
  exit()
try:
  from termcolor import colored as color
except:
  installer("termcolor")
try:
  from nmap.nmap import PortScanner as PS
except:
  installer("python-nmap")
try:
  from ipaddress import IPv4Address as ipaddress
  from ipaddress import IPv4Network as ipnetwork
except:
  installer("ipaddress")
  
#Set constants // splash screen
splash =color("   ______           ______                     \n", "green", attrs=['blink'])
splash+=color("  / ____/__  ____  / ____/___  __  ______ ___  \n", "green", attrs=['blink'])
splash+=color(" / / __/ _ \/ __ \/ __/ / __ \/ / / / __ `__ \ \n", "green", attrs=['blink'])
splash+=color("/ /_/ /  __/ / / / /___/ / / / /_/ / / / / / / \n", "green", attrs=['blink'])
splash+=color("\____/\___/_/ /_/_____/_/ /_/\__,_/_/ /_/ /_/  \n", "green", attrs=['blink'])
print(splash)

argparse = ArgumentParser()
argparse.add_argument('-i', '--ip', type=str, help='ip address to scan')
argparse.add_argument('-a', '--arp', help='option to arp scan. IE: -a 172.16.16.0/24')
args = argparse.parse_args()


#------------------------------------------------------------------------------------
def pprint(data):
  print('%-6s %-6s %-10s' % ("PORT", "STATE", "PROTOCOL"))
  for x in data:
    print('%-6s %-6s %-10s' % (x, data[x]['state'], data[x]['name']))

def get_ip(ip):
  if not ip:
    while not ip:
      try:
        ip = input("Enter ip address/subnet: ")
        if '/' not in ip: tmp = ipaddress(ip)
        else: tmp = ipnetwork(ip)
      except:
        ip = ''
    return ip
  else:
    return ip

def arp_scan(subnet):
  nm = PS(); retadd=[]
  nm.scan(hosts=subnet, arguments="-sn")
  results = nm._scan_result['scan']
  for i in results:
    if results[i]['status']['state'] == "up":
      retadd.append(i)
  return tuple(retadd)

#Define host address
ip = get_ip(args.ip)
if '/' in ip:
  print(color("[*] Running arp scan", "blue"))
  hosts = arp_scan(ip); i=0
  if len(hosts) > 1:
    for x in hosts:
      print("%s) %s" % (i+1,x))
      i+=1
    i = int(input("Which host in range? (number): "))
    ip = hosts[i-1]

def quick_scan(ip):
  nm = PS(); ports = {}
  nm.scan(hosts=ip, arguments="--open")
  results = nm._scan_result['scan']
  if 'tcp' in results[ip].keys():
    ports['tcp'] = results[ip]['tcp']
    pprint(ports['tcp'])
  if 'udp' in results[ip].keys():
    ports['udp'] = results[ip]['udp']
    pprint(ports['udp'])
  return ports

def hydra(service, accounts):
  login = []
  for i in accounts:
    cmd = ("hydra -l %s -e nsr %s" % (i, service)).split();
    p = Popen(cmd, stderr=PIPE, stdout=PIPE)
    output = p.communicate()[0].decode().rstrip().splitlines()
    for line in output:
      if "login" in line and "tries" not in line:
        print(color(line, "green"))

def netbios_scan(host):
  cmd = ("nbtscan -v -h -s : %s" % host).split()
  p = Popen(cmd, stderr=PIPE, stdout=PIPE)
  output = p.communicate()[0].decode().rstrip()
  print(output)

def enum4linux(host):
  cmd = ("enum4linux -S %s" % host).split()
  p = Popen(cmd, stderr=PIPE, stdout=PIPE)
  output = p.communicate()[0].decode().rstrip().splitlines()
  out = []
  for line in output:
    if 'OK' in line or '[+]' in line:
      out.append(line)
  print('\n'.join(str(v) for v in out))

def dirb(url, wordlist):
  if wordlist: cmd = ("dirb %s -a linux -w %s" % (url, wordlist)).split()
  else: cmd= ("dirb %s -a linux" % url).split()
  p = Popen(cmd, stderr=PIPE, stdout=PIPE)
  output = p.communicate()[0].decode().rstrip().splitlines()
  out= []
  print("  dirb output:")
  for line in output:
    if 'CODE:200' in line:
      print(line)
      out.append(line.split()[1])
  return out

def cewl(sitelist):
  if not sitelist: return ''
  wordlist = []
  for url in sitelist:
    cmd = ("cewl %s" % url).split()
    p = Popen(cmd, stderr=PIPE, stdout=PIPE)
    output = p.communicate()[0].decode().rstrip().splitlines()
    for line in output:
      if line not in wordlist:
        wordlist.append(line)
  print("Done. Generated wordlist with %s words" % len(wordlist))
  f = open(".tmp-cewl", "w")
  f.write('\n'.join(str(v) for v in wordlist))
  f.close(); wordlist = '.tmp-cewl'
  if wordlist: return wordlist
  else: return ''

def tcp_scan(host, ports):
  ports = list(ports.keys())
  if 80 in ports: ports.remove(80); ports.append(80)
  if 443 in ports: ports.remove(443); ports.append(443)

  for port in ports:
    if port == 21:
      print(color("\n[*] Trying ftp default login", "blue"))
      hydra("%s://%s" % ("ftp",host), ("anonymous", "ftp"))
    elif port == 22:
      print(color("\n[*] Trying ssh default login", "blue"))
      hydra("%s://%s" % ("ssh",host), ("root"))
    elif port == 139:
      print(color("\n[*] Running nbtscan on host %s" % host, "blue"))
      netbios_scan(host)

    elif port == 445:
      print(color("\n[*] Running enum4linux on host %s" % host, "blue"))
      enum4linux(host)

    elif port == 3306:
      print(color("\n[*] Trying mysql default login", "blue"))
      hydra("%s://%s" % ("mysql",host), ("root"))

    elif port == 80 or port == 443:
      if port == 80 and 443 not in ports: url = "http://%s/" % host
      elif port == 443 and 80 not in ports: url = "https://%s/" % host
      else: url = "https://%s/" % host
      print(color("\n[*] Running web enumeration %s" % host, "blue"))
      sitelist = dirb(url, '') #USING DIRB FUNCTION
      print("running cewl on sites...")
      wordlist = cewl(sitelist) #USING CEWL FUNCTION
      if sitelist: dirb(url, wordlist) #USING DIRB FUNCTION

def udp_scan(ports):
  print("udp scan")


def main(ip):
  print(color("[*] running quick scan on %s" % ip,"blue"))
  ports = quick_scan(ip)
  if "tcp" in ports.keys(): tcp_scan(ip, ports['tcp'])
  if "udp" in ports.keys(): udp_scan(ip, ports['udp'])


main(ip)
