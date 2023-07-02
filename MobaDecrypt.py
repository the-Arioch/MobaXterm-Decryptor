#!/usr/bin/env python3
import sys, os, platform, random, base64, binascii
from Crypto.Hash import SHA512
from Crypto.Cipher import AES
import sys

########### Crypto Code borrowed from https://github.com/HyperSine/how-does-MobaXterm-encrypt-password
class MobaXtermCrypto:

    def __init__(self, SysHostname: bytes, SysUsername: bytes, SessionP: bytes = None):
        self._SysHostname = SysHostname
        self._SysUsername = SysUsername
        self._SessionP = SessionP

    def _KeyCrafter(self, **kargs) -> bytes:
        if kargs.get('ConnHostname') != None and kargs.get('ConnUsername') != None:
            s1 = self._SysUsername + self._SysHostname
            while len(s1) < 20:
                s1 = s1 + s1

            s2 = kargs.get('ConnUsername') + kargs.get('ConnHostname')
            while len(s2) < 20:
                s2 = s2 + s2

            key_space = [
                s1.upper(),
                s2.upper(),
                s1.lower(),
                s2.lower()
            ]
        else:
            s = self._SessionP
            while len(s) < 20:
                s = s + s

            key_space = [
                s.upper(),
                s.upper(),
                s.lower(),
                s.lower()
            ]

        key = bytearray(b'0d5e9n1348/U2+67')
        for i in range(0, len(key)):
            b = key_space[(i + 1) % len(key_space)][i]
            if (b not in key) and (b in b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/'):
                key[i] = b

        return bytes(key)

################### THIS DECODES HASHES THAT ARE FROM INI FILES
    def DecryptCredential(self, Ciphertext: str) -> bytes:
        key = self._KeyCrafter()

        ct = bytearray()
        for char in Ciphertext.encode('ascii'):
            if char in key:
                ct.append(char)

        if len(ct) % 2 == 0:
            pt = bytearray()
            for i in range(0, len(ct), 2):
                l = key.find(ct[i])
                key = key[-1:] + key[0:-1]
                h = key.find(ct[i + 1])
                key = key[-1:] + key[0:-1]
                assert (l != -1 and h != -1)
                pt.append(16 * h + l)
            return bytes(pt)
        else:
            raise ValueError('Invalid ciphertext.')

#################### IF STORED IN REGISTRY YOU NEED 2 MORE PARAMS: THE CONNECTION'S IP/HOST and USERNAME
    def DecryptPassword(self, Ciphertext: str, ConnHostname: bytes, ConnUsername: bytes) -> bytes:
        key = self._KeyCrafter(ConnHostname = ConnHostname, ConnUsername = ConnUsername)

        ct = bytearray()
        for char in Ciphertext.encode('ascii'):
            if char in key:
                ct.append(char)

        if len(ct) % 2 == 0:
            pt = bytearray()
            for i in range(0, len(ct), 2):
                l = key.find(ct[i])
                key = key[-1:] + key[0:-1]
                h = key.find(ct[i + 1])
                key = key[-1:] + key[0:-1]
                assert(l != -1 and h != -1)
                pt.append(16 * h + l)
            return bytes(pt)
        else:
            raise ValueError('Invalid ciphertext.')


def DecryptLine(SysHostname: str, SysUsername: str, SessionP: str, Ciphertext: str, 
                ConnHostname: str = None, ConnUsername: str = None):
    Host_B = SysHostname.encode('mbcs')
    User_B = SysUsername.encode('mbcs')
    Sess_B = SessionP.encode('mbcs')
    
    print("[*] Computer: "+SysHostname)
    print("[*] Username: "+SysUsername)
    print("[*] SessionP: "+SessionP)
    print("[*] EncPass:  "+Ciphertext)

    cipher = MobaXtermCrypto(Host_B,User_B,Sess_B)
    
    if (ConnHostname is None) or (ConnUsername is None):
      passw = cipher.DecryptCredential(Ciphertext)
    else:
      ConnHost_B = ConnHostname.encode('mbcs')
      ConnUser_B = ConnUsername.encode('mbcs')
      
      print("[*] Host/IP:  "+ConnHostname)
      print("[*] User:     "+ConnUsername)
      
      passw = cipher.DecryptPassword(Ciphertext,ConnHost_B,ConnUser_B)
      
    print("[*] Password: " + passw.decode("mbcs"))
    print()

print('''
  __  __       _          __  ___
 |  \/  | ___ | |__   __ _\ \/ / |_ ___ _ __ _ __ ___
 | |\/| |/ _ \| '_ \ / _` |\  /| __/ _ \ '__| '_ ` _ \
 | |  | | (_) | |_) | (_| |/  \| ||  __/ |  | | | | | |
 |_|__|_|\___/|_.__/ \__,_/_/\_\\__\____|_|  |_| |_| |_|
 |  _ \  ___  ___ _ __ _   _ _ __ | |_ ___  _ __
 | | | |/ _ \/ __| '__| | | | '_ \| __/ _ \| '__|
 | |_| |  __/ (__| |  | |_| | |_) | || (_) | |
 |____/ \___|\___|_|   \__, | .__/ \__\___/|_|
                       |___/|_|

      by illwill - decryption class by HyperSine\n''')

if len(sys.argv) == 5:
    DecryptLine(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
    sys.exit(0) # correct exit
if len(sys.argv) == 7:
    DecryptLine(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
    sys.exit(0) # correct exit

print("Usage:\n")
print("From inifile:")
print("    MobaDecrypt.py Computer Username SessionP Hash\n")
print("From Registry Password:")
print("    MobaDecrypt.py Computer Username SessionP Hash Host/IP User")
print("From Registry Credential:")
print("    MobaDecrypt.py Computer Username SessionP Hash")
sys.exit(2) # command line error    