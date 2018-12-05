"""
Based on the code from the official Mikrotik website:
    https://wiki.mikrotik.com/wiki/Manual:API_Python3

Amended by Khashayar Namdar
knamdar@uwo.ca
"""
#!/usr/bin/python3
# -*- coding: latin-1 -*-
import sys, binascii, socket, select # posix, time,
import hashlib
from threading import Thread

class ApiRos:
    "Routeros api"
    def __init__(self, sk):
        self.sk = sk
        self.currenttag = 0

    def login(self, username, pwd):
        for repl, attrs in self.talk(["/login", "=name=" + username,
                                      "=password=" + pwd]):
          if repl == '!trap':
            return False
          elif '=ret' in attrs.keys():
            chal = binascii.unhexlify((attrs['=ret']).encode(sys.stdout.encoding))
            md = hashlib.md5()
            md.update(b'\x00')
            md.update(pwd.encode(sys.stdout.encoding))
            md.update(chal)
            for repl2, attrs2 in self.talk(["/login", "=name=" + username,
                   "=response=00" + binascii.hexlify(md.digest()).decode(sys.stdout.encoding) ]):
              if repl2 == '!trap':
                return False
        return True

    def talk(self, words):
        if self.writeSentence(words) == 0: return
        r = []
        while 1:
            i = self.readSentence();
            if len(i) == 0: continue
            reply = i[0]
            attrs = {}
            for w in i[1:]:
                j = w.find('=', 1)
                if (j == -1):
                    attrs[w] = ''
                else:
                    attrs[w[:j]] = w[j+1:]
            r.append((reply, attrs))
            if reply == '!done': return r

    def writeSentence(self, words):
        ret = 0
        for w in words:
            self.writeWord(w)
            ret += 1
        self.writeWord('')
        return ret
        
    def readSentence(self):
        r = []
        while 1:
            w = self.readWord()
            if w == '': return r
            r.append(w)

    def writeWord(self, w):
        print(("<<< " + w))
        self.writeLen(len(w))
        self.writeStr(w)

    def readWord(self):
        ret = self.readStr(self.readLen())
        print((">>> " + ret))
        return ret

    def writeLen(self, l):
        if l < 0x80:
            self.writeByte((l).to_bytes(1, sys.byteorder))
        elif l < 0x4000:
            l |= 0x8000
            tmp = (l >> 8) & 0xFF
            self.writeByte(((l >> 8) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte((l & 0xFF).to_bytes(1, sys.byteorder))
        elif l < 0x200000:
            l |= 0xC00000
            self.writeByte(((l >> 16) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte(((l >> 8) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte((l & 0xFF).to_bytes(1, sys.byteorder))
        elif l < 0x10000000:
            l |= 0xE0000000
            self.writeByte(((l >> 24) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte(((l >> 16) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte(((l >> 8) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte((l & 0xFF).to_bytes(1, sys.byteorder))
        else:
            self.writeByte((0xF0).to_bytes(1, sys.byteorder))
            self.writeByte(((l >> 24) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte(((l >> 16) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte(((l >> 8) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte((l & 0xFF).to_bytes(1, sys.byteorder))

    def readLen(self):
        c = ord(self.readStr(1))
        # print (">rl> %i" % c)
        if (c & 0x80) == 0x00:
            pass
        elif (c & 0xC0) == 0x80:
            c &= ~0xC0
            c <<= 8
            c += ord(self.readStr(1))
        elif (c & 0xE0) == 0xC0:
            c &= ~0xE0
            c <<= 8
            c += ord(self.readStr(1))
            c <<= 8
            c += ord(self.readStr(1))
        elif (c & 0xF0) == 0xE0:
            c &= ~0xF0
            c <<= 8
            c += ord(self.readStr(1))
            c <<= 8
            c += ord(self.readStr(1))
            c <<= 8
            c += ord(self.readStr(1))
        elif (c & 0xF8) == 0xF0:
            c = ord(self.readStr(1))
            c <<= 8
            c += ord(self.readStr(1))
            c <<= 8
            c += ord(self.readStr(1))
            c <<= 8
            c += ord(self.readStr(1))
        return c

    def writeStr(self, str):
        n = 0;
        while n < len(str):
            r = self.sk.send(bytes(str[n:], 'UTF-8'))
            if r == 0: raise RuntimeError("connection closed by remote end")
            n += r

    def writeByte(self, str):
        n = 0;
        while n < len(str):
            r = self.sk.send(str[n:])
            if r == 0: raise RuntimeError("connection closed by remote end")
            n += r

    def readStr(self, length):
        ret = ''
        # print ("length: %i" % length)
        while len(ret) < length:
            s = self.sk.recv(length - len(ret))
            if s == b'': raise RuntimeError("connection closed by remote end")
            # print (b">>>" + s)
            # atgriezt kaa byte ja nav ascii chars
            if s >= (128).to_bytes(1, "big") :
               return s
            # print((">>> " + s.decode(sys.stdout.encoding, 'ignore')))
            ret += s.decode(sys.stdout.encoding, "replace")
        return ret

def out_str(co_inst):
    
    inputsentence=input("")
    if inputsentence=="{quit}":
        sys.exit(1)
    co_inst.writeWord(inputsentence)
    
    
def inc_str(sock_inst, co_inst):
    
    r = select.select([sock_inst], [], [], 0.0)
    if sock_inst in r[0]:
        x = co_inst.readSentence()
    

def main():
    s = None
    for res in socket.getaddrinfo(sys.argv[1], sys.argv[2], socket.AF_UNSPEC, socket.SOCK_STREAM):
        af, socktype, proto, canonname, sa = res
        try:
             s = socket.socket(af, socktype, proto)
        except socket.error:
            s = None
            continue
        try:
            s.connect(sa)
        except socket.error:
            s.close()
            s = None
            continue
        break
    if s is None:
        print ('could not open socket')
        sys.exit(1)

    apiros = ApiRos(s);
    
    # use default username and pasword if not specified
    if len(sys.argv) == 5:
      if not apiros.login(sys.argv[3], sys.argv[4]):
        return
    elif len(sys.argv) == 4:
      if not apiros.login(sys.argv[3], ""):
        return
    else :
      if not apiros.login("admin", ""):
        return
    
    while 1:
        INC_THREAD = Thread(target=out_str(apiros))
        INC_THREAD.start()  # Starts the infinite loop.
        
        OUT_THREAD = Thread(target=inc_str(s, apiros))
        OUT_THREAD.start()  # Starts the infinite loop.
    

if __name__ == '__main__':
    main()