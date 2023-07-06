from binascii import hexlify, unhexlify
import struct
from sys import *
from base64 import *
from Cryptodome.Cipher import AES
from requests import *
from Cryptodome.Util.Padding import unpad
import string
import random
# Members: Israel Banez, Reed McCullough

# Task I: The Padding Oracle 

def task1():
    s = Session()

    # get cookies
    r = s.get('http://127.0.0.1:8080/eavesdrop').text
    ind = r.find("You eavesdropped the following message: </font></p>") + 118
    stopInd = r.find("</font></p><table>") - 250
    ciphertext = r[ind:stopInd]
    print(ciphertext, len(ciphertext))
    ciphertext_hex = bytes.fromhex(ciphertext)

    # block the cookie
    block_size = AES.block_size
    blocked_cookies = [ciphertext_hex[i:i+block_size] for i in range(0, len(ciphertext_hex), block_size) ]

    # padding oracle attack
    result = []
    for v in range(len(blocked_cookies) - 1): # for ever block
        bty = []
        pad_num = 1
        intermediates = [] 
        answer = []
        bl_n = [i for i in blocked_cookies[v]]
        for k in range(16, 0, -1): # for every byte
        
            for i in range(256):  # go through all 256 possiblities 
                target = bl_n[0: k - 1] + [i] + bty + bl_n[16:]         
                newcipher =(bytes(target) + blocked_cookies[v + 1]).hex()
                r2 = s.get(f'http://127.0.0.1:8080/?enc={newcipher}').status_code
                
                if r2 == 404:
                    inter = i ^ pad_num
                    pl = inter ^ bl_n[k - 1]
                    intermediates = [inter] + intermediates
                    answer = [pl] + answer
                    break
            
            pad_num += 1
            bty = [i ^  pad_num for i in intermediates]
        result = result + answer
    print(result)
    final_answer = unpad(bytes(result), 16)
    r1 = s.post('http://127.0.0.1:8080/submit', data={"guess" : final_answer}).text
    print(r1)
    exit() # 128

#---------------------------------------------------------------------------------

# Task II: SHA1

# Implement SHA1
def leftrotate(n, b):
   return((n << b) | (n >> (32 - b))) & 0xffffffff

def sha_1(m):
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0
    #m = bytes(m, "utf-8")
    ml = len(m) * 8

    m_1 = m + b"\x80" 
    m_2 = m_1 + b"\x00" * ((56 - (len(m) + 1) % 64) % 64)
    m_3 = m_2 + struct.pack(b">Q", ml) 

    chunk = [m_3[i:i+64] for i in range(0, len(m_3), 64)]

    for ch in chunk:
        w = list(struct.unpack(">16L", ch)) + [0] * 64
        
        for j in range(16, 80):
            w[j] = leftrotate(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1) 

        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        for i in range(80):
            if 0 <= i < 20:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i < 60:
                f = (b & c) | (b & d) | (c & d) 
                k = 0x8F1BBCDC
            elif 60 <= i < 80:
                f = b ^ c ^ d
                k = 0xCA62C1D6
                
            temp = (leftrotate(a, 5) + f + e + k + w[i]) & 0xffffffff
            e = d
            d = c
            c = (leftrotate(b, 30))
            b = a
            a = temp

        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff
        #print(h0, h1, h2, h3, h4)
    hh = '%08x %08x %08x %08x %08x' % (h0, h1, h2, h3, h4)
    
    #print(hh)
    return hh

# Find a Collision

def collision():
    hash_holder = {}

    while True:
        res = random.randint(0, 4294967296).to_bytes(8, "big")
        sha = sha_1(res).replace(" ", "")
        #print(sha)
        
        binary = bin(int(sha, 16))[2:].zfill(8)
        hsha1 = binary[0:50]
        #print( binary, len(binary))
        
        if hsha1 in hash_holder.keys():
            if hash_holder[hsha1] == res:
                continue
            else:
                print("collision with",hash_holder[hsha1], res)
                break

        else:
            hash_holder[hsha1] = res

#---------------------------------------------------------------------------------

# Task III: SHA1 Keyed MAC

# Length Extension Attack 

#************* DOESNT WORK FULLY***********************
def lenExAttack():
    s = Session()
    # pad = 08 + 00*56 + #
    print(sha_1(bytes("count=10&lat=37.351&user_id=1&long=-119.827&waffle=eggo", "utf-8")))
    r = s.get('http://127.0.0.1:8080/?who=Israel&what=The%20fellow%20playin%27%20first%20base.&mac=a83352e0cdebf1c361f05c17bef6d2f3dfdd7c25')
    print(r.text)
    exit()
    r = s.post('http://127.0.0.1:8080/?who=Israel&what=Eat%20apples%20for%20free.&mac=').text
    print(r)
    exit()
    key = b"YELLOW SUBMARINE"
    part1 = key + b"The fellow playin' first base."
    sha = sha_1(part1).replace(" ", "")
    sha_next = sha_1(key + sha)
    r = get('http://127.0.0.1:8080/?who=Israel&what=The%20fellow%20playin%27%20first%20base.&mac=a83352e0cdebf1c361f05c17bef6d2f3dfdd7c25')



if __name__ == '__main__':
    task1()
    '''
    a1 = sha_1(bytes("abc", "utf-8"))
    a2 = sha_1(bytes("", "utf-8"))
    a3 = sha_1(bytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "utf-8"))
    a4 = sha_1(bytes("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "utf-8"))
    # check sha1
    assert a1 == "a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d"
    assert a2 == "da39a3ee 5e6b4b0d 3255bfef 95601890 afd80709"
    assert a3 == "84983e44 1c3bd26e baae4aa1 f95129e5 e54670f1"
    assert a4 == "a49b2446 a02c645b f419f995 b6709125 3a04a259"'''
    #check for collision 
    #collision()
    '''print(sha_1(b'\x00\x00\x00\x00h\x1a4\xd3'))
    print(sha_1(b'\x00\x00\x00\x00\x8e\x9dG\x0b'))'''

    # task 3
    #lenExAttack()