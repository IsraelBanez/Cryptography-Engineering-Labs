
from base64 import b64decode
from binascii import hexlify, unhexlify
from http import cookiejar
from operator import xor
from sys import argv
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Cipher import AES
import io
import PIL.Image as Image
from requests import *
import json
import urllib, os

# Members: Israel Banez, Reed McCullough
# Lab 0 XOR
def xor_two_bstr(plain, key):
    new_key = key
    while len(new_key) < len(plain):

        new_key += key

    # key is less than or greater than plain length
    if len(new_key) > len(plain):
        new_key = new_key[:len(plain)]

    # Xor each byte

    return bytes([p ^ k for p, k in zip(plain, new_key)])

# Task I: Padding for Block Ciphers
def pkcs7_pad(txt, blksz):
    return pad(txt, blksz)

def pkcs7_unpad(txt, blksz): 
    # txt mod blksz
    return unpad(txt, blksz)

# --------------------------------------------------------------------------------------------------

# Task II: ECB Mode

# Task II Implement ECB Mode 
def ecb_encrypt(key, pltxt):
    cipher = AES.new(key, AES.MODE_ECB)
    paddedtxt = pkcs7_pad(pltxt, AES.block_size)
    ciphertxt = cipher.encrypt(paddedtxt)
    return ciphertxt

def ecb_decrypt(key, cphtxt):
    decipher = AES.new(key, AES.MODE_ECB)
    deciphertxt = decipher.decrypt(cphtxt)
    unpaddedtxt = pkcs7_unpad(deciphertxt, AES.block_size)
    return unpaddedtxt
    
def task2_1():
    file = open(argv[1], 'r')
    key = bytes("CALIFORNIA LOVE!", "utf-8")
    b64dec = b64decode(bytes(file.read(), "utf-8"))
    plaintext = ecb_decrypt(key, b64dec)
    print(plaintext)

# Task II Identify ECB Mode
def task2_2():
    file = open(argv[1], 'r')
    f = file.readlines()
    for i in range(len(f)):
        blocks = []
        duplicate_cnt = 0
        unhex = unhexlify(f[i].strip())
        cipherblk = unhex[54:]
        # divide the text into blocks to observe any repetition 
        for j in range(0, int(len(cipherblk)), 16):
            blk16 = cipherblk[j : j + 16]
            if blk16 in blocks:
                duplicate_cnt += 1
            blocks.append(blk16)
        print(blocks)
        print(duplicate_cnt)
        # once repetition is reached, display image
        if duplicate_cnt != 0:
            print("here sir on line " + str(i + 1))
            img = Image.open(io.BytesIO(unhex))
            img.show()
            break

# Task II ECB Cookies
def task2_3():
    s = Session()
    # Push user to get role=
    push_user_role = "AAAAAAAAAAAAAAA"

    # make an m[1] admin with padding
    username = "admin"
    padbytes = AES.block_size - len(username)%AES.block_size
    user = username + '\x00' * (padbytes - 1) + chr(padbytes)
    user = "AAAAAAAAAAA" + user 
    r = s.post('http://127.0.0.1:8080/register', {"user": push_user_role, "password": "1"})
    r1 = s.post('http://127.0.0.1:8080/register', {"user": user, "password": "1"})

    r = s.post('http://127.0.0.1:8080', data={"user": push_user_role, "password": "1"})
    user_part1_cookie =  s.cookies["auth_token"]
    r1 = s.post('http://127.0.0.1:8080', data={"user": user, "password": "1"})
    user_part2_cookie = s.cookies["auth_token"]
    # block alignmnet 
    block_size = 32
    blocked_cookies_1 = [user_part1_cookie[i:i+block_size] for i in range(0, len(user_part1_cookie), block_size) ]
    blocked_cookies_2 = [user_part2_cookie[i:i+block_size] for i in range(0, len(user_part2_cookie), block_size) ]
    admin_cookie  = blocked_cookies_1[0] + blocked_cookies_1[1] + blocked_cookies_2[1]


    r3 = s.get('http://127.0.0.1:8080/home', cookies={"auth_token": admin_cookie})
    print(r3.text)

# --------------------------------------------------------------------------------------------------

# Task III: Implement CBC Mode 

# Task III Implement CBC Mode
def cbc_encrypt(plaintext, key, iv):
    answer = b""
    paddedtxt = pkcs7_pad(plaintext, 16)
    cipher = AES.new(key, AES.MODE_ECB)
    blocks = [paddedtxt[i:i+AES.block_size] for i in range(0, len(paddedtxt), AES.block_size) ]
    prev_txt = iv
    for i in blocks:
        xor_txt = xor_two_bstr(i, prev_txt)
        ciphertext = cipher.encrypt(xor_txt)
        answer += ciphertext
        prev_txt = ciphertext
    return answer

def cbc_decrypt(ciphertext, key, iv):
    answer = b""
    decipher = AES.new(key, AES.MODE_ECB)
    blocks = [ciphertext[i:i+AES.block_size] for i in range(0, len(ciphertext), AES.block_size) ]
    prev_txt = iv
    for i in blocks:
        deciphertxt = decipher.decrypt(i)
        xor_txt = xor_two_bstr(deciphertxt, prev_txt)
        answer += xor_txt
        prev_txt = i
    
    return pkcs7_unpad(answer, AES.block_size)
    
def task3_2():
    file = open(argv[1], 'r')
    key = bytes("MIND ON MY MONEY", "utf-8")
    iv = bytes("MIND ON MY MONEY", "utf-8")
    b64dec = b64decode(bytes(file.read(), "utf-8"))
    plaintext = cbc_decrypt(b64dec, key, iv)
    print(plaintext)

# Task III CBC Cookies
def task3_2():
    s = Session()

    # create user
    user = "user" +  '0' + "role" + '0' + "admin"
    r = s.post('http://127.0.0.1:8080/register', {"user": user, "password": "1"})

    r = s.post('http://127.0.0.1:8080', data={"user": user, "password": "1"})
    
    # get cookie
    user_cookie =  s.cookies["auth_token"]
    user_cookie = unhexlify(user_cookie)

    # block the cookie
    block_size = AES.block_size
    blocked_cookies = [user_cookie[i:i+block_size] for i in range(0, len(user_cookie), block_size) ]

    mblock_0 = [i for i in blocked_cookies[0]]
    mblock_1 = [i for i in blocked_cookies[1]]
    mblock_2 = [i for i in blocked_cookies[2]]
    mblock_3 = [i for i in blocked_cookies[3]]

    # bit flipping attack here
    mblock_0[9] =  mblock_0[9] ^ ord("0") ^ord("&")
    mblock_0[14] = mblock_0[14] ^ ord("0") ^ ord("=")  
    blocked_cookies[0] = bytes(mblock_0)
  
    admin_cookie = str(hexlify(blocked_cookies[0] + blocked_cookies[1] + blocked_cookies[2] + blocked_cookies[3]), "utf-8")

    r3 = s.get('http://127.0.0.1:8080/home', cookies={"auth_token": admin_cookie})
    print(r3.text)

if __name__ == '__main__':
    #task2_1()
    #task2_2()
    task2_3()
    #task3_1()
    #task3_2()
