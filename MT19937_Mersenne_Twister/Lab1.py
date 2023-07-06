import time
import random
import base64
from MT19937 import *
from requests import *
# Task 1
# Members: Israel Banez, Reed McCullough

# Part 1: Implement MT19937 Mersenne Twister
w, n, m, r = 32, 624, 397, 31
a = 0x9908B0DF
u, d = 11, 0xFFFFFFFF
s, b = 7, 0x9D2C5680
t, c = 15, 0xEFC60000
l = 18
f = 1812433253

MT = [0] * 624
index = n + 1
lower_mask = (1 << r) - 1
upper_mask = (~lower_mask) & 0xffffffff


# Creates an array of size 624 containing 32 bit integers 
def seed_mt(seed):
    
    global index
    index = n
    MT[0] = seed
    for i in range(1, n ):
        MT[i] = (f * (MT[i - 1] ^ (MT[i - 1] >> (w - 2))) + i) & 0xffffffff


def extract_number1():
    global index
    if index >= n:
        #if index > n:
            
         #   raise ValueError(n)
        twist()

    y = MT[index]
    y = y ^ ((y >> u) & d)
    y = y ^ ((y << s) & b)
    y = y ^ ((y << t) & c)
    y = y ^ (y >> l)

    index += 1
    return (y) & 0xffffffff


def twist():
    global index
    for i in range(n):
        x = (MT[i] & upper_mask) | (MT[(i + 1) % n] & lower_mask)
        xA = x >> 1
        if (x % 2) != 0:
            xA = xA ^ a
        MT[i] = MT[(i + m) % n] ^ xA
    index = 0

# Part 2: Break it --------------------------------------------

def oracle():
    time.sleep(random.randrange(5, 60))
    seed_mt(int(time.time()))
    time.sleep(random.randrange(5, 60))
    answer = base64.b64encode(bytes(str(extract_number1()), "utf-8"))
    return answer

def unmix(v):
    v = v ^ (v >> l)
    v = v ^ ((v << t) & c)
    for i in range(7):
        v = v ^ ((v << s) & b)
    for i in range(3):
        v = v ^ ((v >> u) & d)
    return v


def main():
    tokens = []
    untoken = []
    #totalLength = 0
    post('http://localhost:8080/register', {"user": "bob@calpoly.edu", "password": "1234"})
    for i in range(78):
        print("Token #:", i)
        r = post('http://localhost:8080/forgot', {"user": "bob@calpoly.edu"}).text
        ind = r.find("token=") + 6
        stopInd = r.find("<!--close_token-->")
        #print(r, "ASsa")
        div = (base64.b64decode(r[ind:stopInd]).decode('utf-8')).split(":")
        for i in div:
            tokens += [int(i)]
            untoken += [unmix(int(i))]
        
        #totalLength += len(r[ind:stopInd])
    
    print(tokens)
    print(untoken)
    print(len(tokens))
    # clone the inital state
    for i in range(n):
        MT[i] = untoken[i]
    print(index)
    print(MT, len(MT))
    
    # makes the next token
    newtok = str(extract_number1())
    
    for i in range(7):
        newtok += ":" + str(extract_number1())
        print(newtok)
    print(base64.b64encode(newtok.encode('utf-8')))
    tken = base64.b64encode(newtok.encode('utf-8'))

    # request reset for admin
    print(str(tken.decode()))
    r = post('http://localhost:8080/forgot', {"user": "admin"}).text
    print(r)

    # change passwrord
    r = post('http://localhost:8080/reset', {"password": "123", "token": str(tken.decode())}).text
    print(r)
    r = post('http://localhost:8080', {"username": "admin", "password": "123"}).text
    print(r)
    #seed_mt(untoken[0])
    

if __name__ == '__main__':
    main()
