from binascii import *
from base64 import *
import codecs
from itertools import zip_longest
from sys import *
from langdetect import detect, detect_langs, DetectorFactory

# A. Implement Encoders & Decoders


def ascii_str_to_hex(str_val):
    return hexlify(str_val)


def hex_to_ascii(hex_val):
    return unhexlify(hex_val)


def base64_str_to_hex(str_val):
    return ascii_str_to_hex(b64decode(str_val))


def hex_to_base64(hex_val):
    return b64encode(hex_to_ascii(hex_val))

#----------------------------------------------------------------------------------------------------------------------------------------------
# Task II

# Part A: Implement XOR


def xor_two_bstr(plain, key):
    new_key = key
    while len(new_key) < len(plain):

        new_key += key

    # key is less than or greater than plain length
    if len(new_key) > len(plain):
        new_key = new_key[:len(plain)]

    # Xor each byte

    return bytes([p ^ k for p, k in zip(plain, new_key)])

#--------------------------------------------------------------------------------------------------------------------------------------------------
# Part B: Single-byte XOR

def decryption_func(str_val):
    mx_score = -1
    answer = ""
    key = -1

    for i in range(256):
        line = str(xor_two_bstr(str_val, bytes(chr(i), "utf-8")))
        decoded_lines = detect(line)

        if decoded_lines == "en":  # detects english language
            # print(line, i)       # turn on for observation of the whole 1000 lines and each of their encryption options
            score = detect_langs(line)
            if float(str(score[0])[3:]) > mx_score:  # determines the highest score
                mx_score = float(str(score[0])[3:])
                answer = line
                key = bytes(chr(i), "utf-8")
    return [answer, mx_score, key]


def single_b_xor():
    file = open(argv[1], 'r')
    for i in file.readlines():
        decrypt = decryption_func(hex_to_ascii(
            i.strip()))
        if decrypt[0] != "":
            print(decrypt)
        # Once a suitable answer is displayed, stop the running code (crtl+C), else it will run for a long time

# KEY: b'\x7f' (127)
# PLAINTEXT: b"Out on bail, fresh out of jail, California dreaming\nSoon as I step on the scene, I'm hearing ladies screaming"


#-----------------------------------------------------------------------------------------------------------------------------------------------
# Part C: Multi-byte XOR

def hamming_distance(block1, block2):
    distance = 0
    for (b1, b2) in zip(block1, block2):
        distance += bin(b1 ^ b2).count("1")
    return distance


def mult_decryption(blocks, blnum):
    for i in range(256):
        line = xor_two_bstr(blocks, bytes(chr(i), "utf-8"))
        print(line, i, blnum)


def multi_b_xor():
    file = open(argv[1], 'r')
    f = file.read()
    ascii_text = hex_to_ascii(base64_str_to_hex(f))  # decode base64
    min_hd_score = len(ascii_text)
    key_size = 0

    # get key size
    for size in range(1, 40):
        blocks = []

        for block in range(0, int(len(ascii_text)), size):  # block text by key size
            blocks.append(ascii_text[block:block+size])
        sample_group = blocks[:5]  # do only the first 5 blocks
        hd_score = 0

        for b in range(1, 5):  # compute hamming distance
            hd_score += hamming_distance(
                sample_group[b - 1], sample_group[b]) / size

        avg_score = hd_score / 4
        if avg_score < min_hd_score:  # choose the lowest avg hd
            min_hd_score = avg_score
            key_size = size

    # transpose
    transposed = [ascii_text[i::key_size] for i in range(key_size)]

    # get key
    num = 0
    # prints out a list of all possible combinations from 0-255 for each block in transposed
    for block in transposed:
        mult_decryption(block, num)
        num += 1

    # visibly "a" for position 0, "y" for position 1, and "Z" for position 4 are easy to read from list except positions 2 & 3
    # key so far = "ay__Z"

    # Brute force the remaining two postions till an english sentence is clear
    for i in range(256):
        for j in range(256):
            print(xor_two_bstr(ascii_text, bytes([97, 121, i, j, 90])), i, j)
    key = b'ay\xb5\xe7Z'
    print(xor_two_bstr(ascii_text, key))

# KEY: b'ay\xb5\xe7Z'  [97, 121, 181, 231, 90]
# PLAINTEXT: b"One, two, three and to the fo'\n
# Snoop Doggy Dogg and Dr. Dre is at the door\n
# Ready to make an entrance so back on up\n
# (Cause you know we're about to rip stuff up) \n
# Give me the microphone first so I can bust like a bubble\n
# Compton and Long Beach together now you know you in trouble\n
# Ain't nothing but a G thang, baby \n
# Two loc'ed out dudes so we're crazy\n
# Death Row is the label that pays me\n
# Unfadeable so please don't try to fade this\n"



#------------------------------------------------------------------------------------------------------------------------------------
# Part D:  Vigenère Cipher

def rot_some_num(text, num):
    new_text = ""
    for i in text:
        trans = ord(i) - num

        if trans < 65:
            trans = trans + 26

        new_text += chr(trans)
    return new_text


def chi_stat(occurances, text_length):
    freq = {
        'A': .0824,    'B': .0151,    'C': .0281,    'D': .0429,
        'E': .1281,    'F': .0225,    'G': .0203,    'H': .0615,
        'I': .0615,    'J': .0015,    'K': .0078,    'L': .0406,
        'M': .0243,    'N': .0681,    'O': .0757,    'P': .0195,
        'Q': .0010,    'R': .0604,    'S': .0638,    'T': .0914,
        'U': .0278,    'V': .0099,    'W': .0238,    'X': .0015,
        'Y': .0199,    'Z': .0007
    }
    chi_sum = 0
    for i in range(len(occurances)):
        observed = occurances[i]
        expected = text_length * freq[chr(i + 65)]
        chi_sum += ((observed - expected) ** 2) / expected
    return chi_sum


def vin_decryption(blocks, num):
    min_chi_sum = 100000
    key = -1
    new_text = ""
    for i in range(26):
        occurances = [0] * 26
        rot_block = rot_some_num(blocks, i)
        
        for j in range(len(rot_block)):
            occurances[ord(rot_block[j]) - 65] += 1
       
        chi_sum = chi_stat(occurances, len(rot_block))
        if chi_sum < min_chi_sum:
            min_chi_sum = chi_sum
            key = i
            new_text = rot_block
    
    print(key, new_text, min_chi_sum)
    return [key, new_text]


def vig_decoder():
    file = open(argv[1], 'r')
    f = file.read()
    print(f)
    nums = []
    # look for coincidences
    for i in range(1, len(f)):
        padding = "" + ("0"*i)  # f[-i:]
        new_txt = padding + f[:-i]
        count = sum(1 for a, b in zip(f, new_txt) if a == b)
        nums += [count]
        
    # make a csv graph to observe differnces
    '''for i in range(len(nums)):
        print(f"{nums[i]}, {i}")'''
    # the pattern appears to be 14
    # next transpose
    key_size, num = 14, 0
    transposed = [f[i::key_size] for i in range(key_size)]
    # prints out a list of all possible combinations from 65-90 (A-Z)for each block in transposed
    full_key = ""
    cipher, key_num = [], []
    plaintext = ""

    for block in transposed:
        key_part = vin_decryption(block, num)
        key_num += [key_part[0]]
        full_key += str(chr(key_part[0] + 65))
        cipher.append(key_part[1])
        num += 1

    print(full_key)
    for i in range(len(f)):
        pos = i % 14
        trans = ord(f[i]) - key_num[pos]
        
        if trans < 65:
            trans = trans + 26
        plaintext += chr(trans)
    print(plaintext)

# KEY = "MOMONEYMOPROBS"
# PLAINTEXT = "BIGPOPPANOINFOFORTHEDEAFEDERALAGENTSMADCAUSEIMFLAGRANTTAPMYCELLANDTHEPHONEINTHEBASEMENTMYTEAMSUPREME
# STAYCLEANTRIPLEBEAMLYRICALDREAMIBETHATCATYOUSEEATALLEVENTSBENTGATSINHOLSTERSGIRLSONSHOULDERSPLAYBOYITOLDYAMEREMICS
# TOMEBRUISETOOMUCHILOSETOOMUCHSTEPONSTAGETHEGIRLSBOOTOOMUCHIGUESSITSCAUSEYOURUNWITHLAMEDUDESTOOMUCHMELOSEMYTOUCHNEVER
# THATIFIDIDAINTNOPROBLEMTOGETTHEGATWHERETHETRUEPLAYERSATTHROWYOURROLIESINTHESKYWAVEEMSIDETOSIDEANDKEEPYOURHANDSHIGHWHILE
# IGIVEYOURGIRLTHEEYEPLAYERPLEASELYRICALLYFELLASSEEBIGBEFLOSSINGJIGONTHECOVEROFFORTUNEDOUBLEOHERESMYPHONENUMBERYOURMANAINT
# GOTTOKNOWIGOTTHEDOUGHGOTTHEFLOWDOWNPIZATPLATINUMPLUSLIKETHIZATDANGEROUSONTRIZACKSLEAVEYOURASSFLIZAT"

# Run any one of these 3, one at a time
#single_b_xor()
#multi_b_xor()
vig_decoder()

