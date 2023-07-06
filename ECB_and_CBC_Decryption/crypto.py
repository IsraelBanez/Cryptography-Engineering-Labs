from Cryptodome.Cipher import AES
import urllib

#I read about this padding scheme here: http://en.wikipedia.org/wiki/Padding_(cryptography)#ANSI_X.923
def ansix923_pad(plain,blocksize):
	
	padbytes = blocksize - len(plain)%blocksize
	plain += '\x00' * (padbytes - 1) + chr(padbytes)
	return plain

def ansix923_strip(plain,blocksize):

    numblocks = int(len(plain)/(blocksize) + (1 if len(plain)%blocksize else 0))

    #Get everything up to the last block
    newplain = plain[:(numblocks-1)*blocksize]
    #Get the block with adding
    padblock = plain[(numblocks-1)*blocksize:]
    padbytes = int(padblock[-1:].hex(),16)
    #Validate padding - we should never see a pad end in zero
    if padbytes == 0 or padbytes > blocksize:
        raise Exception("PaddingError")
        return ""
    #make sure all the pad bytes make sense
    for b in padblock[blocksize-padbytes:blocksize-1]:
        if b != 0:
            raise Exception("PaddingError")
            return ""

    newplain += padblock[:-padbytes]

    return newplain.decode("UTF-8")


def create_crypto_cookie(user, userid, role, key):
    #Create the cookie contents
    cookie = "user=" + user + "&uid=" + str(userid) + "&role=" + role
    #Use strong crypto so cookie can't be read or changed.
    aes_obj = AES.new(bytes(key),AES.MODE_ECB)
    return aes_obj.encrypt(bytes(ansix923_pad(cookie, AES.block_size), "UTF-8"))

def verify_crypto_cookie(enc_cookie, key):

    aes_obj = AES.new(bytes(key),AES.MODE_ECB)
    cookie_pad = aes_obj.decrypt(enc_cookie)
    cookie = ansix923_strip(cookie_pad, AES.block_size)
    query = urllib.parse.parse_qs(cookie)
    
    return query["user"][0], query["uid"][0], query["role"][0]