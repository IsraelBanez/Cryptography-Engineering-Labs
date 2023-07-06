import sys, time, json, os
from ecdsa import VerifyingKey, SigningKey
from p2pnetwork.node import Node
import hashlib
from Cryptodome.Cipher import AES
from Cryptodome import Random

# Israel Banez and Reed M.
# Not Fully Implemented 
SERVER_ADDR = "zachcoin.net"
SERVER_PORT = 9067

# Message types
BLOCK = 0
TRANSACTION = 1
BLOCKCHAIN = 2
UTXPOOL = 3

# Mining constants
COINBASE = 50
DIFFICULTY = 0x000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

class ZachCoinClient (Node):
    
    #ZachCoin Constants
    BLOCK = 0
    TRANSACTION = 1
    BLOCKCHAIN = 2
    UTXPOOL = 3
    COINBASE = 50
    DIFFICULTY = 0x000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

    #Hardcoded gensis block
    blockchain = [
        {
            "type": BLOCK,
            "id": "124059f656eb6b016ce36583b5d6e9fdaf82420355454a4e436f4ee2ff17dba7",
            "nonce": "5052bfab11df236c43a4d877d93e42a3",
            "pow": "000000be01b9e4b6fdd73985083174007c30a98dc0801eaa830e27bbbea0d705",
            "prev": "124059f656eb6b016ce36583b5d6e9fdaf82420355454a4e436f4ee2ff17dba7",
            "tx": {
                "type": TRANSACTION,
                "input": {
                    "id": "0000000000000000000000000000000000000000000000000000000000000000",
                    "n": 0
                },
                "sig": "33399ed9ba1cc40eb1395ef8826955398446badb9c7c84113d545806714809a013c73d71b3326041853638b1190443af",
                "output": [
                    {
                        "value": 50,
                        "pub_key": "c26cfef538dd15b6f52593262403de16fa2dc7acb21284d71bf0a28f5792581b4a6be89d2a7ec1d4f7849832fe7b4daa"
                    }
                ]
            }
        }
    ]
    utx = []
  
    def __init__(self, host, port, id=None, callback=None, max_connections=0):
        super(ZachCoinClient, self).__init__(host, port, id, callback, max_connections)

    def outbound_node_connected(self, connected_node):
        print("outbound_node_connected: " + connected_node.id)
        
    def inbound_node_connected(self, connected_node):
        print("inbound_node_connected: " + connected_node.id)

    def inbound_node_disconnected(self, connected_node):
        print("inbound_node_disconnected: " + connected_node.id)

    def outbound_node_disconnected(self, connected_node):
        print("outbound_node_disconnected: " + connected_node.id)

    def node_message(self, connected_node, data):
        print("node_message from " + connected_node.id + ": " + json.dumps(data,indent=2))

        if data != None:
            if 'type' in data:
                if data['type'] == self.TRANSACTION:
                    self.utx.append(data)
                elif data['type'] == self.BLOCKCHAIN:
                    self.blockchain = data['blockchain']
                elif data['type'] == self.UTXPOOL:
                    self.utx = data['utxpool']
                #TODO: Validate blocks
                elif data['type'] == self.BLOCK:
                    print("Verifying ...")
                    v = verify_block(data, self.blockchain, self.utx)
                    if v == True:
                        print("-Verified-")
                        self.blockchain.append(data)
                        for i in self.utx:
                            if i["sig"] == data["tx"]["sig"]:
                                self.utx.remove(i)
                    

    def node_disconnect_with_outbound_node(self, connected_node):
        print("node wants to disconnect with oher outbound node: " + connected_node.id)
        
    def node_request_to_stop(self):
        print("node is requested to stop!")

#-----------------------------Tampered------------------------------------------------------------------------
# ------------------------------------------------------------------------------------------------------------
# Format the block
def block_format(BLOCK_ID, NONCE, SHA256_HASH, prev, utx):
    zc_block = {
        "type": BLOCK,
        "id": BLOCK_ID,
        "nonce": NONCE,
        "pow": SHA256_HASH,
        "prev": prev,
        "tx": utx
    }
    return zc_block

# Format the utx
def utx_format(BLOCK_ID, n, ECDSA_SIGNATURE, amount, ECDSA_PUBLIC_KEY):
    utx = {
    'type': TRANSACTION,
    'input': {
        'id': BLOCK_ID,
        'n': n
        },
    'sig': ECDSA_SIGNATURE,
    'output': [      
        {
         'value': amount,
         'pub_key': ECDSA_PUBLIC_KEY
      }]
    }
    return utx        

# Compute Block Id
def block_identifier(zc_block):
    #print(json.dumps(zc_block['tx'], sort_keys=True), "Json")
    block_id = hashlib.sha256(json.dumps(zc_block['tx'], sort_keys=True).encode('utf8')).hexdigest()
    return block_id

# Mine
def mine_transaction(utx):
   nonce = Random.new().read(AES.block_size).hex()
   while( int( hashlib.sha256(json.dumps(utx, sort_keys=True).encode('utf8') + nonce.encode('utf-8')).hexdigest(), 16) > DIFFICULTY):
      nonce = Random.new().read(AES.block_size).hex()
   pow = hashlib.sha256(json.dumps(utx, sort_keys=True).encode('utf8') + nonce.encode('utf-8')).hexdigest()
   
   return pow, nonce


#Creating a signature ------------------------------------------------------------------------------------------
def create_sig(sk, utx):
    sig = sk.sign(json.dumps(utx['input'], sort_keys=True).encode('utf8')).hex()
    return sig

# vk is the public key
# n = output number ( 0 1, 2)
#Verifying a signature
def verify_sig(pub_key, tx):
    vk = VerifyingKey.from_string(bytes.fromhex(pub_key))
    assert vk.verify(bytes.fromhex(tx['sig']),
    json.dumps(tx['input'], sort_keys=True).encode('utf8'))
#ed3ff
#337b5ac2bbf8749ce277db78d6057d3fe817d31396039901ff141c4159279bcb531d39b1d6bb664fced3b2bbd36d1d8d

# create a transaction, create a block 
# unverified valid/ unvalid transaction and submit to network -----------------------------------------------------
def create_utx(sk, blockchain, client, vk):
    block_id = input("Spend from which block: ")
    utx = []

    # Search the blockchain for the block the user is refering to
    for block in blockchain:
        if block["id"] == block_id:
            utx = block["tx"]
            break
    
    # Print the output of that block
    for i in range(len(utx["output"])):
        print(f'{i} : {utx["output"][i]}')

    output_number = int(input("Which output: "))
    amount_of_coin = int(input("How many coins: "))
    remainder = int(utx["output"][int(output_number)]["value"]) - amount_of_coin
    target_address = input("To which address: ")

    # current utx is the utx of the block we are referencing (Do we need to sign that utx or our own utx we make) $$
    print("Transaction to submit: ")
    my_utx = {'type': TRANSACTION,
    'input': {
        'id': block_id,
        'n': output_number
        }}
    new_utx = utx_format(block_id, output_number, create_sig(sk, my_utx), amount_of_coin, target_address)
    print(new_utx)

    # Submit utx to the network
    while True:
        option = input("Send transaction? (y/N): ")
        if option == "y":
            client.send_to_nodes(new_utx)
            print("Success!")
            return
        elif option == "N":
            # send one to self
            break
        else:
            continue
    
    # Option for Second transaction but only to self
    while True:
        option = input("Would you like to send the remaining to yourself? (y/N): ")
        if option == "y":
            new_utx["output"].append({"value": remainder, "pub_key": vk})
            client.send_to_nodes(new_utx)
            print("Success!")
            return output_number
        elif option == "N":
            # send one to self
            break
        else:
            continue
    
    
    

# mine unverified transactions into a block and submit them to the network
# to be validated and added to the blockchain -------------------------------------------------
def create_block(client, vk):
    option = -1

    # Ask user for which utx
    while True:
        option = int(input("Which transaction (-1 to see transcation range): "))
        if option > (len(client.utx) - 1) or option < 0:
            print(f"Must be a number between 0 and {len(client.utx) - 1}")
        else:
            break
    
    # Add coinbase to the end of output (we are not updating the utx pool value but using a temper)
    print("Adding coinbase transaction...")
    utx_target = client.utx[option]
    utx_target["output"] = utx_target["output"] + [{"value": COINBASE, "pub_key": vk}]
    new_utx = utx_target
    print(new_utx)

    mine_option = -1
    while True:
        mine_option = input("Mine this transaction? (y/N): ")
        if mine_option == "y":
            print("Mining...")
            break
        elif mine_option == "N":
            return
        
    block_id = -1
    pub_key = -1
    n = new_utx["input"]["n"]
    b_l = -1
    for block in client.blockchain:
        if block["id"] == new_utx["input"]["id"]:
            b_l = block
            pub_key = block["tx"]["output"][n]["pub_key"]
            break

    # current block_id is made from the block we are referencing (Do we need to make from the block we are making ) $$
    new_block = block_format("", "", "", client.blockchain[len(client.blockchain) - 1]["id"], new_utx)
    block_id = block_identifier(new_block)
    #print(block_id)
    
    # mine transaction
    verify_sig(pub_key, new_utx)
    pow, nonce = mine_transaction(new_utx)
    #print("heh")
    
    # Create new block
    new_block = block_format(block_id, nonce, pow, client.blockchain[len(client.blockchain) - 1]["id"], new_utx)
    print(new_block)
    
    # Submit block to the newtwork
    while True:
        option_b = input("Submit this block? (y/N):")
        if option_b == "y":
            client.send_to_nodes(new_block)
            print("Success!")
            return
        elif option_b == "N":
            return
        else:
            continue

# validate blocks and add them to the blockchain ------------------------------------------
def verify_block(block, zc_blocks, utx_pool):
    #  The block contains all required fields
    if list(block.keys()) != ['type', 'id', 'nonce', 'pow', 'prev', 'tx']:
        raise Exception("Block does not contain all fields")
    # The type field is the value BLOCK
    if block["type"] != BLOCK:
        raise Exception("Type is not BLOCK")
    # The block ID has been computed correctly
    #----already did it in create_block------
    '''try:
        block_identifier(block)
    except:
        raise Exception("Incorrect computation of block_id")'''
    # The prev field stores the block ID of the preceding block on the blockchain 
    if block["prev"] != zc_blocks[len(zc_blocks) - 1]["id"]:
        raise Exception("Prev value does not match id of previous block")
    # The proof-of-work validates and is less than the DIFFICULTY value
    #----already did it in create_block------
    '''try:
        mine_transaction(block["tx"])
    except:
        raise Exception("Invalid proof-of-work or Difficulty is greater than expected value")'''

    # The transaction contains all required fields
    if list(block["tx"].keys()) != ['type', 'input', 'sig', 'output']:
        raise Exception("Transaction does not contain all fields")
    # The type field is set to the value TRANSACTION
    if block["tx"]["type"] != TRANSACTION:
         raise Exception("Type is not TRANSACTION")
    # The transaction input refers to a valid block and output
    valid = False
    for bl in zc_blocks:
        if block["tx"]["input"]["id"]  == bl["id"]:
            valid = True
    
    if valid == False:
        raise Exception("Transcation input does not refer to a valid block")
    
    total_output = 0
    for value in block["tx"]["output"][:len(block["tx"]["output"]) - 1]:
        if list(value.keys()) != ["value", "pub_key"]:
            raise Exception("Incorrect outputs pattern")
        total_output += value["value"]

    if len(block["tx"]["output"]) < 2 or len(block["tx"]["output"]) > 3:
        raise Exception("More than three outputs or no outputes detected")
    # The input is unspent (i.e. there is no other valid transaction referring to the same output currently in the blockchain)
    for i in zc_blocks:
        if block["tx"]["input"]["id"] == i["tx"]["input"]["id"] and block["tx"]["input"]["n"] == i["tx"]["input"]["n"]:
            raise Exception("There already exists a transcation that referes the same output")

    # The value of the input equals the sum of the outputs (not including the coinbase output).
    target_pub = -1
    for i in zc_blocks:
        if i["id"] == block["tx"]["input"]["id"]:
            if i["tx"]["output"][int(block["tx"]["input"]["n"])]["value"] != total_output:
                raise Exception("Value of the input does not equal the sum of the outputs")
            target_pub = i["tx"]["output"][int(block["tx"]["input"]["n"])]["pub_key"]
    # The coinbase output is correct (in value)
    if  block["tx"]["output"][len(block["tx"]["output"]) - 1]["value"] != COINBASE:
        raise Exception("Wrong coinbase")
    
    # the public key in our new block or the public key in the block we are referencing $$
    # That the signature of the transaction verifies
    '''try:
        print(target_pub, block["tx"]["output"][0]["pub_key"])
        verify_sig(target_pub, block["tx"])
    except:
        raise Exception("Signature of the transaction not verified")'''

    return True

# ------------------------------------------------------------------------------------------------------------
# ------------------------------------------------------------------------------------------------------------
def main():

    if len(sys.argv) < 3:
        print("Usage: python3", sys.argv[0], "CLIENTNAME PORT")
        quit()

    #Load keys, or create them if they do not yet exist
    keypath = './' + sys.argv[1] + '.key'
    if not os.path.exists(keypath):
        sk = SigningKey.generate()
        vk = sk.verifying_key
        with open(keypath, 'w') as f:
            f.write(sk.to_string().hex())
            f.close()
    else:
        with open(keypath) as f:
            try:
                sk = SigningKey.from_string(bytes.fromhex(f.read()))
                vk = sk.verifying_key
            except Exception as e:
                print("Couldn't read key file", e)

    #Create a client object
    client = ZachCoinClient("127.0.0.1", int(sys.argv[2]), sys.argv[1])
    client.debug = False

    time.sleep(1)

    client.start()

    time.sleep(1)

    #Connect to server 
    client.connect_with_node(SERVER_ADDR, SERVER_PORT)
    print("Starting ZachCoin™ Client:", sys.argv[1])
    time.sleep(2)
    
    while True:
        os.system('cls' if os.name=='nt' else 'clear')
        slogan = " You can't spell \"It's a Ponzi scheme!\" without \"ZachCoin\" "
        print("=" * (int(len(slogan)/2) - int(len(' ZachCoin™')/2)), 'ZachCoin™', "=" * (int(len(slogan)/2) - int(len('ZachCoin™ ')/2)))
        print(slogan)
        print("=" * len(slogan),'\n')
        x = input("\t0: Print keys\n\t1: Print blockchain\n\t2: Print UTX pool\n\t3: Create Transaction\n\t4: Mine Transaction\n\nEnter your choice -> ")
        try:
            x = int(x)
        except:
            print("Error: Invalid menu option.")
            input()
            continue
        if x == 0:
            print("sk: ", sk.to_string().hex())
            print("vk: ", vk.to_string().hex())
        elif x == 1:
            print(json.dumps(client.blockchain, indent=1))
        elif x == 2:
            print(json.dumps(client.utx, indent=1))
        # TODO: Add options for creating and mining transactions
        # as well as any other additional features
        elif x == 3:
            try:
               create_utx(sk, client.blockchain, client, vk.to_string().hex())
            except:
                raise Exception("Something is wrong with creating transactions")
        elif x == 4:
            try:
               create_block(client, vk.to_string().hex())
            except:
                raise Exception("Something is wrong with minining")
        input()
        
if __name__ == "__main__":
    main()