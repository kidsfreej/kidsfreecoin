import ecdsa,hashlib
import requests,threading,flask
import json
import random
from flask import jsonify,Flask,request
import base64

def get(d,v):
    if v not in d:
        return 0
    return d[v]
def pluse(d,v,s):
    if v not in d:
        d[v] = s
    else:
        d[v] +=s
def hash_tx(tx):
    data = tx["input"] + " " + tx["output"] + " " + tx["amount"] + " " + tx[
        "fee"]+" "+tx["signature"]
    return hashlib.sha256(data.encode()).hexdigest()
def hash_block(b):

    """
    all data stypes are bytes
    {"miner":base64,"difficulty":base10,"nonce":nomatter,"transactions","prev_hash":base10,"hash":base10}
    """

    d = b["prev_hash"]+" "+b["nonce"]+" "+b['difficulty']+" "+b["miner"]
    for tx in b["transactions"]:
        d+=hash_tx(tx)
    return int(hashlib.sha256(d.encode()).hexdigest(),base=16)

class Miner:
    def __init__(self,private_key):
        self.private_key = ecdsa.SigningKey.from_string(private_key,curve=ecdsa.SECP256k1,hashfunc=hashlib.sha256)
        self.public_key= self.private_key.get_verifying_key()
        self.maxh = 2**256
        self.block_probability = 10000
        self.nodes = ["http://localhost:7070"]
        self.difficulty = (self.maxh//self.block_probability)
        self.transaction_count = 0
    # def create_transaction(self,out,amount):
    #     d = {"output":out,"amount":amount,"input":base64.b64encode(self.public_key.to_string())}
    #     data = d["input"] + " " + ["output"] + " " +d["amount"]
    #
    #
    #     d["signature"] = base64.b64encode(self.private_key.sign(data,hashfunc=hashlib.sha256)).decode("utf8")
    #     return d
    def create_tx(self,output,amount,fee):
        tx = {"input":base64.b64encode(self.public_key.to_string()).decode("utf8"),"output":output,"amount":amount,"fee":str(fee)}
        data = tx["input"] + " " + tx["output"] + " " + tx["amount"] +" "+ tx['fee']
        tx["signature"] = base64.b64encode(self.private_key.sign(data.encode(), hashfunc=hashlib.sha256)).decode("utf8")

        self.public_key.verify(base64.b64decode(tx["signature"]),data.encode())
        return tx
    def send_money(self,output,amount,fee):
        # {"input": base64, "output": bas64, "amount": stringint, "signature": base64, "fee": stringint}
        # formula
        # for hash is:
        #     sha256(input + " " + output + " " + amount)
        tx = self.create_tx(output,amount,fee)
        choicenode = random.choice(self.nodes)
        print("initalized")
        requests.post(choicenode+"/addtx",data={"data":json.dumps(tx)})
        print("adsasdasd")
        return tx
    def mine(self):
        choicenode = random.choice(self.nodes)
        txnode = random.choice(self.nodes)
        txs = json.loads(requests.get(txnode+"/gettoptxs").content.decode())
        validated_txs = []
        # WORK HERE
        for tx in txs:
            if Blockchain.validate_transaction(tx):
                validated_txs.append(tx)
        gotten = requests.get(choicenode+"/latesthash").content.decode("utf8")
        b = {"miner":base64.b64encode(self.public_key.to_string()).decode("utf8"),"difficulty":str(self.difficulty),"transactions":validated_txs,"nonce":0,"prev_hash":gotten}
        nonce =1
        while True:
            if nonce%1000000==0:
                b["prev_hash"] = requests.get(choicenode+"/latesthash").content.decode("utf8")

            b["nonce"] = str(nonce)
            if hash_block(b)<=self.difficulty:
                break

            nonce+=1

        requests.post(choicenode+"/addblock",data={'data':json.dumps(b)})

        return b

class Blockchain:
    def __init__(self):
        self.maxh = 2**256
        self.block_probability = 10000
        self.difficulty = (self.maxh//self.block_probability)
        self.blocks = []
        self.wallets = {}
        self.nodes = ["http://localhost:7070"]
        self.transaction_hashes = {}
        self.mempool_hashes ={}
        self.mempool = []
    def request_add_block(self,block):
        bhash= hash_block(block)
        if bhash > self.difficulty:
            return "a"
        if block["difficulty"]!=str(self.difficulty):
            return "b"


        if len(self.blocks)!=0 and str(hash_block(self.blocks[-1]))!=block["prev_hash"]:
            return "d"
        self.accept_transactions(block["transactions"],block)

        pluse(self.wallets,block["miner"],100)
        self.blocks.append(block)
        return True
    def accept_transactions(self,transactions,block):
        '''
            strngs not bytes
            {"input":base64,"output":bas64,"amount":stringint,"signature":base64,"fee":stringint}
            formula for hash is:
            sha256(input+" "+output+" "+amount)
        '''
        miner = block["miner"]
        changes = {miner:0}
        new_tx = []
        transaction_hash_changes= {}
        for transaction in transactions:
            if get(self.wallets,transaction['input']) <\
                    int(transaction['amount']):

                print("not enough")
                continue
            if int(transaction["amount"]) <= 0:
                raise Exception("illegal amount")
            if int(transaction["fee"]) <= 0:
                raise Exception("illegal fee")
            data = transaction["input"]+" "+transaction["output"]+" "+transaction["amount"]+" "+transaction["fee"]
            vk = ecdsa.VerifyingKey.from_string(base64.b64decode(transaction["input"]), curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256)
            try:

                vk.verify(base64.b64decode(transaction["signature"]),data.encode(), hashfunc=hashlib.sha256)
            except:
                raise Exception("failed to verify")

            hashed = hashlib.sha256(data.encode()).hexdigest()
            if  hashed in self.transaction_hashes:
                raise Exception("double transaction")

            new_tx.append(transaction)
            pluse(changes,transaction["output"],int(transaction["amount"]))
            pluse(changes,transaction["input"],-int(transaction["amount"])-int(transaction["fee"]))
            changes[miner]+=int(transaction["fee"])
            transaction_hash_changes[hashed] = len(self.blocks)
        for wallet in changes:
            pluse(self.wallets,wallet,changes[wallet])
        for txh in transaction_hash_changes:
            self.transaction_hashes[txh] = transaction_hash_changes[txh]
        block["transactions"]= new_tx
        return False
    @staticmethod
    def validate_transactions(txs,miner):
        wallet_changes = {}
        for tx in txs:
            if not Blockchain.validate_transaction(tx):
                return False
            pluse(wallet_changes, tx["output"], int(tx["amount"]))
            pluse(wallet_changes, tx["input"], -int(tx["amount"]) - int(tx["fee"]))
            pluse(wallet_changes, miner, int(tx["amount"]))

    @staticmethod
    def validate_transaction(tx):
        data = tx["input"]+" "+tx["output"]+" "+tx["amount"]+" "+tx["fee"]
        if int(tx["amount"])<=0:
            return False
        if int(tx["fee"])<=0:
            return False
        vk = ecdsa.VerifyingKey.from_string(base64.b64decode(tx["input"]), curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256)
        try:
            vk.verify(base64.b64decode(tx["signature"]), data.encode(), hashfunc=hashlib.sha256)
        except:
            return False
        return True

    def resolve_conflicts(self):
        max_l = len(self.blocks)
        max_node = None
        for node in self.nodes:
            l =int(requests.get(node+"/length").content)
            if l > max_l:
                max_l = l
                max_node = node

        if max_node is not None:
            block_downloads = []
            i = 0
            prev_hash = None
            wallet_changes ={}
            transaction_hashes_changes = {}

            while i<max_l:
                raw = requests.get(max_node+f"/feblock?feblock={i}").content

                block = json.loads(raw)
                transactions = block["transactions"]
                block_downloads.append(block)

                for tx in transactions:
                    if Blockchain.validate_transaction(tx):
                        hashed = hash_tx(tx)
                        if hashed in transaction_hashes_changes:
                            continue
                        transaction_hashes_changes[hashed] = max_l-i-1
                        pluse(wallet_changes, tx["output"], int(tx["amount"]))
                        pluse(wallet_changes, tx["input"], -int(tx["amount"]) - int(tx["fee"]))
                        pluse(wallet_changes, block["miner"], int(tx["amount"]))

                if prev_hash is not None and (int(prev_hash) != hash_block(block) or int(prev_hash)>self.difficulty):
                    print("INVALID")
                    return

                if i>max_l-len(self.blocks)-1 and int(block["prev_hash"])==hash_block(self.blocks[max_l-i-1]):
                    break
                prev_hash = block["prev_hash"]
                i+=1
            for txh in transaction_hashes_changes:
                if txh in self.transaction_hashes and self.transaction_hashes[txh]< max_l-i:
                    return
            for change in wallet_changes:
                if get(self.wallets,change)<wallet_changes[change]:
                    return
            for change in wallet_changes:
                pluse(self.wallets,change,wallet_changes[change])
            stop = i
            for c,i in enumerate(range(max_l-stop,max_l)):

                if i< len(self.blocks):
                    for tx in self.blocks[i]["transactions"]:
                        hashed = hash_tx(tx)
                        self.transaction_hashes.pop(hashed)
                        self.mempool_hashes[hashed] = tx

                        self.blocks[i] =block_downloads[-c - 1]
                else:
                    self.blocks.append(block_downloads[-c-1])
            for tx in transaction_hashes_changes:
                self.transaction_hashes[tx]=transaction_hashes_changes[tx]
                hashed = hash_tx(tx)
                if hashed in self.mempool_hashes:
                    self.mempool_hashes.pop(hashed)
            self.mempool=sorted(list(self.mempool_hashes.values()),key=lambda x:int(x["fee"])+self.mempool)
bc = Blockchain()
app = Flask(__name__)
@app.route("/feblock",methods=["GET"])
def feblock():
    try:
        return jsonify(bc.blocks[-int(request.args["feblock"])-1]) ,200
    except:
        return "out of range", 400
@app.route("/length",methods=["GET"])
def length():
    return str(len(bc.blocks)),200
@app.route("/latesthash",methods=["GET"])
def latesthash():
    if len(bc.blocks)==0:
        return '0',200
    return str(hash_block(bc.blocks[-1])),200
@app.route("/check",methods=["GET"])
def check():
    print("asdasadas")
    bc.resolve_conflicts()
    return "ok lmao", 200
@app.route("/addblock",methods=["POST"])
def addblock():
    block = json.loads(dict(request.form)["data"])
    print("block:",block)
    bc.request_add_block(block)
    print("chain:",bc.blocks)
    print("wallets:",bc.wallets)
    return jsonify({}),200
@app.route("/addtx",methods=['POST'])
def addtx():
    tx = json.loads(dict(request.form)["data"])
    if int(tx["fee"])<3:
        return "too small of a fee, cheapskate",404
    hashed = hash_tx(tx)
    if hashed in bc.mempool_hashes:
        return "no repeats, idiot",405
    bc.mempool_hashes[hashed] = tx
    print(tx)
    bc.mempool = sorted(bc.mempool+[tx],key=lambda x:int(x["fee"]))
    return "ok lmbao",200
@app.route("/gettoptxs",methods=['GET'])
def gettxs():
    return json.dumps(bc.mempool[:(100 if len(bc.mempool)>100 else len(bc.mempool))]),200
if __name__ == "__main__":

    app.run("localhost",int(input()),threaded=True)

