from kidsfreecoin.Node import Miner
import threading,random
alpha = "abcdefghijklmnopqrstuvwxyz"



def mine():

    name = b''.join([random.choice(alpha).encode() for i in range(32)])
    m = Miner(b"c"*32)
    print(m.public_key.to_string())
    m.mine()
    # for i in range(10):
    #     m.mine()

# for i in range(10):
#     threading.Thread(target=mine).start()
mine()