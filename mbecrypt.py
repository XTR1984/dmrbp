# test encrypting for decrypt
from dmrbp import *
import sys
import random

KEYLEN = 128
loadmbe("samples/output.amb")
samples2bits()
key = []
for i in range(0,KEYLEN):
    key.append(random.randint(0,1))
print("key=",bitlist2str(key))
ks = makekeystream(key)
print("keylen= ", len(key))
print("kslen= ", len(ks))
crypt(ks)
savembe("samples/crypted/crypted.amb");