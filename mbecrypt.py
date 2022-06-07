# test encrypting for decrypt
from dmrbp import *
import sys


loadmbe("samples/input.amb")
samples2bits()
key =[0,1,0,1,1,1,1,1,1]
print("key=",bitlist2str(key))
ks = makekeystream(key)
print("keylen= ", len(key))
print("kslen= ", len(ks))
crypt(ks)
savembe("samples/crypted/crypted.amb");