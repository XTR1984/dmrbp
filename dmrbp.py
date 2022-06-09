# disclaimer: this script maked for simple cryptography educational purposes only, 
# do not use it for evil! make world more secure!
import os
import sys

SUPERN = 6
FRAMEN = 3 
SAMPLESIZE = 49
FRAMESIZE= SAMPLESIZE*FRAMEN
SILENCECODE = 124
MINKEYSIZE = 10
MAXKEYSIZE = 256

#some global variables, ups
superarray  = []
mbesamples = []

## procedures for converting mbe file from bytes to bitstring and back
def byte2bits(b):
    res = []
    res.append(b >> 7 & 1 )
    res.append(b >> 6 & 1 )
    res.append(b >> 5 & 1 )
    res.append(b >> 4 & 1 )
    res.append(b >> 3 & 1 )
    res.append(b >> 2 & 1 )
    res.append(b >> 1 & 1 )
    res.append(b & 1 )
    return(res)

def bits2byte(bits):
    b = 0
    for i in range(0,7):
        b |= bits[i]
        b = b << 1
    b |= bits[7]
    return b

def sample2bits(s):
    res = []
    for i in range(0,6):
        res += byte2bits(s[i])
    if s[6] == 1:
        res += [1]
    else: res += [0]
    return res

def bits2sample(bits):
    res = []
    for i in range(0,SAMPLESIZE-1,8):
        res.append(bits2byte(bits[i:i+8]))
    res.append(bits[SAMPLESIZE-1])
    return res

def bits2samples():
    mbe = []
    for i in range(0, len(superarray)):
        for j in range(0, SUPERN*FRAMEN):
            sbits = superarray[i]["cryptotext"][j*SAMPLESIZE:j*SAMPLESIZE+SAMPLESIZE]
            mbe.append(bits2sample(sbits))
    return mbe

def samples2bits():
    k = 0
    for i in range(0,len(mbesamples), SUPERN*FRAMEN):
        item = {}
        item["cryptotext"]= []
        for j in range(0,SUPERN*FRAMEN):
            item["cryptotext"] += sample2bits(mbesamples[i+j])
        superarray.append(item)    
    #print(superarray[0]["seq"])        
    print("loaded superframes: ",len(superarray))

# loading and saving 
def loadmbe(fname):
    f = open(fname,"rb")
    ba = f.read()
    for i in range(4,len(ba)-7,8):
        mbesamples.append(ba[i+1:i+8])

def loadmbedir(rootdir):
    for subdir, dirs, files in os.walk(rootdir):
        for file in files:
            #print( os.path.join(subdir, file))
            filepath = subdir + os.sep + file
            if filepath.endswith(".amb"):
                loadmbe(filepath)
    print("loaded samples: ", len(mbesamples))

def savembe(fname):
    assert ".amb" in fname
    f = open(fname, "wb")
    f.write(bytearray(".amb",encoding="ascii"))
    mbe = bits2samples()
    for m in mbe:
        f.write(b'\0')
        f.write(bytearray(m))
    f.close()


##### key searching and decrypting #####
def makekeystream(key):
    factor = (SUPERN * FRAMESIZE) // len(key) + 1
    keystream = key * factor
    return keystream

def xorseq(seq, keystream):
    res =  []
    for i in range(0, len(seq)):
        res.append(seq[i] ^ keystream[i])
    return res

def crypt(ks):
    for t in superarray:
        t["cryptotext"] = xorseq(t["cryptotext"], ks)
 
def bitlist2str(l):
    return "".join(map(lambda x: str(x), l))

def getb0(seq):
    b0 = []
    b0.append(seq[0])
    b0.append(seq[1])
    b0.append(seq[2])
    b0.append(seq[3])
    b0.append(seq[37])
    b0.append(seq[38])
    b0.append(seq[39])
    b0 = int(bitlist2str(b0), 2)
    return b0

# get statistics
def stat1(xr=0, printflag=False, graph=False, j=0):
    statdict = {}
    for i in range(0,255):
        statdict[i] = 0
    for i in range(0, len(superarray)):
        #for j in range(0,SUPERN*FRAMEN):
            text = superarray[i]["cryptotext"][j*SAMPLESIZE:j*SAMPLESIZE+SAMPLESIZE]
            statitem = getb0(text)
            if statitem==0: continue
            statitem = statitem ^ xr
            if statitem in statdict:
                statdict[statitem] +=1 
            else:
                statdict[statitem] = 1
    max = 0
    maxkey = 0
    for key in sorted(statdict.keys()):
        if printflag:
            print(f'{key} ={statdict[key]}')
        if statdict[key] > max:
            max = statdict[key]
            maxkey = key
    if graph:
        import numpy as np
        import matplotlib.pyplot as plt
        fig = plt.figure()
        axes = fig.subplots(1,1)
        x = np.array(list(statdict.keys()))
        y = np.array(list(statdict.values()))
        axes.plot(x,y)
        plt.show()

    return maxkey

# get keystream parts
def statsearch():
    res = []
    for j in range(0,SUPERN*FRAMEN):
        maxkey = stat1(xr=0,j=j)
        ks = maxkey ^ SILENCECODE
        res.append(ks)
        #print(f"j={j},ks={ks}")
    return res

def dumparray(fname):
    f = open(fname, "w")
    for t in superarray:
        k = 0
        for i in t["cryptotext"]:
            if k%SAMPLESIZE==0:
                f.write("-")
            f.write(str(i))
            k+=1
        f.write("\n")
    f.close()                

## set 
def setkeystreamX_B0(ks,b0,j):
    ks[0  +SAMPLESIZE*j]  = (b0 >> 6) & 1
    ks[1  +SAMPLESIZE*j]  = (b0 >> 5) & 1
    ks[2  +SAMPLESIZE*j]  = (b0 >> 4) & 1
    ks[3  +SAMPLESIZE*j]  = (b0 >> 3) & 1
    ks[37 +SAMPLESIZE*j]  = (b0 >> 2) & 1
    ks[38 +SAMPLESIZE*j]  = (b0 >> 1) & 1
    ks[39 +SAMPLESIZE*j]  = b0 & 1

#### guessing key len
def guesskeylen(xks):
    maxres = 0
    maxres_i = 0
    for i in range(MINKEYSIZE, MAXKEYSIZE):
        breakflag = False
        res = 0
        kchunks = len(xks) // i
        for k in range(0,i):
            firstfixed=None
            for j in range(0,kchunks):
              bit = xks[j*i+k]
              if bit!='x':
                  if not firstfixed:
                     firstfixed = bit
                  else:
                     if bit == firstfixed:
                        res+=1
                     else:
                        res = 0 
                        breakflag = True
                        break
            if breakflag:
                break
        if res > maxres:
            maxres = res
            maxres_i = i
    return maxres_i

def printchunks(ksx,keylen):
    for k in range(0,len(ksx),keylen):
        print(bitlist2str(ksx[k:k+keylen]))

def assemblekey(xks,keylen):
    key = ['x'] * keylen
    kchunks = len(xks) // keylen
    for k in range(0,keylen):
        for j in range(0,kchunks):
           bit = xks[j*keylen+k]
#           print(bit)
           if bit!='x':
               key[k] = bit
               break
    return key            

def main():
    print(" DMR Basic privacy decrypt tool v1.0")
    if len(sys.argv)<2:
        print(" using:")
        print(" # python dmrbp.py <subdir> [<outputname>] ")
        print("    <subdir> - name of subdirectory in working directory with .amb files collection ")
        print("    <outputname> - output .amb name, no name - no decryption ")
        exit()
    if not os.path.isdir("./" + sys.argv[1]):
        print("Ups, bad directory!")
        exit();
    print("Loading data from " + sys.argv[1])
    loadmbedir(sys.argv[1])
    samples2bits()
#    if len(superarray) < 100:
#        print("Sorry, need more samples for good statistics")
#        exit()

    print("Calculating...")
    res= statsearch()
    ksx = ["x"]*SUPERN*FRAMEN*SAMPLESIZE
    for j in range(0,SUPERN*FRAMEN):
        setkeystreamX_B0(ksx,res[j],j)

    ksxstr = bitlist2str(ksx)
    print("keystreamX=",ksxstr)

    keylen = guesskeylen(ksx)
    print("guess key length is: ", keylen)            
    printchunks(ksx,keylen)
    key = assemblekey(ksx, keylen)
    print("guess key is: ", bitlist2str(key)) 
    if len(sys.argv)==3:
        key = [x if x!='x' else 0 for x in key]
        print("decrypting with key: " + bitlist2str(key))
        ks = makekeystream(key)   
        crypt(ks)
        print("saving to " + sys.argv[2] + ".amb")
        savembe(sys.argv[2]+".amb")

if __name__ == '__main__':
    main()