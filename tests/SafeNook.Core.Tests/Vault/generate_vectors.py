"""Synthetic public test data only. Never use these keys/nonces outside tests.
Run with cryptography==46.0.3, argon2-cffi==25.1.0; see SN-003A-IMPLEMENTATION.md.
Independent of .NET, NSec and libsodium: OpenSSL AES/HKDF and reference Argon2 C bindings.
"""
import base64, hashlib, hmac, struct, uuid
from pathlib import Path
from importlib.metadata import version
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends.openssl.backend import backend
D=lambda s: b'SafeNook/v1/'+s.encode()+b'\0'
K=lambda k,s,i: HKDF(algorithm=hashes.SHA256(),length=32,salt=s,info=i).derive(k)
vid=uuid.UUID('00112233-4455-4677-8899-aabbccddeeff').bytes
eid=uuid.UUID('10213243-5465-4768-89ab-bcdef0123456').bytes
gid=uuid.UUID('20314253-6475-4869-9abc-cdef01234567').bytes
pid=uuid.UUID('30415263-7485-496a-abcd-def012345678').bytes
rid=uuid.UUID('40516273-8495-4a6b-bcde-ef0123456789').bytes
vk=bytes(range(32)); rk=bytes(range(32,64)); pwd=b'SN003A synthetic password'
write=bytes(range(64,96)); nonce=bytes(range(96,108)); plain=b'Synthetic blob\x00\xff'
e=b'SNOBJ001'+struct.pack('<HBB',1,2,0)+vid+eid+gid+write+struct.pack('<HHHQ',0,1,1,len(plain))+nonce
objectkey=K(vk,vid,D('object-key')+e[:106]); objectaad=D('object')+e
file=e+AESGCM(objectkey).encrypt(nonce,plain,objectaad)
seed=hash_secret_raw(pwd,bytes(range(16)),3,65536,1,32,Type.ID,19)
def slot(sid,kind,salt,nonce):
    pre=sid+struct.pack('<BBHIII',kind,1 if kind==1 else 0,1,65536 if kind==1 else 0,3 if kind==1 else 0,1 if kind==1 else 0)+salt+nonce
    kek=K(seed,vid,D('password-wrap')+eid+sid) if kind==1 else K(rk,salt,D('recovery-wrap')+vid+eid+sid)
    aad=D('slot')+struct.pack('<H',1)+vid+eid+pre
    return pre+AESGCM(kek).encrypt(nonce,vk,aad),kek,aad
ps,pk,pa=slot(pid,1,bytes(range(16)),bytes(range(16,28)))
rs,rkey,ra=slot(rid,2,bytes(range(128,144)),bytes(range(144,156)))
prefix=b'SNVLT001'+struct.pack('<HH',1,0)+vid+eid+gid+struct.pack('<Q',1)+bytes(32)+write+hashlib.sha256(file).digest()+struct.pack('<H',2)
headkey=K(vk,vid,D('header-mac')+eid); header=prefix+ps+rs
mac=hmac.digest(headkey,D('header')+header,'sha256'); header+=mac
symbols=base64.b32encode(rk).decode().rstrip('=')+base64.b32encode(hashlib.sha256(D('recovery-check')+rk).digest()[:5]).decode()
code='SN1-'+'-'.join(symbols[i:i+5] for i in range(0,60,5))
values=dict(VaultId=vid,EpochId=eid,GenerationId=gid,PasswordSlotId=pid,RecoverySlotId=rid,VaultKey=vk,RecoveryKey=rk,Password=pwd,WriteId=write,Nonce=nonce,Plaintext=plain,Envelope=e,ObjectKey=objectkey,ObjectAad=objectaad,File=file,Hash=hashlib.sha256(file).digest(),ArgonSeed=seed,PasswordSlot=ps,PasswordKek=pk,PasswordAad=pa,RecoverySlot=rs,RecoveryKek=rkey,RecoveryAad=ra,Prefix=prefix,HeaderKey=headkey,Mac=mac,Header=header,
ArgonSeed2=hash_secret_raw(b'\xc3\xa9\x00test',bytes(range(255,239,-1)),4,65536,1,32,Type.ID,19))
assert len(header)==414 and len(e)==118 and len(prefix)==166 and len(ps)==108 and len(code)==75
out=['// Generated independent public synthetic vectors; see generate_vectors.py.','namespace SafeNook.TestVectors;','internal static class Vectors','{']
for name,value in values.items(): out.append(f'    public const string {name} = "{value.hex()}";')
out.append(f'    public const string RecoveryText = "{code}";');out.append('}')
Path(__file__).with_name('Vectors.g.cs').write_text('\n'.join(out)+'\n',encoding='utf-8', newline='\n')
print({p:version(p) for p in ['cryptography','argon2-cffi','argon2-cffi-bindings','cffi','pycparser']})
print(backend.openssl_version_text()); print('Generated deterministic public fixtures.')
