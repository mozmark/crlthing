import sys
from pyasn1_modules import pem, rfc2459
from pyasn1.codec.der import decoder, encoder

from base64 import b64encode, b64decode
from binascii import unhexlify
import hashlib

"""
Get a byte array for an ASN1 integer
"""
def getASNIntegerBytes(asnInt):
    hexstr = "%X" % (int(asnInt))
    if len(hexstr) % 2 == 1:
        return unhexlify('0'+hexstr)
    return unhexlify(hexstr)

substrate = open(sys.argv[1],'r').read()
cert = decoder.decode(substrate, asn1Spec=rfc2459.Certificate())[0]
#print(cert.prettyPrint())
print("blocklist info for issuer / serial:");
print("issuer is: "+b64encode(encoder.encode(cert[0][3])))
print("serial is: "+b64encode(getASNIntegerBytes(cert[0][1])));
print("blocklist info for subject / pubKey:");
print("subject is: "+b64encode(encoder.encode(cert[0][5])))
key = encoder.encode(cert[0][6][1])
# print("key is: "+b64encode(key));
hasher = hashlib.new("sha256")
hasher.update(key)
hashed = hasher.digest()
print("key hash is (actually, don't trust this...): "+b64encode(hashed));
