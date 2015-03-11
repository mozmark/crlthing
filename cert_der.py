import sys
from pyasn1_modules import pem, rfc2459
from pyasn1.codec.der import decoder, encoder

from base64 import b64encode, b64decode

substrate = pem.readPemFromFile(open(sys.argv[1]))
encoded = ''
lines = open(sys.argv[1],'r').readlines()
for line in lines:
    if -1 == line.find('-'):
        encoded = encoded + line.strip()
#substrate = open(sys.argv[1],'r').read()
substrate = b64decode(encoded)
cert = decoder.decode(substrate, asn1Spec=rfc2459.Certificate())[0]
#print(cert.prettyPrint())

print("raw issuer is"+cert[0][5].prettyPrint())

print("issuer is: "+b64encode(encoder.encode(cert[0][3])))
print("serial is "+b64encode(encoder.encode(cert[0][1])[2:]));
for i in encoder.encode(cert[0][1])[2:]:
    print("%x"%(ord(i)))
