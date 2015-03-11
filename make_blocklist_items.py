import sys
from base64 import b64encode, b64decode
from binascii import unhexlify

from pyasn1.codec.der import encoder, decoder
from pyasn1_modules import rfc2459

asn1Spec = rfc2459.Extension()
crlType = rfc2459.CertificateList()

"""
Get a byte array for an ASN1 integer
"""
def getASNIntegerBytes(asnInt):
    hexstr = "%X" % (int(asnInt))
    if len(hexstr) % 2 == 1:
        return unhexlify('0'+hexstr)
    return unhexlify(hexstr)

"""
Get the information on revocation. Returns a tuple of the issuer (name) and a
list of revoked serials
"""
def getRevocationInfo(crl):
    serials = []
    name = None
    if None != crl[0]['tbsCertList'] and None != crl[0]['tbsCertList']['revokedCertificates']:
        name = b64encode(encoder.encode(crl[0]['tbsCertList']['issuer']))
        for cert in crl[0]['tbsCertList']['revokedCertificates']:
            serials.append(b64encode(getASNIntegerBytes(cert['userCertificate'])))
    return name, serials

certItemsTemplate = "<certItems>\n%s\n</certItems>"
certItemTemplate = "\t<certItem issuerName=\"%s\">\n%s\n\t</certItem>"
serialTemplate = "\t\t<serialNumber>%s</serialNumber>"

if __name__ == "__main__":
    total = 0
    issuers = []
    for arg in sys.argv[1:]:
        try:
            f = open(arg,'r')
            data = f.read()
            f.close()
            stuff = decoder.decode(data,asn1Spec=crlType)
            name, serials = getRevocationInfo(stuff)
            if None != name:
                issuers.append((name, serials))
                total = total + len(serials)
        except:
            print 'there was a problem with',arg
    print certItemsTemplate % ("\n".join([certItemTemplate % (name, "\n".join([serialTemplate  % (serial) for serial in serials])) for name, serials in issuers]))
    #for issuer, serials in issuers:
    #    print issuer
    #    for serial in serials:
    #        print ' '+serial
