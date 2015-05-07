from fetch_all import fetchCRL, parseCRL, getRevokedSerials
import sys

crlURI = sys.argv[1]
print crlURI
issuer, serials = getRevokedSerials(parseCRL(fetchCRL(crlURI)))
print issuer
for serial in serials:
    print serial
