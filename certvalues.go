package main

import (
  "crypto/sha256"
  "crypto/x509"
  "encoding/asn1"
  "encoding/base64"
  "encoding/pem"
  "flag"
  "fmt"
  "io/ioutil"
)

func check(e error) {
  if e != nil {
    panic(e)
  }
}

func main() {
  certPtr := flag.String("cert", "", "a certificate file")
  flag.Parse()

  var certData []byte
  if nil != certPtr && len(*certPtr) > 0 {
    // Get the cert from the args
    var err error
    certData, err = ioutil.ReadFile(*certPtr)
    check(err)
  }

  if len(certData) > 0{
    // Maybe it's PEM; try to parse as PEM, if that fails, just use the bytes
    block, _ := pem.Decode(certData)
    if block != nil {
      certData = block.Bytes
    }

    cert, err := x509.ParseCertificate(certData)
    if err != nil {
      panic("could not parse cert")
    }


    issuerString := base64.StdEncoding.EncodeToString(cert.RawIssuer)
    fmt.Printf("issuer: %v\n", issuerString)

    marshalled, err := asn1.Marshal(cert.SerialNumber)

    if err == nil {
      serialString := base64.StdEncoding.EncodeToString(marshalled[2:])
      fmt.Printf("serial: %v\n", serialString)
    }

    subjectString := base64.StdEncoding.EncodeToString(cert.RawSubject)
    fmt.Printf("subject: %v\n", subjectString)

    pubKeyData, err := x509.MarshalPKIXPublicKey(cert.PublicKey)

    if err == nil {
      hash := sha256.Sum256(pubKeyData)
      base64EncodedHash := base64.StdEncoding.EncodeToString(hash[:])
      fmt.Printf("pubKeyHash: %v\n", base64EncodedHash)
    }
  }
}
