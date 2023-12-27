# Features

## ECC/RSA

- ECIES: envelop encryption/decryption using ecc keypair
- RSA Envelope Encryption and decryption
- KeyGen: generate ecc keypair, return in PEM format, comply with PKCS 8( Private Key ), and PKIX (Public Key), or RSA in PKCS 1 encoding
- convertion bettween DER and PEM, s
- Signing/Verifing
- NIST P256/384/521
- ...

## AES

- WRAP cipher suite(CBC / GCM ...), return self defined CMS pack

## X509

- Working in progress

## ECIES Tool

- 提供使用 ECC 证书和公钥加密数据的能力，YEAH，very cool
- example/ecnrypt-argv 支持使用ECC的明文pem公钥加密数据，并在信封中携带指定的数据
