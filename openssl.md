openssl

## read crt file(x509)

`openssl x509 -in a.crt -text`


## generate CA private key

`openssl genrsa -des3 -out private.key 2048`

Generate rsa key of 2048 bit Using DES3 cipher for the key generation

## Create CA Certificate

`openssl req -new -x509 -days 3650 -key private.key -out certificate.crt`

* req: Certificate request and certification utility.
* -new: Generate a new certificate. It will prompt the user for several input fields.
* -x509: Create a self-signed certificate.
* -days: Specify the number of days the certificate is valid.
* -key: Key file with the private key to be used for signing.
* -out: Specifies the file name for the certificate (.crt).

## encrypt using any algo(aes,rsa,des)

`openssl enc -aes-256-cbc -salt -in file.txt -out file.enc`


## decrypt using any algo(aes,rsa,des)

`openssl enc -aes-256-cbc -d -in file.enc -out file.txt`


# General OpenSSL Commands

## Generate a new private key and Certificate Signing Request

`openssl req -out CSR.csr -new -newkey rsa:2048 -nodes -keyout privateKey.key`

## Generate a self-signed certificate
`openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout privateKey.key -out certificate.crt`

## Generate a certificate signing request (CSR) for an existing private key
`openssl req -out CSR.csr -key privateKey.key -new`

## Generate a certificate signing request based on an existing certificate






















