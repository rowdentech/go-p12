# go-p12

This project provides a cli tool for creating `.p12` (`PKCS12`) format files. These normally contain a private key and at least one certificate, and are used to set up client certificates within browsers, and also by Java as trust / certificate stores.

Tooling for p12 files is poor as it is a legacy format (uses 3DES internally etc), and more modern software normally uses the certificate and encrypted key directly. OpenSSL can create them, but as always that requires a trip to Stack Overflow to work out the command incantations required I wanted something neater.

## Installation 
Clone the repository, then run

```
go build
```

to get a binary for your platform.

You may need to run

```
go get software.sslmate.com/src/go-pkcs12
```

if you get errors about the `go-pkcs12` library.

## Usage

```
Usage: go-p12 -p12 <file.p12> -cert <cert.crt> -key <key.pem> -ca <root.crt>
  -ca value
        (Optional) Path to a CA certificate to append to the p12 (can be passed multiple times)
  -cert string
        (Optional) Path to the primary certificate
  -key string
        (Optional) Path to the private key for the primary certificate
  -p12 string
        Output path for the P12 you wish to create
```

P12 files have to be protected by a password. `go-p12` will prompt you interactively to specify one. If you want to set
a password automatically for scripting etc, use the `P12_PASS` environmental variable:
```
$ENV:P12_PASS = "hello"
go-p12.exe ......
```
```
P12_PASS=hello ./go-12 ....
```

### Examples

```
go-p12 -p12 myclientcert.p12 -cert myclientcert.crt -key myprivatekey.pem
```

This will create `myclientcert.p12` containing the specified cert and key. You will be prompted for the password to decrypt the private key, and then again for the password to encrypt the p12 container. This file is then suitable for importing into Firefox / Windows / Java applications to identify yourself to servers.

```
go-p12 -p12 identitystore.p12 -cert myserver.crt -key serverprivatekey.pem -ca intermediate.crt -ca root-ca.crt
```

This will create `identitystore.p12` containing the server certificate and key, but also the intermediate and root certificates that have signed the server cert. This file is then suitable for using as an "identity store" in Java applications to provide HTTPS for `myserver`.

```
go-p12 -p12 truststore.p12 -ca intermediate.crt -ca root-ca.crt
```

This will create `truststore.p12` containing only the intermediate and root certificates. This file is then suitable for using as "trust store" in Java applications  to verify certificates provided by other clients or servers.
