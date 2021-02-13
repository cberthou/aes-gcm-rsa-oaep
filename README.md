# AES-GCM + RSA OAEP encryption

AES-GCM + RSA-OAEP encryption/decryption using WebCrypto API in NodeJS or in the browser 

Tests uses `@peculiar/webcrypto` for polyfilling browser crypto api.

This can be used to replace [kubeseal](https://github.com/bitnami-labs/sealed-secrets) encryption in JavaScript environments.

See demo : https://38lo8.csb.app/

## Using x509 certificates

To be able to use x509 certificates, you need to first extract the public key with 
openssl :

```shell script
openssl x509 -in ./cert.pem -pubkey -noout > certificate_publickey.pem
```

Extracting the public key form the certificate is a pain to do in JS.

You can also use `node-forge` to do it : 
```
import { pki } from "node-forge";

const cert = pki.certificateFromPem(
  `-----BEGIN CERTIFICATE-----
  ...
  -----END CERTIFICATE-----`
);

const publikKeyPem = pki.publicKeyToPem(cert.publicKey);

pemPublicKeyToCryptoKey(publicKeyPem);
```
