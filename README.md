# AES-GCM + RSA OAEP

POC of AES-GCM + RSA-OAEP encryption/decryption using window.crypto api.

Tests uses `@peculiar/webcrypto` for polyfilling browser crypto api.

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
