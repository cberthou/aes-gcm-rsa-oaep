import { pki } from 'node-forge';
import { HybridEncrypt, pemPublicKeyToCryptoKey } from '../src';

/*
  generate a sealed-secret from a public key in NodeJS
  NodeJS require `node-forge` to create the cryptoKey from the raw public key
*/

// some cluster public certificate
const cert = pki.certificateFromPem(
  `-----BEGIN CERTIFICATE-----
MIIErjCCApagAwIBAgIRAOqAV9ZpCl1cwMunTHirqXwwDQYJKoZIhvcNAQELBQAw
ADAeFw0yMDA1MjYwODQxMTBaFw0zMDA1MjQwODQxMTBaMAAwggIiMA0GCSqGSIb3
DQEBAQUAA4ICDwAwggIKAoICAQDc5wz/el5+ghmNAsQzpFK3jtLRIDcoYgyeGHaG
LH/FCuatiE3qhFeJt2uYQ+GFmEg3e9N/6xDY8NgUMvLdUlAfl5TqV5H96EXTSsGE
aRL2K4EIIdmFflas+r7dh5IYtmV8NTXW2ESLkyOe3PufK/OhdD/xcxglYLM+JnR2
pbKqFvFcsk+LHK3FTWt0xSeqgd+6G9PIxUAbHtoKYI9R41rWnCXY7n0zp+zWD/6j
EDsbCgFJ657Zwwn0XXGkQqItdZsN+ETIcBVIdqemzcksd7RRUZQiJF8imM5S/wj/
1o55JwAPLqg5Odj5T/pQq4gSG+UG1P0eJxBQpUCgmtW1SAjS2Gv9kkuw/PAMmLAa
N0uHnM8TY9OPLLMENjmn9IhvYrhj5lKff4NXNC4nHFSDUAVfu5kNHrYn9WnCCw/f
ZE81p5Do7IcsbfmgEq3Ttg7p1eqXpH9NE9TWSZTz3HW/0lmEuIsNxjX/692DBeP/
CCUiYlAef704Woo84jwIz4jEwfjonsFVaHbbtIGyqjvTlWcYfQnCLvnB+Plqutc/
/p8/ViXXfuAwj/K3lYvhGWt2TNLo963XG/pqBVbZxYVI4m7IzrZ0vhbhck1oGYN8
yX8sYPBUn5/5X/bJ8Xz1KsAeCfSXAvCjAZ3MfQDwxbsEURVQAeiDcF61G75/Lq/Z
Bm74hwIDAQABoyMwITAOBgNVHQ8BAf8EBAMCAAEwDwYDVR0TAQH/BAUwAwEB/zAN
BgkqhkiG9w0BAQsFAAOCAgEAKLvQtDV5QVNUEcg3ywL03IwtNWmU8EqqASgckVAc
dmeGnFwV7+7VnrIHI34xCZDhAVEnlMAb0oELgTDSstTx4p25rjqOLQfPcb0TsPko
cpJHS00trLsLX4DYoZ1dLprgySGrC9jQ/FMYMK1oZ0M04gA/U9alNVNu2DWKosHu
JGRYBbXVnse5rZi3hl4GV5Vq2ZR/3GHL9xgcjMcSLqHhXoSULLm5qEBUA5flV0BJ
bY2FEfpm1NHSh5vOaA5t7lrW/XqiAuo8lJM2Ztg/dsX6Zxq7Memq8nqMRpoMFbdj
i0jTxlPL1ssVHvvmWcLsdx9fHX7XaNGZ4ulA6BIL4DZQMPxvtFk9alqbc9WnjsqL
/8QA3STXkTSzWrSsTUcabxlp5+MLHRf31iE1dlGVv7FVLjPy29T145eSzoNPM9sN
1+aBLnXDCj5HUwto8+iKJn7VTURty5KceUFSeURXM2IKYYTec8MElLX0PeXi+SvO
W37ZCn0RMnljus5aTUPbRHNvJ3Ut/1WDLQu8X0wIm509F1A80Udg5FTxHasBizM2
L+rpr2923MG1JSitDfvNj1rxx1FLdynP84SOEJDCtbB8YRcDUC4bHKrAcG4FBAFX
UDzbbsoR58onjcZW3QH4mvV9K3+llwHSo8zfYyKRhF8pUUJHp7A/8DgMYQyYAv2z
bag=
-----END CERTIFICATE-----`
);

const generateSealedSecret = async () => {
  const publicKeyPem = pki.publicKeyToPem(cert.publicKey);
  const publicKey = await pemPublicKeyToCryptoKey(publicKeyPem);

  const encryptedText = 'Bonjour le monde';

  // https://github.com/bitnami-labs/sealed-secrets/blob/717b7c1cae24af1ead57992b78196ff6dc70025e/pkg/apis/sealed-secrets/v1alpha1/sealedsecret_expansion.go#L77
  const label = Buffer.from('');

  const result = await HybridEncrypt(publicKey, encryptedText, label);

  const sealedText = Buffer.from(result).toString('base64');

  console.log(`
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  annotations:
    &a1
    sealedsecrets.bitnami.com/cluster-wide: "true"
  name: app-sealed-secret-js
  namespace: sample-next-app
spec:
  encryptedData:
    SECRET: ${sealedText}
  template:
    metadata:
      annotations: *a1
      name: app-sealed-secret-js
    type: Opaque

`);
};

generateSealedSecret();
