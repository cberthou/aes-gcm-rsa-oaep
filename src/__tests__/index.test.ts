// eslint-disable-next-line import/no-unresolved
import * as fs from 'fs';
import * as path from 'path';
import { HybridDecrypt, HybridEncrypt, pemPublicKeyToCryptoKey } from '../index';
import { arrayBufferToB64 } from '../utils';

describe('index', () => {
  describe('encrypt and decrypt', () => {
    it('works', async () => {
      const publicKey = fs.readFileSync(path.join(__dirname, '../../public.pem'), 'utf8');
      const privateKey = fs.readFileSync(path.join(__dirname, '../../pk8.pem'));

      const pubKey = await pemPublicKeyToCryptoKey(publicKey);

      const privKey = await crypto.subtle.importKey('pkcs8', privateKey, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, [
        'encrypt',
        'decrypt',
      ]);

      const encryptedText = 'Bonjour le monde';
      const label = Buffer.from('label');

      const result = await HybridEncrypt(pubKey, encryptedText, label);

      const str = await HybridDecrypt(privKey, result, label);

      expect(str).toEqual(encryptedText);
    });
  });

  describe('import pem key', () => {
    it('works', async () => {
      const pemContent = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA3OcM/3pefoIZjQLEM6RS
t47S0SA3KGIMnhh2hix/xQrmrYhN6oRXibdrmEPhhZhIN3vTf+sQ2PDYFDLy3VJQ
H5eU6leR/ehF00rBhGkS9iuBCCHZhX5WrPq+3YeSGLZlfDU11thEi5Mjntz7nyvz
oXQ/8XMYJWCzPiZ0dqWyqhbxXLJPixytxU1rdMUnqoHfuhvTyMVAGx7aCmCPUeNa
1pwl2O59M6fs1g/+oxA7GwoBSeue2cMJ9F1xpEKiLXWbDfhEyHAVSHanps3JLHe0
UVGUIiRfIpjOUv8I/9aOeScADy6oOTnY+U/6UKuIEhvlBtT9HicQUKVAoJrVtUgI
0thr/ZJLsPzwDJiwGjdLh5zPE2PTjyyzBDY5p/SIb2K4Y+ZSn3+DVzQuJxxUg1AF
X7uZDR62J/VpwgsP32RPNaeQ6OyHLG35oBKt07YO6dXql6R/TRPU1kmU89x1v9JZ
hLiLDcY1/+vdgwXj/wglImJQHn+9OFqKPOI8CM+IxMH46J7BVWh227SBsqo705Vn
GH0Jwi75wfj5arrXP/6fP1Yl137gMI/yt5WL4RlrdkzS6Pet1xv6agVW2cWFSOJu
yM62dL4W4XJNaBmDfMl/LGDwVJ+f+V/2yfF89SrAHgn0lwLwowGdzH0A8MW7BFEV
UAHog3BetRu+fy6v2QZu+IcCAwEAAQ==
-----END PUBLIC KEY-----
`;

      const key = await pemPublicKeyToCryptoKey(pemContent);
      expect(key).toBeDefined();
      const encrypted = await HybridEncrypt(key, 'hello', Buffer.from(''));
      console.log(encrypted);
      console.log(arrayBufferToB64(encrypted));
      expect(encrypted).toBeDefined();
    });
  });
});
