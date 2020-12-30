import { HybridDecrypt, HybridEncrypt } from '../index';

describe('obj', () => {
  it('works', async () => {
    const { publicKey, privateKey } = await crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: 'SHA-256',
      },
      false,
      ['encrypt', 'decrypt']
    );

    const encryptedText = 'Bonjour le monde';
    const label = Buffer.from('label');

    const result = await HybridEncrypt(publicKey, encryptedText, label);

    const str = await HybridDecrypt(privateKey, result, label);

    expect(str).toEqual(encryptedText);
  });
});
