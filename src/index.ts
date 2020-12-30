function str2ab(str: string): ArrayBuffer {
  const buf = new ArrayBuffer(str.length * 2); // 2 bytes for each char
  const bufView = new Uint16Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i += 1) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

function ab2str(buf: ArrayBuffer): string {
  return String.fromCharCode.apply(null, new Uint16Array(buf));
}

const aesGcmEncrypt = async (key: CryptoKey, str: string): Promise<ArrayBuffer> => {
  const nonce = new Uint8Array(16);
  nonce.fill(0);
  const result = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
    },
    key,
    str2ab(str)
  );

  return result;
};

const aesGcmDecrypt = async (key: CryptoKey, enc: ArrayBuffer): Promise<string> => {
  const nonce = new Uint8Array(16);
  nonce.fill(0);
  const result = await window.crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
    },
    key,
    enc
  );

  return ab2str(result);
};

const sessionKeyLength = 256;

export async function HybridEncrypt(pubKey: CryptoKey, text: string, label: ArrayBuffer): Promise<ArrayBuffer> {
  const sessionKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: sessionKeyLength }, true, ['encrypt']);

  const rawSessionKey = await crypto.subtle.exportKey('raw', sessionKey);

  const rsaCipherText = await window.crypto.subtle.encrypt(
    {
      name: 'RSA-OAEP',
      label,
    },
    pubKey,
    rawSessionKey
  );

  const rsaCipherLength = Uint16Array.from([rsaCipherText.byteLength]).buffer;
  const result = await aesGcmEncrypt(sessionKey, text);

  const resultBuffer = new Uint8Array(rsaCipherLength.byteLength + rsaCipherText.byteLength + result.byteLength);

  resultBuffer.set(new Uint8Array(rsaCipherLength), 0);
  resultBuffer.set(new Uint8Array(rsaCipherText), rsaCipherLength.byteLength);
  resultBuffer.set(new Uint8Array(result), rsaCipherLength.byteLength + rsaCipherText.byteLength);
  return resultBuffer.buffer;
}

export async function HybridDecrypt(privKey: CryptoKey, cipherText: ArrayBuffer, label: ArrayBuffer): Promise<string> {
  const rsaLength = new Uint16Array(cipherText, 0, 1)[0];
  const rsaCipherText = new Uint8Array(cipherText.slice(2, 2 + rsaLength));
  const aesCipherText = new Uint8Array(cipherText.slice(2 + rsaLength));
  const sessionKey = await window.crypto.subtle.decrypt(
    {
      name: 'RSA-OAEP',
      label,
    },
    privKey,
    rsaCipherText
  );

  const key = await crypto.subtle.importKey('raw', sessionKey, { name: 'AES-GCM', length: sessionKeyLength }, false, [
    'decrypt',
  ]);
  const text = aesGcmDecrypt(key, aesCipherText);

  return text;
}
