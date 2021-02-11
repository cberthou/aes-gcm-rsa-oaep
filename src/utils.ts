export const arrayBufferToB64 = (arrayBuffer: ArrayBuffer): string =>
  btoa(String.fromCharCode.apply(null, new Uint8Array(arrayBuffer)));

/**
 * Converts a string to an ArrayBuffer
 * @param str
 */
export function str2ab(str: string): ArrayBuffer {
  const buf = new ArrayBuffer(str.length * 2); // 2 bytes for each char
  const bufView = new Uint16Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i += 1) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

export const atob =
  typeof window !== 'undefined'
    ? window.atob
    : function (str: string) {
        return Buffer.from(str, 'base64').toString('binary');
      };
