export const arrayBufferToB64 = (arrayBuffer: ArrayBuffer): string =>
  btoa(String.fromCharCode.apply(null, new Uint8Array(arrayBuffer)));

/**
 * Converts a string to an ArrayBuffer
 * @param str
 */
export function str2ab(str: string): ArrayBuffer {
  return new TextEncoder().encode(str);
}

export const atob =
  typeof window !== 'undefined'
    ? window.atob
    : function (str: string) {
        return Buffer.from(str, 'base64').toString('binary');
      };
