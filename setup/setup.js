const crypto = require('@peculiar/webcrypto');

// eslint-disable-next-line no-undef
window.crypto = new crypto.Crypto();
// eslint-disable-next-line no-undef
window.Crypto = crypto.Crypto;
