// __test-utils__/custom-jest-environment.js
// Stolen from: https://github.com/ipfs/jest-environment-aegir/blob/master/src/index.js
// Overcomes error from jest internals.. this thing: https://github.com/facebook/jest/issues/6248

// eslint-disable-next-line import/no-extraneous-dependencies
const NodeEnvironment = require('jest-environment-jsdom');

// Jest definition of ArrayBuffer, Uint8Array and Uint32Array messes with type assertions, so we override them
class MyEnvironment extends NodeEnvironment {
  constructor(config) {
    super({
      ...config,
      globals: {
        ...config.globals,
        Uint32Array,
        Uint8Array,
        ArrayBuffer,
      },
    });
  }

  // eslint-disable-next-line no-empty-function,class-methods-use-this
  async setup() {}

  // eslint-disable-next-line no-empty-function,class-methods-use-this
  async teardown() {}
}

module.exports = MyEnvironment;
