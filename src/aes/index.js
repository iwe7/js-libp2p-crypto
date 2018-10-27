'use strict'

const ciphers = require('./ciphers')

const CIPHER_MODES = {
  16: 'aes-128-ctr',
  32: 'aes-256-ctr'
}

exports.create = async function (key, iv) {
  const mode = CIPHER_MODES[key.length]
  if (!mode) {
    throw new Error('Invalid key length')
  }

  const cipher = ciphers.createCipheriv(mode, key, iv)
  const decipher = ciphers.createDecipheriv(mode, key, iv)

  const res = {
    async encrypt (data, cb) {
      return cipher.update(data)
    },

    async decrypt (data, cb) {
      return decipher.update(data)
    }
  }

  return res
}
