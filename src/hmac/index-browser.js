'use strict'

const crypto = require('../webcrypto.js')()
const lengths = require('./lengths')

const hashTypes = {
  SHA1: 'SHA-1',
  SHA256: 'SHA-256',
  SHA512: 'SHA-512'
}

const sign = (key, data) => {
  return Buffer.from(crypto.subtle.sign({ name: 'HMAC' }, key, data))
}

exports.create = async function (hashType, secret, callback) {
  const hash = hashTypes[hashType]

  const key = crypto.subtle.importKey(
    'raw',
    secret,
    {
      name: 'HMAC',
      hash: { name: hash }
    },
    false,
    ['sign']
  )

  return {
    async digest (data) {
      return sign(key, data)
    },
    length: lengths[hashType]
  }
}
