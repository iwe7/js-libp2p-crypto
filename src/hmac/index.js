'use strict'

const crypto = require('crypto')
const lengths = require('./lengths')

exports.create = async function (hash, secret, callback) {
  const res = {
    async digest (data) {
      const hmac = crypto.createHmac(hash.toLowerCase(), secret)
      hmac.update(data)
      return hmac.digest()
    },
    length: lengths[hash]
  }

  return res
}
