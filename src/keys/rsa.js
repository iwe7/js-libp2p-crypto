'use strict'

const crypto = require('crypto')
let keypair
try {
  if (process.env.LP2P_FORCE_CRYPTO_LIB === 'keypair') {
    throw new Error('Force keypair usage')
  }

  const ursa = require('ursa-optional') // throws if not compiled
  keypair = ({ bits }) => {
    const key = ursa.generatePrivateKey(bits)
    return {
      private: key.toPrivatePem(),
      public: key.toPublicPem()
    }
  }
} catch (e) {
  if (process.env.LP2P_FORCE_CRYPTO_LIB === 'ursa') {
    throw e
  }

  keypair = require('keypair')
}

const pemToJwk = require('pem-jwk').pem2jwk
const jwkToPem = require('pem-jwk').jwk2pem

exports.utils = require('./rsa-utils')

exports.generateKey = async function (bits) {
  const key = keypair({ bits })
  return {
    privateKey: pemToJwk(key.private),
    publicKey: pemToJwk(key.public)
  }
}

// Takes a jwk key
exports.unmarshalPrivateKey = async function (key) {
  if (!key) {
    throw new Error('Key is invalid')
  }
  return {
    privateKey: key,
    publicKey: {
      kty: key.kty,
      n: key.n,
      e: key.e
    }
  }
}

exports.getRandomValues = function (arr) {
  return crypto.randomBytes(arr.length)
}

exports.hashAndSign = async function (key, msg) {
  const sign = crypto.createSign('RSA-SHA256')
  sign.update(msg)
  const pem = jwkToPem(key)
  return sign.sign(pem)
}

exports.hashAndVerify = async function (key, sig, msg) {
  const verify = crypto.createVerify('RSA-SHA256')
  verify.update(msg)
  const pem = jwkToPem(key)
  return verify.verify(pem, sig)
}
