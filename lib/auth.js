const random = require("bcrypto/lib/random");
const sha256 = require("bcrypto/lib/sha256");
const secp256k1 = require("bcrypto/lib/secp256k1");

const CHALLENGE_SIZE = 32; // bytes

const generateChallenge = () =>
  random.randomBytes(CHALLENGE_SIZE).toString("hex");

const getPrivateKey = (password) => sha256.digest(Buffer.from(password));

const getPublicKey = (privateKey) => secp256k1.publicKeyCreate(privateKey);

const getPublicKeyFromPassword = (password) =>
  getPublicKey(getPrivateKey(password)).toString("hex");

const sign = (challenge, password) =>
  secp256k1
    .sign(Buffer.from(challenge, "hex"), getPrivateKey(password))
    .toString("hex");

const verify = (challenge, signature, publicKey) =>
  secp256k1.verify(
    Buffer.from(challenge, "hex"),
    Buffer.from(signature, "hex"),
    Buffer.from(publicKey, "hex")
  );

module.exports = {
  generateChallenge,
  getPublicKeyFromPassword,
  sign,
  verify,
};
