const assert = require("assert");

const auth = require("../lib/auth");

const PASSWORD = Buffer.from("password");
const PUBLIC_KEY =
  "02b568858a407a8721923b89df9963d30013639ac690cce5f555529b77b83cbfc7";
const CHALLENGE = Buffer.from(
  "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
);

const SIGNATURE =
  "09dbe71a9fdfd1faca485f3727cc2e9a1ef20ae70f8e1e6af26c408e23b7685e620e307832c126ef6b2d24b7da79cb405d122af00b318cb99d5f2034c286cddb";

describe("Auth", function () {
  it("should generate a random challenge", function () {
    const c1 = auth.generateChallenge();
    const c2 = auth.generateChallenge();

    assert.equal(c1.length, 64);
    assert.equal(c1.length, c2.length);
    assert.notEqual(c1, c2);
  });

  it("should return a public key", () => {
    assert.equal(auth.getPublicKeyFromPassword(PASSWORD), PUBLIC_KEY);
  });

  it("should sign a challenge", () => {
    assert.equal(auth.sign(CHALLENGE, PASSWORD), SIGNATURE);
  });

  it("should verify a signature", () => {
    signature = Buffer.from(SIGNATURE, "hex");
    publicKey = Buffer.from(PUBLIC_KEY, "hex");

    assert.ok(auth.verify(CHALLENGE, signature, publicKey));
  });
});
