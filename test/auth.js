const assert = require("assert");

const auth = require("../lib/auth");

const PASSWORD = "password";
const PUBLIC_KEY =
  "02b568858a407a8721923b89df9963d30013639ac690cce5f555529b77b83cbfc7";
const CHALLENGE =
  "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";

const SIGNATURE =
  "8943f5e3d2607cb932af7582aa8bc65e4464b90ae04c483cf3b69fae79fbb64328ca92cc6107191259f49e7aa90ba76447d1f936196e75950d97a249400ae702";

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
    assert.ok(auth.verify(CHALLENGE, SIGNATURE, PUBLIC_KEY));
  });
});
