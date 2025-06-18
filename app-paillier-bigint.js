const paillierBigint = require('paillier-bigint');

async function main() {
  // Key generation
  const { publicKey, privateKey } = await paillierBigint.generateRandomKeys(2048);

  const x = 5n; // Example input
  console.log('Original x:', x.toString());

  // Encrypt x
  const encryptedX = publicKey.encrypt(x);

  // Calculate x * (x - 1) + x + 3
  // Since Paillier supports only addition and scalar multiplication, we must evaluate manually

  const xMinus1 = x - 1n;
  const xTimesXMinus1 = x * xMinus1; // Unencrypted here for demo — in real FHE, this would be encrypted

  // Encrypt the intermediate result
  const enc_xTimesXMinus1 = publicKey.encrypt(xTimesXMinus1);

  // Encrypt x and 3 separately
  const enc_x = publicKey.encrypt(x);
  const enc_3 = publicKey.encrypt(3n);

  // Homomorphic addition
  const resultEncrypted = publicKey.addition(
    publicKey.addition(enc_xTimesXMinus1, enc_x),
    enc_3
  );

  // Decrypt result
  const result = privateKey.decrypt(resultEncrypted);

  console.log(`Encrypted computation result: ${result.toString()}`);
  console.log(`Expected result: ${x * (x - 1n) + x + 3n}`);
}

main();
