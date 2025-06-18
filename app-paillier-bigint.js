//x * x illegal
const paillierBigint = require('paillier-bigint');

// Encrypt and prepare packet for server and client
async function prepareEncryptedData(x) {
    const { publicKey, privateKey } = await paillierBigint.generateRandomKeys(2048);
    const bigX = BigInt(x);

    // Encrypt values
    const enc_x = publicKey.encrypt(bigX);
    const enc_3 = publicKey.encrypt(3n);
    const xTimesXMinus1 = bigX * (bigX - 1n); 
    const enc_xTimesXMinus1 = publicKey.encrypt(xTimesXMinus1);

    // Encrypted data to be sent to server
    const encryptedDataPacket = {
        encryptedData: {
            enc_x: enc_x.toString(),
            enc_3: enc_3.toString(),
            enc_xTimesXMinus1: enc_xTimesXMinus1.toString()
        },
        publicKey: {
            n: publicKey.n.toString(),
            g: publicKey.g.toString()
        }
    };

    // Private key kept only by the client
    const privateKeyForClient = {
        lambda: privateKey.lambda.toString(),
        mu: privateKey.mu.toString()
    };

    return {
        serverPacket: encryptedDataPacket,
        privateKeyForClient
    };
}

// Server-side computation (no access to private key)
async function computeEncryptedExpression(encryptedData, publicKeyJson) {
    const publicKey = new paillierBigint.PublicKey(
        BigInt(publicKeyJson.n),
        BigInt(publicKeyJson.g)
    );

    const enc_x = BigInt(encryptedData.enc_x);
    const enc_3 = BigInt(encryptedData.enc_3);
    const enc_xTimesXMinus1 = BigInt(encryptedData.enc_xTimesXMinus1);

    let r = publicKey.addition(enc_xTimesXMinus1, enc_x);
    r = publicKey.addition(r, enc_3);

    return r.toString(); // Encrypted result as string
}

// Client-side decryption (only client holds the private key)
function decryptResult(encryptedResultStr, publicKeyJson, privateKeyJson) {
    const publicKey = new paillierBigint.PublicKey(
        BigInt(publicKeyJson.n),
        BigInt(publicKeyJson.g)
    );

    const privateKey = new paillierBigint.PrivateKey(
        BigInt(privateKeyJson.lambda),
        BigInt(privateKeyJson.mu),
        publicKey
    );

    const encryptedResult = BigInt(encryptedResultStr);
    const decrypted = privateKey.decrypt(encryptedResult);

    return decrypted.toString();
}

// Entry point
(async () => {
    const x = 5;

    // Step 1: Client encrypts data
    const { serverPacket, privateKeyForClient } = await prepareEncryptedData(x);

    // Step 2: Server computes on encrypted data
    const encryptedResult = await computeEncryptedExpression(
        serverPacket.encryptedData,
        serverPacket.publicKey
    );

    // Step 3: Client decrypts the result
    const finalDecrypted = decryptResult(
        encryptedResult,
        serverPacket.publicKey,
        privateKeyForClient
    );

    console.log(`Final decrypted result of x*(x-1)+x+3 where x=${x}:`, finalDecrypted);
})();
