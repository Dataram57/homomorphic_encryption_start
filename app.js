const SEAL = require('node-seal');
(async () => {
    const seal = await SEAL();

    // Set up encryption parameters
    const schemeType = seal.SchemeType.bfv;
    const securityLevel = seal.SecurityLevel.tc128;
    const polyModulusDegree = 4096;
    const bitSizes = [36, 36, 37];
    const bitSize = 20;

    const encParms = seal.EncryptionParameters(schemeType);
    encParms.setPolyModulusDegree(polyModulusDegree);
    encParms.setCoeffModulus(
        seal.CoeffModulus.Create(polyModulusDegree, Int32Array.from(bitSizes))
    );
    encParms.setPlainModulus(seal.PlainModulus.Batching(polyModulusDegree, bitSize));

    const context = seal.Context(encParms, true, securityLevel);
    if (!context.parametersSet()) {
        throw new Error('Failed to set parameters');
    }

    // Generate keys
    const keyGenerator = seal.KeyGenerator(context);
    const publicKey = keyGenerator.createPublicKey();
    const secretKey = keyGenerator.secretKey();

    // Set up encryptor, evaluator, decryptor
    const encryptor = seal.Encryptor(context, publicKey);
    const evaluator = seal.Evaluator(context);
    const decryptor = seal.Decryptor(context, secretKey);

    // Use BatchEncoder instead of IntegerEncoder
    const batchEncoder = seal.BatchEncoder(context);

    // Function to compute x² homomorphically
    async function HomomorphicCompute(x){
        let result;
        result = evaluator.add(x, x);
        result = evaluator.multiply(result, x);
        return result;
    }
    
    //wrapper
    async function Compute(x) {
        // Encode the value (using BatchEncoder)
        const plain = new Int32Array(1);
        plain[0] = x;
        const plainText = batchEncoder.encode(plain);
        
        // Encrypt
        const encrypted = encryptor.encrypt(plainText);
        
        // Square the encrypted value
        const encryptedSquare = await HomomorphicCompute(encrypted);
        
        // Decrypt
        const plainResult = decryptor.decrypt(encryptedSquare);
        
        // Decode
        const resultArray = batchEncoder.decode(plainResult);
        return resultArray[0];
    }

    // Example usage
    const result = await Compute(5);
    console.log('(x + x) * x =', result); // Should output 25

    // Clean up
    [encParms, context, keyGenerator, publicKey, secretKey, encryptor, evaluator, decryptor, batchEncoder].forEach(obj => obj.delete());
})();