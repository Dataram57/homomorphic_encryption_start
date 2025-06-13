//proper lib.
//const SEAL = require('node-seal');

//node-seal with no transparency checks
//history: https://github.com/s0l0ist/node-seal/issues/160
const SEAL = require('node-seal/allows_wasm_node_umd');

//async app
(async () => {
    const seal = await SEAL();

    // Set up encryption parameters
    const schemeType = seal.SchemeType.bfv;
    const securityLevel = seal.SecurityLevel.tc128;
    const polyModulusDegree = 8192;
    const bitSizes = [36, 36, 36, 36, 37];
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

    // Generate keys (including relinearization keys)
    const keyGenerator = seal.KeyGenerator(context);
    const publicKey = keyGenerator.createPublicKey();
    const secretKey = keyGenerator.secretKey();
    const relinKeys = keyGenerator.createRelinKeys(7);  // Needed for multiplication

    // Set up encryptor, evaluator, decryptor
    const encryptor = seal.Encryptor(context, publicKey);
    const evaluator = seal.Evaluator(context);
    const decryptor = seal.Decryptor(context, secretKey);

    // Use BatchEncoder
    const batchEncoder = seal.BatchEncoder(context);

    // Function to compute (x + x) * x homomorphically
    async function HomomorphicCompute(clientData) {
        // Load encryption parameters
        const encParms = seal.EncryptionParameters(seal.SchemeType.bfv);
        encParms.load(clientData.encParms);

        // Recreate context
        const context = seal.Context(encParms, true, seal.SecurityLevel.tc128);
        if (!context.parametersSet()) throw new Error('Failed to set parameters');

        // Create batch encoder
        const batchEncoder = seal.BatchEncoder(context);

        // Load Keys and Ciphertext
        const publicKey = seal.PublicKey();
        publicKey.load(context, clientData.publicKey);

        const relinKeys = seal.RelinKeys();
        relinKeys.load(context, clientData.relinKeys);

        const ciphertext = seal.CipherText();
        ciphertext.load(context, clientData.ciphertext);

        // Perform Computations
        const evaluator = seal.Evaluator(context);
        
        // Compute (x + 1) * x
        let result
        checkNoise("r = x", ciphertext, decryptor);
        result = evaluator.addPlain(ciphertext, batchEncoder.encode(Int32Array.from([1]))); //x+1
        checkNoise("r = r + 1", result, decryptor);
        result = evaluator.square(result); //x*x
        checkNoise("r = r ** 2", result, decryptor);
        result = evaluator.relinearize(result, relinKeys); // Reduce size
        checkNoise("r = r", result, decryptor);
        result = evaluator.multiplyPlain(result, batchEncoder.encode(Int32Array.from([3]))); //x*x
        checkNoise("r = r * 3", result, decryptor);
        result = evaluator.multiply(result, ciphertext);  // (x + x) * x
        checkNoise("r = r * x", result, decryptor);
        result = evaluator.relinearize(result, relinKeys);  // Critical: reduce ciphertext size
        checkNoise("r = r", result, decryptor);
        //return
        return result;
    }
    
    function checkNoise(msg, ct, decryptor) {
        console.log(msg + ",", "Noise budget:", decryptor.invariantNoiseBudget(ct));
    }

    // Wrapper function
    async function Compute(x) {
        // Encode the value (using BatchEncoder)
        const plainText = batchEncoder.encode(Int32Array.from([x]));
        
        // Encrypt
        const ciphertext = encryptor.encrypt(plainText);
        
        // Prepare data for computation
        const exportData = {
            encParms: encParms.save(),
            publicKey: publicKey.save(),
            relinKeys: relinKeys.save(),  // Now included
            ciphertext: ciphertext.save(),
        };

        // Perform homomorphic computation
        const encryptedResult = await HomomorphicCompute(exportData);
        
        // Decrypt
        const plainResult = decryptor.decrypt(encryptedResult);
        
        // Decode
        const resultArray = batchEncoder.decode(plainResult);
        return resultArray[0];  // Return first slot value
    }

    // Example usage
    const x = 5;
    const result = await Compute(x);
    console.log('x = ' + x);
    console.log('3 * ((x + 1) ** 2) * x =', result);

    // Clean up
    [encParms, context, keyGenerator, publicKey, secretKey, relinKeys, 
     encryptor, evaluator, decryptor, batchEncoder].forEach(obj => obj.delete());
})();