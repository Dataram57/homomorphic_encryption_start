const SEAL = require('node-seal');
(async () => {
const seal = await SEAL();

async function runCalculation() {
    try {
        // Set up encryption parameters
        const schemeType = seal.SchemeType.bfv;
        const securityLevel = seal.SecurityLevel.tc128;
        const polyModulusDegree = 4096;
        const bitSizes = [36, 36, 37];
        const bitSize = 20;
        
        const encParams = seal.EncryptionParameters(schemeType);
        encParams.setPolyModulusDegree(polyModulusDegree);
        encParams.setCoeffModulus(seal.CoeffModulus.Create(polyModulusDegree, Int32Array.from(bitSizes)));
        encParams.setPlainModulus(seal.PlainModulus.Batching(polyModulusDegree, bitSize));
        
        // Create context
        const context = seal.Context(encParams, true, securityLevel);
        if (!context.parametersSet()) {
            throw new Error('Failed to set encryption parameters');
        }
        
        // Generate keys
        const keyGenerator = seal.KeyGenerator(context);
        const publicKey = keyGenerator.createPublicKey();
        const secretKey = keyGenerator.secretKey();
        const relinKeys = keyGenerator.createRelinKeys();
        
        // Create encryptor, evaluator, and decryptor
        const encryptor = seal.Encryptor(context, publicKey);
        const evaluator = seal.Evaluator(context);
        const decryptor = seal.Decryptor(context, secretKey);
        
        // Create batch encoder
        const batchEncoder = seal.BatchEncoder(context);
        
        // Our secret value (x)
        const secretX = 5; // This would be your secret value in a real application
        
        // Encode and encrypt x
        const plainX = seal.PlainText();
        batchEncoder.encode(Int32Array.from([secretX]), plainX);
        const encryptedX = seal.CipherText();
        encryptor.encrypt(plainX, encryptedX);
        
        // Perform the calculation (x + 3) * 7
        
        // Step 1: Encode and encrypt 3
        const plainThree = seal.PlainText();
        batchEncoder.encode(Int32Array.from([3]), plainThree);
        
        // Step 2: Add 3 to encrypted x
        evaluator.addPlain(encryptedX, plainThree, encryptedX);
        
        // Step 3: Encode 7
        const plainSeven = seal.PlainText();
        batchEncoder.encode(Int32Array.from([7]), plainSeven);
        
        // Step 4: Multiply by 7
        evaluator.multiplyPlain(encryptedX, plainSeven, encryptedX);
        //evaluator.relinearizeInplace(encryptedX, relinKeys);
        
        // Decrypt and decode the result
        const plainResult = seal.PlainText();
        decryptor.decrypt(encryptedX, plainResult);
        const resultArray = batchEncoder.decode(plainResult);
        const result = resultArray[0];
        
        console.log(`Original x: ${secretX}`);
        console.log(`Result of (x + 3) * 7: ${result}`);
        console.log(`Expected result: ${(secretX + 3) * 7}`);
        
        // Clean up
        plainX.delete();
        encryptedX.delete();
        plainThree.delete();
        plainSeven.delete();
        plainResult.delete();
        publicKey.delete();
        secretKey.delete();
        relinKeys.delete();
        keyGenerator.delete();
        encryptor.delete();
        evaluator.delete();
        decryptor.delete();
        batchEncoder.delete();
        encParams.delete();
        context.delete();
        
    } catch (error) {
        console.error('Error:', error);
    }
}

runCalculation();
})();