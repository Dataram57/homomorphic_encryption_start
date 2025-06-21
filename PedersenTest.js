
// Big integer operations with native BigInt
const p = 208351617316091241234326746312124448251235562226470491514186331217050270460481n; // Large prime
const g = 2n;
const h = 3n;

// Modular exponentiation
function modExp(base, exponent, mod) {
    let result = 1n;
    base = base % mod;
    while (exponent > 0) {
        if (exponent % 2n === 1n) {
        result = (result * base) % mod;
        }
        exponent = exponent / 2n;
        base = (base * base) % mod;
    }
    return result;
}

// Pedersen commitment: C = g^x * h^r mod p
function pedersenCommit(x, r) {
    return (modExp(g, x, p) * modExp(h, r, p)) % p;
}

// Example values
const x1 = 5n, r1 = 17n;
const x2 = 12n, r2 = 33n;
const x3 = 8n, r3 = 4n;
const x4 = 9n, r4 = 5n;

const C1 = pedersenCommit(x1, r1);
const C2 = pedersenCommit(x2, r2);
const C3 = pedersenCommit(x3, r3);
const C4 = pedersenCommit(x4, r4);

console.log("C1:", C1.toString());
console.log("C2:", C2.toString());
console.log("C3:", C3.toString());
console.log("C4:", C3.toString());

// Combine commitments: C_sum = C1 * C2 * C3 mod p
//const C_sum = (C1 * C2 * C3) % p;
const C_sum = (C1 * C2 * C3 * C4) % p;

// Public sum
//const S = x1 + x2 + x3; // 5 + 12 + 8 = 25
const S = x1 + x2 + x3 + x4; // 5 + 12 + 8 + 9 = 34
//const R = r1 + r2 + r3;
const R = r1 + r2 + r3 + r4;

// Commitment to S
const C_check = pedersenCommit(S, R);

console.log("Combined Commitment (C_sum):", C_sum.toString());
console.log("Commitment to S (C_check):", C_check.toString());

if (C_sum === C_check) {
    console.log("✅ Proof successful: commitments add up to public sum S =", S.toString());
} else {
    console.log("❌ Proof failed");
}

