const she = require('she-wasm');


she.init(she.BN_SNARK1).then(async () => {
    const sec = new she.SecretKey();
    sec.setByCSPRNG();
    const pub = sec.getPublicKey();
    const m1 = 9
    const m2 = 5
    const m3 = 2
    const m4 = -1
    const c11 = pub.encG1(m1)
    const c12 = pub.encG1(m2)
    const c21 = pub.encG2(m3)
    const c22 = pub.encG2(m4)
    const c1 = she.add(c11, c12)
    console.log("m1+m2", sec.dec(c1))
    const c2 = she.sub(c21, c22)
    console.log("m3-m4", sec.dec(c2))
    const ct = she.mul(c1, c2)
    console.log("(m1+m2)*(m3-m4)", sec.dec(ct))
    //still can't calculate encrypted * encrypted
});

