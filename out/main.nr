//! Generated main.nr template for Greco circuit
// TODO: Your imports here (example below)
// use greco::{Greco, Params};
// use polynomial::Polynomial;

fn main(
    params: Params<8192, 4>,
    pk_commitment: pub Field,
    pk0is: [Polynomial<8192>; 4],
    pk1is: [Polynomial<8192>; 4],
    ct0is: [Polynomial<8192>; 4],
    ct1is: [Polynomial<8192>; 4],
    u: Polynomial<8192>,
    e0: Polynomial<8192>,
    e0is: [Polynomial<8192>; 4],
    e0_quotients: [Polynomial<8192>; 4],
    e1: Polynomial<8192>,
    k1: Polynomial<8192>,
    r1is: [Polynomial<16383>; 4],
    r2is: [Polynomial<8191>; 4],
    p1is: [Polynomial<16383>; 4],
    p2is: [Polynomial<8191>; 4],
    // TODO: Other parameters...
) {
    // TODO: Your logic here...

    // Create Greco circuit instance.
    let greco: Greco<8192, 4, 56, 56, 2, 110, 6, 10, 14, 56, 14, 56> = Greco::new(
        params,
        pk0is,
        pk1is,
        ct0is,
        ct1is,
        u,
        e0,
        e0is,
        e0_quotients,
        e1,
        k1,
        r1is,
        r2is,
        p1is,
        p2is,
    );
    
    // TODO: Your logic here...
    }