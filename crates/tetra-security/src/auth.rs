//! Authentication procedures of ETSI EN 300 392-7 clause 4.1, from the
//! infrastructure's point of view, as pure functions over the TAA1
//! algorithms. The MM state machine in `tetra-entities` drives these; nothing
//! here does I/O or keeps state beyond the values the protocol carries.
//!
//! * Authentication of an MS (4.1.2): the SwMI sends RS and RAND1, the MS
//!   answers RES1, and both sides derive DCK1.
//! * Authentication of the infrastructure (4.1.3): the MS sends RAND2 (and,
//!   when it starts the exchange, RS), the SwMI answers RES2, and both sides
//!   derive DCK2.
//! * Mutual authentication (4.1.4): the responder of a one-way challenge adds
//!   its own challenge; DCK = TB4(DCK1, DCK2).

use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::keys::{AuthKey, CipherKey};
use crate::taa1;

/// A random seed RS or challenge RAND (80 bits).
pub type Nonce = [u8; 10];

/// Fresh random RS / RAND1 / RAND2 from the operating system's generator.
pub fn random_nonce() -> Nonce {
    let mut n = [0u8; 10];
    rand::rng().fill_bytes(&mut n);
    n
}

/// A session authentication key (KS or KS').
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionKey(pub [u8; 16]);

/// An authentication data set (RS, KS, KS') as the authentication centre hands it to the
/// entity that authenticates on its behalf (EN 300 392-7 clause 4.1.1): KS = TA11(K, RS) for
/// the authentication of the MS (4.1.2), KS' = TA21(K, RS) for the authentication of the
/// infrastructure (4.1.3). Whoever holds it never needs K, and RAND1 / RAND2 stay fresh per
/// exchange. Used once.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct AuthVector {
    #[zeroize(skip)]
    pub rs: Nonce,
    pub ks: [u8; 16],
    pub ks_p: [u8; 16],
}

impl std::fmt::Debug for AuthVector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AuthVector {{ rs: {:02x?}, ks: <redacted> }}", self.rs)
    }
}

impl AuthVector {
    /// The set for seed `rs`, computed from K (a station that holds K itself).
    pub fn from_k(k: &AuthKey, rs: Nonce) -> AuthVector {
        AuthVector { rs, ks: taa1::ta11(&k.0, &rs), ks_p: taa1::ta21(&k.0, &rs) }
    }
}

/// The infrastructure's view of a challenge it has issued to an MS
/// (clause 4.1.2): everything needed to judge the response.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MsChallenge {
    #[zeroize(skip)]
    pub rs: Nonce,
    #[zeroize(skip)]
    pub rand1: Nonce,
    /// Expected response XRES1.
    xres1: [u8; 4],
    /// Derived cipher key half DCK1.
    dck1: [u8; 10],
}

impl MsChallenge {
    /// Issue a challenge to the subscriber holding `k`: generates RS and
    /// RAND1, and precomputes XRES1 and DCK1 with TA11 / TA12.
    pub fn new(k: &AuthKey) -> MsChallenge {
        MsChallenge::with_nonces(k, random_nonce(), random_nonce())
    }

    /// As [`MsChallenge::new`] with given nonces (for tests and for
    /// re-using an RS across a mutual exchange).
    pub fn with_nonces(k: &AuthKey, rs: Nonce, rand1: Nonce) -> MsChallenge {
        let ks = taa1::ta11(&k.0, &rs);
        let r = taa1::ta12(&ks, &rand1);
        MsChallenge {
            rs,
            rand1,
            xres1: r.res,
            dck1: r.dck,
        }
    }

    /// Issue a challenge from an authentication data set: RS from the set, a fresh RAND1, and
    /// XRES1 / DCK1 from KS with TA12 (clause 4.1.1: the entity on behalf of the
    /// authentication centre only knows KS).
    pub fn from_vector(v: &AuthVector, rand1: Nonce) -> MsChallenge {
        let r = taa1::ta12(&v.ks, &rand1);
        MsChallenge { rs: v.rs, rand1, xres1: r.res, dck1: r.dck }
    }

    /// Judge the MS's response RES1. On success returns DCK1.
    pub fn verify(&self, res1: &[u8; 4]) -> Option<[u8; 10]> {
        if constant_time_eq(&self.xres1, res1) {
            Some(self.dck1)
        } else {
            None
        }
    }
}

/// The infrastructure answering an MS's challenge (clause 4.1.3): computes
/// RES2 and DCK2 with TA21 / TA22 from the shared K, the random seed RS of
/// the exchange and the MS's RAND2.
pub struct InfrastructureResponse {
    pub res2: [u8; 4],
    pub dck2: [u8; 10],
}

pub fn answer_ms_challenge(k: &AuthKey, rs: &Nonce, rand2: &Nonce) -> InfrastructureResponse {
    let ksp = taa1::ta21(&k.0, rs);
    let r = taa1::ta22(&ksp, rand2);
    InfrastructureResponse { res2: r.res, dck2: r.dck }
}

/// As [`answer_ms_challenge`] from KS' of an authentication data set (no K needed).
pub fn answer_with_vector(v: &AuthVector, rand2: &Nonce) -> InfrastructureResponse {
    let r = taa1::ta22(&v.ks_p, rand2);
    InfrastructureResponse { res2: r.res, dck2: r.dck }
}

/// The derived cipher key after an exchange (clause 4.2.1): TB4 over the two
/// halves, a missing half being zero for a one-way authentication.
pub fn derive_dck(dck1: Option<&[u8; 10]>, dck2: Option<&[u8; 10]>) -> CipherKey {
    let zero = [0u8; 10];
    CipherKey(taa1::tb4(dck1.unwrap_or(&zero), dck2.unwrap_or(&zero)))
}

fn constant_time_eq(a: &[u8; 4], b: &[u8; 4]) -> bool {
    let mut diff = 0u8;
    for i in 0..4 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k() -> AuthKey {
        "0123456789abcdef0123456789abcdef".parse().unwrap()
    }

    /// What a radio would compute on its side, written independently of the
    /// infrastructure helpers above so the two sides are checked against each other.
    fn ms_response(k: &AuthKey, rs: &Nonce, rand1: &Nonce) -> ([u8; 4], [u8; 10]) {
        let ks = taa1::ta11(&k.0, rs);
        let r = taa1::ta12(&ks, rand1);
        (r.res, r.dck)
    }

    #[test]
    fn ms_authentication_round_trip() {
        let c = MsChallenge::new(&k());
        let (res1, dck1) = ms_response(&k(), &c.rs, &c.rand1);
        assert_eq!(c.verify(&res1), Some(dck1));
        let mut wrong = res1;
        wrong[0] ^= 1;
        assert_eq!(c.verify(&wrong), None);
        // Another subscriber's key does not produce the same response.
        let other: AuthKey = "ffffffffffffffffffffffffffffffff".parse().unwrap();
        let (res_other, _) = ms_response(&other, &c.rs, &c.rand1);
        assert_ne!(res_other, res1);
    }

    #[test]
    fn mutual_authentication_derives_a_combined_dck() {
        let c = MsChallenge::new(&k());
        let (res1, dck1) = ms_response(&k(), &c.rs, &c.rand1);
        assert!(c.verify(&res1).is_some());
        // The MS makes it mutual: sends RAND2, expects RES2 computed with KS'.
        let rand2 = random_nonce();
        let infra = answer_ms_challenge(&k(), &c.rs, &rand2);
        let ksp = taa1::ta21(&k().0, &c.rs);
        let expected = taa1::ta22(&ksp, &rand2);
        assert_eq!(infra.res2, expected.res);
        let dck = derive_dck(Some(&dck1), Some(&infra.dck2));
        assert_eq!(dck.0, taa1::tb4(&dck1, &expected.dck));
        // One-way: the other half is zero, so DCK equals DCK1.
        assert_eq!(derive_dck(Some(&dck1), None).0, dck1);
    }

    #[test]
    fn a_vector_authenticates_exactly_like_k() {
        // The station without K (vector from the authentication centre) must come to the same
        // XRES1 / DCK1 and RES2 / DCK2 as one that holds K.
        let rs = random_nonce();
        let rand1 = random_nonce();
        let rand2 = random_nonce();
        let v = AuthVector::from_k(&k(), rs);
        let with_k = MsChallenge::with_nonces(&k(), rs, rand1);
        let with_v = MsChallenge::from_vector(&v, rand1);
        assert_eq!((with_v.rs, with_v.rand1), (rs, rand1));
        let (res1, dck1) = ms_response(&k(), &rs, &rand1);
        assert_eq!(with_k.verify(&res1), Some(dck1));
        assert_eq!(with_v.verify(&res1), Some(dck1));
        let a = answer_ms_challenge(&k(), &rs, &rand2);
        let b = answer_with_vector(&v, &rand2);
        assert_eq!((a.res2, a.dck2), (b.res2, b.dck2));
        // Matches the reference vector of TA11 / TA21 (taa1 tests).
        let k2: AuthKey = "c62e22850340bceb5552222860173d7e".parse().unwrap();
        let rs2 = [0x56, 0x5a, 0x72, 0xd6, 0x3c, 0xce, 0xed, 0x0b, 0x6f, 0x30];
        let v2 = AuthVector::from_k(&k2, rs2);
        assert_eq!(v2.ks[..4], [0x77, 0xbc, 0x47, 0xf6]);
        assert_eq!(v2.ks_p[..4], [0xfc, 0xfa, 0xf4, 0x55]);
    }

    #[test]
    fn nonces_are_random() {
        assert_ne!(random_nonce(), random_nonce());
    }
}
