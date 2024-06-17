pub mod okhttp3_11;
pub mod okhttp3_13;
pub mod okhttp3_14;
pub mod okhttp3_9;
pub mod okhttp4_10;
pub mod okhttp4_9;
pub mod okhttp5;

const SIGALGS_LIST: [&str; 9] = [
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512",
    "rsa_pkcs1_sha1",
];
