pub mod safari15_3;
pub mod safari15_5;
pub mod safari15_6_1;
pub mod safari16;
pub mod safari16_5;
pub mod safari17_2_1;
pub mod safari17_4_1;
pub mod safari17_5;
pub mod safari_ios_16_5;
pub mod safari_ios_17_2;
pub mod safari_ios_17_4_1;

const SIGALGS_LIST: [&str; 11] = [
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "ecdsa_sha1",
    "rsa_pss_rsae_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512",
    "rsa_pkcs1_sha1",
];
