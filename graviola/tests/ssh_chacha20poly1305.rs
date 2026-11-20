// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use graviola::aead::SshChaCha20Poly1305;

#[test]
fn openssh_vector_and_authentication_failure() {
    let key: [u8; 64] = hex::decode("aeb9910ce0ce442e85d3ff47f89be87938bfb1cfc77ed52002e8d3c27f2c1e217ae436b0b31da1ff88ed4988ab411467f87d2e2ee9f38e10fe9b3bebada9ddd8").unwrap().try_into().unwrap();
    let plain = hex::decode("1626bc7414052b5f").unwrap();
    let expected = hex::decode("67a2cbbe26445830ea959911b2eaa2754d27523769f6a105").unwrap();
    let cipher = SshChaCha20Poly1305::new(&key);
    let mut packet = plain.clone();
    let mut tag = [0; 16];
    cipher.seal(0, &mut packet, &mut tag).unwrap();
    assert_eq!(packet, expected[..8]);
    assert_eq!(tag, expected[8..]);
    assert_eq!(
        cipher.decrypt_length(0, packet[..4].try_into().unwrap()),
        plain[..4]
    );
    let mut bad_tag = tag;
    bad_tag[0] ^= 1;
    let sealed = packet.clone();
    assert!(cipher.open(0, &mut packet, &bad_tag).is_err());
    assert_eq!(packet, sealed);
    cipher.open(0, &mut packet, &tag).unwrap();
    assert_eq!(packet, plain);
}
