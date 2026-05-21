use base64::{Engine, engine::general_purpose::STANDARD};
use num_bigint::Sign;
use simple_asn1::{ASN1Block, BigInt, from_der};
use std::fs;
use std::path::Path;

#[derive(Debug)]
pub struct RsaKey {
    pub n: BigInt,    // modulus
    pub e: BigInt,    // public exponent
    pub d: BigInt,    // private exponent
    pub p: BigInt,    // prime factor 1
    pub q: BigInt,    // prime factor 2
    pub dp: BigInt,   // d mod (p-1)
    pub dq: BigInt,   // d mod (q-1)
    pub qinv: BigInt, // q^-1 mod p
}

fn pem_to_der(pem: &str) -> Vec<u8> {
    let body: String = pem
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.starts_with("-----"))
        .collect();
    let clean = body.replace(['\n', '\r', ' ', '\t'], "");
    STANDARD.decode(clean).expect("Invalid base64")
}

pub fn parse_rsa_key_from_pem(pem: &str) -> std::io::Result<RsaKey> {
    let der = pem_to_der(pem);
    let blocks = from_der(&der).expect("Invalid DER encoding");

    let outer_seq = match &blocks[0] {
        ASN1Block::Sequence(_, items) => items,
        _ => panic!("Expected outer SEQUENCE"),
    };

    let inner_der = match &outer_seq[2] {
        ASN1Block::OctetString(_, bytes) => bytes,
        _ => panic!("Expected OCTET STRING"),
    };

    let inner_blocks = from_der(inner_der).expect("Invalid inner DER encoding");
    let inner_seq = match &inner_blocks[0] {
        ASN1Block::Sequence(_, items) => items,
        _ => panic!("Expected inner SEQUENCE"),
    };

    let ints: Vec<Vec<u8>> = inner_seq
        .iter()
        .filter_map(|b| match b {
            ASN1Block::Integer(_, n) => Some(n.to_bytes_be().1),
            _ => None,
        })
        .collect();

    if ints.len() < 9 {
        panic!("Expected 9 integers, got {}", ints.len());
    }

    Ok(RsaKey {
        n: BigInt::from_bytes_be(Sign::Plus, &ints[1]), // modulus
        e: BigInt::from_bytes_be(Sign::Plus, &ints[2]), // public exponent
        d: BigInt::from_bytes_be(Sign::Plus, &ints[3]), // private exponent
        p: BigInt::from_bytes_be(Sign::Plus, &ints[4]), // prime factor 1
        q: BigInt::from_bytes_be(Sign::Plus, &ints[5]), // prime factor 2
        dp: BigInt::from_bytes_be(Sign::Plus, &ints[6]), // d mod (p-1)
        dq: BigInt::from_bytes_be(Sign::Plus, &ints[7]), // d mod (q-1)
        qinv: BigInt::from_bytes_be(Sign::Plus, &ints[8]), // q^-1 mod p
    })
}

pub fn load_rsa_key<P: AsRef<Path>>(path: P) -> std::io::Result<RsaKey> {
    parse_rsa_key_from_pem(&fs::read_to_string(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigInt;

    const PEM_512: &str = "\
-----BEGIN PRIVATE KEY-----
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAzLUczq12qOSGm+Pv
HSiJ+BPm/Z7vKITVMcUbipwycMcYZF8TjWiiShYLuVtWLA5mEE86FKvrmaf79/tG
RTB6LQIDAQABAkEAu3ZgGyTfNWuRmdDyeFFXh8cyEbAqc4CxfBJ1VkoUJxGJDM+z
m9DXk/vYvL5G+PbNOOHIE2VKNkWbdgX3OQ8GQQIhAOWUQkJEfVYNX8whrjFEzd9j
SprujROHi4IKxzI1o4mrAiEA5EQY/mqL8LIEM7+1UXBN8dPJlSmcxcyRGwL39pTh
o4cCIB0xw1NF/mJJBRuiVNJzG3MC32PgXhRTskvxLu+VnpxNAiBm59BAufXWj9pX
HgD28uMgtzK0fSsA/QUZoU/6KQpD9wIgGDW/g+ztlu98aA9+zzaKbU77J/pDsAdN
Az5KOlJPE6c=
-----END PRIVATE KEY-----";

    const PEM_1024: &str = "\
-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALo81vSeR9KcXane
KwJtS1QAAntAXSkLUQK9Aq/xZrEuI66lWwsUD+A1jutCy0ss/02PxqFIGjX3ByHl
9HOwkb+qThrYu8aThVTroR3NWXudGYvofkR7OZGRDlIPju06von9pzvsqfaTy6Rk
ThdSdK33DsTJ5bjeUxEwblJKUFTjAgMBAAECgYA7iW2Sf/MoAjLzNgH74aK+NM6W
RkpB78szG+d7Bao1pDFmCJilXwGARL7uuMiyvKzVR8xRDPLMI6+VB6VxQpYk6tbq
XEQ1MwfaPGIjP69fs5g0x4QtkGcjIqEt0lQEYkcDkOtrfBt6CnkGyT+HtKFG2s4a
W9MTs65vsXbWh4NLqQJBAOgtyqizfLgw+/2fvhE9wpamcNw4uNPWFeA/nHibZItG
iBzHP5SeN7ifi5H+uhvg4R3bqivuvjW1fU/ujBCitcUCQQDNWGVcZH/fvWpKPe+N
7/Y7AS734PIUGsYLyUQw9h2bWfmYQfb/bytsJlORKq7raydnAGGGU/JtDvo8ky2b
GjKHAkAT7mppVQ8t2LapLR9p531e5Wbm4M+tD8HNAGj0SZK2ChYBMnGY1oQ+CyQ2
IkHjxshMgeD36ITXo37gb8ACZZVpAkEAgaulbl/EZFxvh2xvHvl+SypnJ370P3/c
ukqhdi2k6po5xE07lXf1OrlFIjGK/fzPh/q0myfducKwgJoMPZqgdwJAUKvzw/uz
97Vl50Ot+Ir42/o9tvn/1VpSlAHhjtg8rC1XProY3UAaCDaDSnjws43d4a8AI+zt
Eu7k9eTFIs8d5w==
-----END PRIVATE KEY-----";

    const PEM_2048: &str = "\
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDAFhkfShNkFq3c
pQgsD/Ck9p30cvGY9l/6jRfCuxnaHZhNoEXzbqksFfQrf8KyjsEDlBDPueQkD5X5
IaT0a6QQDI84k2PCuH1BP41UPTfRcCQfVeTt46Pnj99nemo526HDBEaD7iy3pe85
TqKvE+1Y2qve40FajUndGGrylPpmvT7EIghmj9RJRgJ22Zy/2Xh7PdNZxF8fixuA
IvfaBP9AbdepfQF1OeApv0si8tGTQxv5BM7Xuiy/SG19iLCkK9sEn0vqlylrYNXx
2K7efpbHwh+dxdFaXI8GVpQWzvowL2rIvZWg6zRo19u2DjEWIzncQ8uLygT94cfJ
0sND6VNjAgMBAAECggEAUxycpR2zkzB+7MPZa9s/x9jPUngzkfg0YiAPYln7XxVE
E35gFerRNvqOyg1/LCw5VneH6KFplbLKtN96VKmIdMtCYvvfA984jvVVDNhqIOxR
LN/I7Kd9AVIOm2LruHoQHWXprubsoU+iWRztpixMm5AOIqQY4HnWtlv81lZgm/fQ
OwTAdTIlDNVchw7N71L6MM4TPOitkQswigrZD08oNy5ymoN34JhX55KxZvH+VK6i
RKAFewgKwkZfK4inl/708hudL2ysdjUt48Y/s0vvYSaiUc7BB2NYgHJSttGJUIZN
QWprn6u2TmES7Ns+jh5GBuuugj6QB3DLI9c0l5oRKQKBgQD3M00pjXE+ruWXDHDM
1J/1y5b14LiLvf6MO81dtnhbuQA8KtKjyfi+vk9oanIv+xSRcPSkc85n2FHdEUXP
DJ80lsVFQeJEJ1WaaNBDpjH/3cAr5xEmAywWnPTAiZh4Angcpc/D5aquW1ttMEqL
WCbyG1sqraHr06ZPQfO8okOHywKBgQDG7Iz+t5WY3ef+NdLHAdOqnloYjBByvojE
ZOPan7MC/wKqKTYNHxEm1lFQFWaPhgSZEGi6e/5i+BQxut+WKZR4BBpIt0UZdQz1
5PZ+f6VClD4JnIYtUZRiHVUkBUgqeMutvp0eT1V39rt3ZKAyE+fZS5f28fH2521n
Sm256NJ/yQKBgB3nXtY//gsPLUbwglTFA/TABCsKXEjLWxerxFQp1rWB071zkLev
nx+z9fczqUyUmxBdEbszJyz4xi5wAHnjlP7Pnl2acry75WcgdtE4MaQ6Nx0YfsKS
b6rsoc8I1iDua4lLpa6VAejFtHGo/duNdmijVov7JTNaDyxXVhzjpDexAoGBAITI
9Jk3LOn8/taHUSq8gnF7AMMwA+7EVwFaI2sVfWY7majCl60MluNo3qBpmKunlzwh
YvdQu4+O79P+XS+ck9nFS1JM3BhRNRSTASORy1v1HrBFxp9LvJP95o6D5BdNyRAy
lCjeZjwM/DiHeBPVi8dWGZujB5R8CWCQo0wdKR5ZAoGBALO4i+kgMdq+AGOdhiXG
xNmGdirgGB/zRHUGeF0OIJAHqJ+crecUoGCmJEA9FDA7l7/T2cGGMiYAHpXr/kFX
o+QHndhr8IJVcSpl29XtwlgasyjUiT/B++wVj5IzUXqDM2L27Fkd+3A2oHbCW9Tg
j1rxrCfYFDCy1LPnfG/lHfER
-----END PRIVATE KEY-----";

    const PEM_4096: &str = "\
-----BEGIN PRIVATE KEY-----
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
LOGOoj3Ev6V5r1LqrSryKdC6YDpW4nJY
-----END PRIVATE KEY-----";

    fn assert_key_valid(key: &RsaKey) {
        assert_eq!(key.n.sign(), Sign::Plus);
        assert_eq!(key.e.sign(), Sign::Plus);
        assert_eq!(key.d.sign(), Sign::Plus);
        assert_eq!(key.p.sign(), Sign::Plus);
        assert_eq!(key.q.sign(), Sign::Plus);
        assert_eq!(key.dp.sign(), Sign::Plus);
        assert_eq!(key.dq.sign(), Sign::Plus);
        assert_eq!(key.qinv.sign(), Sign::Plus);

        assert_eq!(key.e, BigInt::from(65537));
        assert_eq!(key.n, &key.p * &key.q);

        let p_minus_1 = &key.p - BigInt::from(1);
        let q_minus_1 = &key.q - BigInt::from(1);
        assert_eq!(key.dp, &key.d % &p_minus_1);
        assert_eq!(key.dq, &key.d % &q_minus_1);
    }

    #[test]
    fn test_parse_512_bit_key() {
        let key = parse_rsa_key_from_pem(PEM_512).unwrap();
        assert_key_valid(&key);
    }

    #[test]
    fn test_parse_1024_bit_key() {
        let key = parse_rsa_key_from_pem(PEM_1024).unwrap();
        assert_key_valid(&key);
    }

    #[test]
    fn test_parse_2048_bit_key() {
        let key = parse_rsa_key_from_pem(PEM_2048).unwrap();
        assert_key_valid(&key);
    }

    #[test]
    fn test_parse_4096_bit_key() {
        let key = parse_rsa_key_from_pem(PEM_4096).unwrap();
        assert_key_valid(&key);
    }

    #[test]
    #[should_panic(expected = "Invalid base64")]
    fn test_invalid_pem_body() {
        let bad_pem = "\
-----BEGIN PRIVATE KEY-----
not-valid-base64!!!
-----END PRIVATE KEY-----";
        let _ = parse_rsa_key_from_pem(bad_pem);
    }

    #[test]
    fn test_load_rsa_key_file_not_found() {
        let result = load_rsa_key("nonexistent_key.pem");
        assert!(result.is_err());
    }

    #[test]
    fn test_pem_with_extra_whitespace() {
        let spaced_pem = PEM_512.replace('\n', "\n  \n");
        let key = parse_rsa_key_from_pem(&spaced_pem).unwrap();
        assert_eq!(key.e, BigInt::from(65537));
    }
}
