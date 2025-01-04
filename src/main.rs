// #[allow(unused)]
// fn read_version(transactionhex: &str) -> u32 {
//     // convert hex to bytes
//     let transaction_bytes = hex::decode(transactionhex);
//     1
// }

// fn main() {
//     let version = reade_version(transcationhex::"0200000000010352db42960f8bb090eaecd9e587a8fbff9c198a91c8808d292be67808a98a57120000000000fdffffff3ed0e9b4811c24b2c7bcc5ea16c89e56055e0e718e2a76f6465225799e634bbe0100000000fdffffff360241047e21041b5e16929a47565f0ddcd711357bbfaff0b48e2dcf362c75ce0000000000fdffffff022470357700000000220020159412197dba355c1b48201ea60ddaa25a65846aa4475221ce2cd4e50a4421dd00c817a8040000002200202122f4719add322f4d727f48379f8a8ba36a40ec4473fd99a2fdcfd89a16e0480500473044022005ebf4766745c8993478681029b560dc6e9f59341b2004700289269cf854463402205de9ef70dc234b6ebd4f962763305f120a2ead7d40a91187cc1b96812344ed2e01483045022100cd6a62472160c4d8b3e9dfc6a29ad05640ccce44dc55578d2f49e3f934a6aa4102201e11385fa50334f840ebbc9e8d43594f6dbdb6d681736582fcd08c5233ca345501483045022100bc5011d8faa3b7393d3208a4dd8059a530a9759e3722623d9431f22bb7ea534e022005a04a5d63e3bcebee05586c59e49d1b8b0f2c9ba7f4b3d6f78ba3ad74d295bd01695321026f41b4081272639c5287bfba1f13a09584c175eb3f93916b4f8a48563412038721027851e48a6605a74375c819357b626c0b885aa62c93f0ed02443b18dfb7b1adcd2103ab69379d0ce823d43f86771791a2b9518baa88e5d99e904c979a98de98db21bc53ae0500473044022006ecc3996e2fc0e8a5ec233300d1779659955b0d64370592d1e1f53a0e33dab7022018c9a5c7c459b47ddfb0f5952ad68b8f1c463f19cd637a4b321619408cfe84f3014730440220519c6f819d144655dcd9ae78e62b31359e427a7ca3e41b40c5ad503248fc146002205310ef6327dd17233e5072824fada07a02345e531e8bb02c9798d10ed2c3725401483045022100f48e68f9214d84cc3150e7c478bed5342a2bbf3897460bd11c12ff5d8e5c19f7022043a2967dcbb777c06927d6ce50feb34f442de1ac63db0037e942d5ae43a897c101695321026f41b4081272639c5287bfba1f13a09584c175eb3f93916b4f8a48563412038721027851e48a6605a74375c819357b626c0b885aa62c93f0ed02443b18dfb7b1adcd2103ab69379d0ce823d43f86771791a2b9518baa88e5d99e904c979a98de98db21bc53ae05004730440220727f988e77e0b8803d542db301e5321b420770dee716390fd732ba1a9919a7c202206ed8c115849ba75f8fc9c82e5c8e7bddaa9ab0f23223aebdb63f5a7ae54b62b401483045022100ac8c63f3d511f46a8e50b85dbb7e67f00931fc834d59c454724f9ea58556be1c0220772ac67fe2c424775f7de90d7518d9d3ddd8ba87eedebd23cdf70d7a4330deae0147304402202a9f9c3d0bfb25f5f7391848ecf6d947158693226fbbef096dc305fb759d490a022048ea44494c5cf2e430238c2883da1875c805dee2ddec0d335c4d3d9add2d8bfc01695321026f41b4081272639c5287bfba1f13a09584c175eb3f93916b4f8a48563412038721027851e48a6605a74375c819357b626c0b885aa62c93f0ed02443b18dfb7b1adcd2103ab69379d0ce823d43f86771791a2b9518baa88e5d99e904c979a98de98db21bc53ae00000000");

//     println!("version: {}", version);
// }

// #[allow(unused)]
// enum Fruit {
//     Banana(String),
//     Apple(String),
//     Orange(String),
// }

// #[allow(unused)]
// fn main() {
//     let fruit = Fruit::Orange("ripe".to_string());

//     match fruit {
//         Fruit::Banana(adj) => println!("{}", adj),
//         Fruit::Apple(adj) => println!("{}", adj),
//         _ => println!("not a banana or apple"),
//     }

// }

// enum Point {
//     Nothing,
//     TuplePoint(i32, i32),
//     StructPoint { x: i32, y: i32 },
// }

// fn get_point(n: u8) -> Point {
//     match n {
//         1 => Point::TuplePoint(-1, 3),
//         2 => Point::StructPoint { x: -1, y: 2 },
//         _ => Point::Nothing,
//     }
// }

// fn main() {
//     let p = get_point(9);
//     match p {
//         Point::Nothing => println!("no point"),
//         Point::TuplePoint(x, y) => println!("x is {} and y is {}", x, y),
//         Point::StructPoint { x, y } => println!("x is {} and y is {}", x, y),
//     }
// }

use std::io::Read;

fn read_compact_size(transaction_bytes: &mut &[u8]) -> u64 {
    let mut compact_size = [0_u8; 1];
    transaction_bytes.read(&mut compact_size).unwrap();

    match compact_size[0] {
        0..=252 => compact_size[0] as u64,
        253 => {
            let mut buffer = [0; 2];
            transaction_bytes.read(&mut buffer).unwrap();
            u16::from_le_bytes(buffer) as u64
        }
        254 => {
            let mut buffer = [0; 4];
            transaction_bytes.read(&mut buffer).unwrap();
            u32::from_le_bytes(buffer) as u64
        }
        255 => {
            let mut buffer = [0; 8];
            transaction_bytes.read(&mut buffer).unwrap();
            u64::from_le_bytes(buffer)
        }
    }
}

fn read_version(transaction_bytes: &mut &[u8]) -> u32 {
    let mut buffer = [0; 4];
    transaction_bytes.read(&mut buffer).unwrap();
    u32::from_le_bytes(buffer)
}

fn main() {
    let transaction_hex = "0200000000010352db42960f8bb090eaecd9e587a8fbff9c198a91c8808d292be67808a98a57120000000000fdffffff3ed0e9b4811c24b2c7bcc5ea16c89e56055e0e718e2a76f6465225799e634bbe0100000000fdffffff360241047e21041b5e16929a47565f0ddcd711357bbfaff0b48e2dcf362c75ce0000000000fdffffff022470357700000000220020159412197dba355c1b48201ea60ddaa25a65846aa4475221ce2cd4e50a4421dd00c817a8040000002200202122f4719add322f4d727f48379f8a8ba36a40ec4473fd99a2fdcfd89a16e0480500473044022005ebf4766745c8993478681029b560dc6e9f59341b2004700289269cf854463402205de9ef70dc234b6ebd4f962763305f120a2ead7d40a91187cc1b96812344ed2e01483045022100cd6a62472160c4d8b3e9dfc6a29ad05640ccce44dc55578d2f49e3f934a6aa4102201e11385fa50334f840ebbc9e8d43594f6dbdb6d681736582fcd08c5233ca345501483045022100bc5011d8faa3b7393d3208a4dd8059a530a9759e3722623d9431f22bb7ea534e022005a04a5d63e3bcebee05586c59e49d1b8b0f2c9ba7f4b3d6f78ba3ad74d295bd01695321026f41b4081272639c5287bfba1f13a09584c175eb3f93916b4f8a48563412038721027851e48a6605a74375c819357b626c0b885aa62c93f0ed02443b18dfb7b1adcd2103ab69379d0ce823d43f86771791a2b9518baa88e5d99e904c979a98de98db21bc53ae0500473044022006ecc3996e2fc0e8a5ec233300d1779659955b0d64370592d1e1f53a0e33dab7022018c9a5c7c459b47ddfb0f5952ad68b8f1c463f19cd637a4b321619408cfe84f3014730440220519c6f819d144655dcd9ae78e62b31359e427a7ca3e41b40c5ad503248fc146002205310ef6327dd17233e5072824fada07a02345e531e8bb02c9798d10ed2c3725401483045022100f48e68f9214d84cc3150e7c478bed5342a2bbf3897460bd11c12ff5d8e5c19f7022043a2967dcbb777c06927d6ce50feb34f442de1ac63db0037e942d5ae43a897c101695321026f41b4081272639c5287bfba1f13a09584c175eb3f93916b4f8a48563412038721027851e48a6605a74375c819357b626c0b885aa62c93f0ed02443b18dfb7b1adcd2103ab69379d0ce823d43f86771791a2b9518baa88e5d99e904c979a98de98db21bc53ae05004730440220727f988e77e0b8803d542db301e5321b420770dee716390fd732ba1a9919a7c202206ed8c115849ba75f8fc9c82e5c8e7bddaa9ab0f23223aebdb63f5a7ae54b62b401483045022100ac8c63f3d511f46a8e50b85dbb7e67f00931fc834d59c454724f9ea58556be1c0220772ac67fe2c424775f7de90d7518d9d3ddd8ba87eedebd23cdf70d7a4330deae0147304402202a9f9c3d0bfb25f5f7391848ecf6d947158693226fbbef096dc305fb759d490a022048ea44494c5cf2e430238c2883da1875c805dee2ddec0d335c4d3d9add2d8bfc01695321026f41b4081272639c5287bfba1f13a09584c175eb3f93916b4f8a48563412038721027851e48a6605a74375c819357b626c0b885aa62c93f0ed02443b18dfb7b1adcd2103ab69379d0ce823d43f86771791a2b9518baa88e5d99e904c979a98de98db21bc53ae00000000";
    let transaction_bytes = hex::decode(transaction_hex).unwrap();
    let mut bytes_slice = transaction_bytes.as_slice();
    let version = read_version(&mut bytes_slice);
    let input_length = read_compact_size(&mut bytes_slice);

    println!("version: {}", version);
    println!("Input length: {}", input_length);
}

#[cfg(test)]
mod test {
    use super::read_compact_size;

    #[test]
    fn test_read_compact_size() {
        let mut bytes = [1_u8].as_slice();
        let count = read_compact_size(&mut bytes);
        assert_eq!(count, 1_u64);

        let mut bytes = [253_u8, 0, 1].as_slice();
        let count = read_compact_size(&mut bytes);
        assert_eq!(count, 256_u64);

        let mut bytes = [254_u8, 0, 0, 0, 1].as_slice();
        let count = read_compact_size(&mut bytes);
        assert_eq!(count, 256_u64.pow(3));

        let mut bytes = [255_u8, 0, 0, 0, 0, 0, 0, 0, 1].as_slice();
        let count = read_compact_size(&mut bytes);
        assert_eq!(count, 256_u64.pow(7));

        let hex = "fd204e";
        let decoded = hex::decode(hex).unwrap();
        let mut bytes = decoded.as_slice();
        let count = read_compact_size(&mut bytes);
        let expended_count = 20_000_u64;
        assert_eq!(count, expended_count);
    }
}
