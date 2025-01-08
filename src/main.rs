use std::error::Error;
use std::io::{Error as ioError, Read};
use transaction::{Amount, Input, Output, Transaction, Txid};
mod transaction;
use sha2::{Digest, Sha256};

fn read_compact_size(transaction_bytes: &mut &[u8]) -> Result<u64, ioError> {
    let mut compact_size = [0_u8; 1];
    transaction_bytes.read_exact(&mut compact_size)?;

    match compact_size[0] {
        0..=252 => Ok(compact_size[0] as u64),
        253 => {
            let mut buffer = [0; 2];
            transaction_bytes.read_exact(&mut buffer)?;
            Ok(u16::from_le_bytes(buffer) as u64)
        }
        254 => {
            let mut buffer = [0; 4];
            transaction_bytes.read_exact(&mut buffer)?;
            Ok(u32::from_le_bytes(buffer) as u64)
        }
        255 => {
            let mut buffer = [0; 8];
            transaction_bytes.read_exact(&mut buffer)?;
            Ok(u64::from_le_bytes(buffer))
        }
    }
}

fn read_u32(transaction_bytes: &mut &[u8]) -> Result<u32, ioError> {
    let mut buffer = [0; 4];
    transaction_bytes.read_exact(&mut buffer)?;
    Ok(u32::from_le_bytes(buffer))
}

fn read_amount(transaction_bytes: &mut &[u8]) -> Result<Amount, ioError> {
    let mut buffer = [0; 8];
    transaction_bytes.read_exact(&mut buffer)?;
    Ok(Amount::from_sat(u64::from_le_bytes(buffer)))
}

fn read_txid(transaction_bytes: &mut &[u8]) -> Result<Txid, ioError> {
    let mut buffer = [0_u8; 32];
    transaction_bytes.read_exact(&mut buffer)?;
    Ok(Txid::from_bytes(buffer))
}

fn read_script(transaction_bytes: &mut &[u8]) -> Result<String, ioError> {
    let script_size = read_compact_size(transaction_bytes)? as usize;
    let mut buffer = vec![0_u8; script_size];
    transaction_bytes.read_exact(&mut buffer)?;
    Ok(hex::encode(buffer))
}

fn hash_raw_transaction(raw_transaction: &[u8]) -> Txid {
    let mut hasher = Sha256::new();
    hasher.update(&raw_transaction);
    let hash1 = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(hash1);
    let hash2 = hasher.finalize();

    Txid::from_bytes(hash2.into())
}

fn decode(transaction_hex: String) -> Result<String, Box<dyn Error>> {
    let transaction_bytes =
        hex::decode(transaction_hex).map_err(|e| format!("Hex decode error: {}", e))?;
    let mut bytes_slice = transaction_bytes.as_slice();
    let version = read_u32(&mut bytes_slice)?;
    let input_count = read_compact_size(&mut bytes_slice)?;

    let mut inputs = vec![];
    for _ in 0..input_count {
        let txid = read_txid(&mut bytes_slice)?;
        let output_index = read_u32(&mut bytes_slice)?;
        let script_sig = read_script(&mut bytes_slice)?;
        let sequence = read_u32(&mut bytes_slice)?;

        inputs.push(Input {
            txid,
            output_index,
            script_sig,
            sequence,
        })
    }

    let output_count = read_compact_size(&mut bytes_slice)?;
    let mut outputs = vec![];

    for _ in 0..output_count {
        let amount = read_amount(&mut bytes_slice)?;
        let script_pubkey = read_script(&mut bytes_slice)?;

        outputs.push(Output {
            amount,
            script_pubkey,
        });
    }

    let lock_time = read_u32(&mut bytes_slice)?;
    let transaction_id = hash_raw_transaction(&transaction_bytes);

    let transaction = Transaction {
        transaction_id,
        version,
        inputs,
        outputs,
        lock_time,
    };

    Ok(serde_json::to_string_pretty(&transaction)?)
}

fn main() {
    let transaction_hex = "0100000002f544d5a6ee6d25a1cc1c54c01f7c4e4a8b65191ac64f9a0c3c98b5421245642c000000006b483045022100c3a359416a552c4a115bc886870e1b060f05145d6112154de348b75523eb4d9d022066bc22f5dcee84e626e5d42bfa937058ebd6d01a3cf804be3a4b7a986a15d3fa012103e7c50bb4c10bf167e9840b75d924f09f0034f20334f301f6d652c1c059219650ffffffff61070d2983b3a9221b4eedfd46db990d38e0f039d25bb37877e4fa94cdceca52000000006b483045022100fcb0bfa709cb86541698b793eec7560d5da395e01018c9f50adaed06904440db022058fb78aaaddf20e273ee351833d74597848407c203c82455d2fbfcbded21c840012103e7c50bb4c10bf167e9840b75d924f09f0034f20334f301f6d652c1c059219650ffffffff02e0f70300000000001976a9149f21a07a0c7c3cf65a51f586051395762267cdaf88ac915f4000000000001976a9149f21a07a0c7c3cf65a51f586051395762267cdaf88ac00000000";

    match decode(transaction_hex.to_string()) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("{}", e),
    }
}

#[cfg(test)]
mod test {
    use super::read_compact_size;
    use super::Error;

    #[test]
    fn test_read_compact_size() -> Result<(), Box<dyn Error>> {
        let mut bytes = [1_u8].as_slice();
        let count = read_compact_size(&mut bytes)?;
        assert_eq!(count, 1_u64);

        let mut bytes = [253_u8, 0, 1].as_slice();
        let count = read_compact_size(&mut bytes)?;
        assert_eq!(count, 256_u64);

        let mut bytes = [254_u8, 0, 0, 0, 1].as_slice();
        let count = read_compact_size(&mut bytes)?;
        assert_eq!(count, 256_u64.pow(3));

        let mut bytes = [255_u8, 0, 0, 0, 0, 0, 0, 0, 1].as_slice();
        let count = read_compact_size(&mut bytes)?;
        assert_eq!(count, 256_u64.pow(7));

        let hex = "fd204e";
        let decoded = hex::decode(hex)?;
        let mut bytes = decoded.as_slice();
        let count = read_compact_size(&mut bytes)?;
        let expended_count = 20_000_u64;
        assert_eq!(count, expended_count);

        Ok(())
    }
}
