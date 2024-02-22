use anyhow::Result;
use bonsai_sdk::alpha as bonsai_sdk;
use chess_core::{ChessMove, ChessMoveResult};
use chess_methods::{CHESS_ID, CHESS_ELF};
use cozy_chess::Board;
use k256::ecdsa::{signature::Signer, Signature, SigningKey};
use rand_core::OsRng;
use risc0_zkvm::{compute_image_id, serde::to_vec, Receipt};
use sha2::{Digest as _, Sha256};
use std::time::Duration;

fn main() {
    let whites_sigkey = SigningKey::random(&mut OsRng);
    let whites_pubkey = whites_sigkey.verifying_key().to_encoded_point(true);
    let whites_pubkey_bytes = whites_pubkey.as_bytes();
    let blacks_sigkey = SigningKey::random(&mut OsRng);
    let blacks_pubkey = blacks_sigkey.verifying_key().to_encoded_point(true);
    let blacks_pubkey_bytes = blacks_pubkey.as_bytes();
    let nonce: u128 = 1;

    let match_id_parts = [
        whites_pubkey_bytes,
        blacks_pubkey_bytes,
        &nonce.to_le_bytes(),
    ]
    .concat();
    let match_id_digest = Sha256::digest(&match_id_parts);

    let board_initial_state = Board::default().to_string();
    let whites_move = r"e2e4".to_string();

    let whites_sig_parts = [
        match_id_digest.as_slice(),
        board_initial_state.as_bytes(),
        whites_move.as_bytes(),
    ]
    .concat();
    let whites_sig: Signature = whites_sigkey.sign(&whites_sig_parts);

    let whites_move_1 = ChessMove {
        image_id: CHESS_ID.clone(),
        match_id: match_id_digest.try_into().unwrap(),
        nonce: nonce.to_le_bytes().try_into().unwrap(),
        whites_pubkey: whites_pubkey_bytes.to_vec(),
        blacks_pubkey: blacks_pubkey_bytes.to_vec(),
        board_state: board_initial_state,
        player_move: whites_move.clone(),
        player_sig: whites_sig.to_vec(),
    };

    let (receipt, move_result) = run_bonsai(whites_move_1, None).expect("zk program failed executing with Bonsai SDK");


    let blacks_move = r"e7e5".to_string();

    let blacks_sig_parts = [
        match_id_digest.as_slice(),
        move_result.board_state.clone().as_bytes(),
        blacks_move.as_bytes(),
    ]
    .concat();
    let blacks_sig: Signature = blacks_sigkey.sign(&blacks_sig_parts);

    let blacks_move_1 = ChessMove {
        image_id: CHESS_ID.clone(),
        match_id: match_id_digest.try_into().unwrap(),
        nonce: nonce.to_le_bytes().try_into().unwrap(),
        whites_pubkey: whites_pubkey_bytes.to_vec(),
        blacks_pubkey: blacks_pubkey_bytes.to_vec(),
        board_state: move_result.board_state,
        player_move: blacks_move,
        player_sig: blacks_sig.to_vec(),
    };

    let _ = run_bonsai(blacks_move_1, Some(receipt)).expect("zk program failed executing with Bonsai SDK");
}

fn run_bonsai(input: ChessMove, prev_rcpt: Option<Receipt>) -> Result<(Receipt,ChessMoveResult)> {
    let client = bonsai_sdk::Client::from_env(risc0_zkvm::VERSION)?;

    // Compute the image_id, then upload the ELF with the image_id as its key.
    let image_id = hex::encode(compute_image_id(CHESS_ELF)?);
    client.upload_img(&image_id, CHESS_ELF.to_vec())?;

    // Prepare input data and upload it.
    let input_data = to_vec(&input).unwrap();
    let input_data = bytemuck::cast_slice(&input_data).to_vec();
    let input_id = client.upload_input(input_data)?;

    // Add a list of assumptions
    let assumptions = if prev_rcpt.is_some() {
        vec![client.upload_receipt(bincode::serialize(&prev_rcpt.unwrap())?)?]
    } else {
        vec![]
    };

    // Start a session running the prover
    let session = client.create_session(image_id, input_id, assumptions)?;
    let mut result: Option<(Receipt,ChessMoveResult)> = None;
    loop {
        let res = session.status(&client)?;
        if res.status == "RUNNING" {
            eprintln!(
                "Current status: {} - state: {} - continue polling...",
                res.status,
                res.state.unwrap_or_default()
            );
            std::thread::sleep(Duration::from_secs(15));
            continue;
        }
        if res.status == "SUCCEEDED" {
            // Download the receipt, containing the output
            let receipt_url = res
                .receipt_url
                .expect("API error, missing receipt on completed session");

            let receipt_buf = client.download(&receipt_url)?;
            let receipt: Receipt = bincode::deserialize(&receipt_buf)?;
            receipt
                .verify(CHESS_ID)
                .expect("Receipt verification failed");
            
            result = Some((receipt.clone(), receipt.journal.decode().unwrap()));
        } else {
            panic!(
                "Workflow exited: {} - | err: {}",
                res.status,
                res.error_msg.unwrap_or_default()
            );
        }

        break;
    }

    // Optionally run stark2snark
    // run_stark2snark(session.uuid)?;

    Ok(result.unwrap())
}

fn run_stark2snark(session_id: String) -> Result<()> {
    let client = bonsai_sdk::Client::from_env(risc0_zkvm::VERSION)?;

    let snark_session = client.create_snark(session_id)?;
    eprintln!("Created snark session: {}", snark_session.uuid);
    loop {
        let res = snark_session.status(&client)?;
        match res.status.as_str() {
            "RUNNING" => {
                eprintln!("Current status: {} - continue polling...", res.status,);
                std::thread::sleep(Duration::from_secs(15));
                continue;
            }
            "SUCCEEDED" => {
                let snark_receipt = res.output;
                eprintln!("Snark proof!: {snark_receipt:?}");
                break;
            }
            _ => {
                panic!(
                    "Workflow exited: {} err: {}",
                    res.status,
                    res.error_msg.unwrap_or_default()
                );
            }
        }
    }
    Ok(())
}