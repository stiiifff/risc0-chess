use chess_core::ChessMove;
use chess_methods::CHESS_ID;
use cozy_chess::Board;
use host::play_chess;
use k256::ecdsa::{signature::Signer, Signature, SigningKey};
use rand_core::OsRng;
use sha2::{Digest as _, Sha256};

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
    let player_move = r"e2e4".to_string();

    let player_sig_parts = [
        match_id_digest.as_slice(),
        board_initial_state.as_bytes(),
        player_move.as_bytes(),
    ]
    .concat();
    let player_sig: Signature = whites_sigkey.sign(&player_sig_parts);

    let chess_move = ChessMove {
        image_id: CHESS_ID.clone(),
        match_id: match_id_digest.try_into().unwrap(),
        nonce: nonce.to_le_bytes().try_into().unwrap(),
        whites_pubkey: whites_pubkey_bytes.to_vec(),
        blacks_pubkey: blacks_pubkey_bytes.to_vec(),
        board_state: board_initial_state,
        player_move: player_move,
        player_sig: player_sig.to_vec(),
    };

    println!("Chess move: {:?}", &chess_move);

    let (receipt, result) = play_chess(&chess_move, None);

    // Verify receipt, panic if it's wrong
    receipt.verify(CHESS_ID).expect(
        "Code you have proven should successfully verify; did you specify the correct image ID?",
    );

    // Report the product
    println!("Chess move was performed successfully ! {:?}", result);

    let receipt_bytes = bincode::serialize(&receipt).unwrap();
    println!("zk Proof: {} bytes", receipt_bytes.len());
}
