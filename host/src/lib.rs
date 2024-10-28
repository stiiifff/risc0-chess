use chess_core::{ChessMove, ChessMoveResult};
use chess_methods::CHESS_ELF;
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};

pub fn play_chess(
    chess_move: &ChessMove,
    prev_rcpt: Option<Receipt>,
) -> (Receipt, ChessMoveResult) {
    let mut env_builder = ExecutorEnv::builder();
    if prev_rcpt.is_some() {
        env_builder.add_assumption(prev_rcpt.unwrap());
    }

    let env = env_builder.write(chess_move).unwrap().build().unwrap();

    // Obtain the default prover.
    let prover = default_prover();

    // Produce a receipt by proving the specified ELF binary.
    let prove_info = prover.prove(env, CHESS_ELF).unwrap();

    let receipt = prove_info.receipt;

    // Extract journal of receipt (i.e. output result, where result = a * b)
    let result: ChessMoveResult = receipt.journal.decode().expect(
        "Journal output should deserialize into the same types (& order) that it was written",
    );

    (receipt, result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chess_core::{MatchState, NextMove};
    use chess_methods::CHESS_ID;
    use cozy_chess::Board;
    use k256::ecdsa::{signature::Signer, Signature, SigningKey};
    use rand_core::OsRng;
    use sha2::{Digest as _, Sha256};

    #[test]
    fn test_chess_move() {
        let whites_sigkey = SigningKey::random(&mut OsRng);
        let whites_pubkey = whites_sigkey.verifying_key().to_encoded_point(true);
        let whites_pubkey_bytes = whites_pubkey.as_bytes();
        println!("Whites pubkey: {}", hex::encode(whites_pubkey));
        let blacks_sigkey = SigningKey::random(&mut OsRng);
        let blacks_pubkey = blacks_sigkey.verifying_key().to_encoded_point(true);
        let blacks_pubkey_bytes = blacks_pubkey.as_bytes();
        println!("Blacks pubkey: {}", hex::encode(blacks_pubkey));
        let nonce: u128 = 1;

        let match_id_parts = [
            whites_pubkey_bytes,
            blacks_pubkey_bytes,
            &nonce.to_le_bytes(),
        ]
        .concat();
        let match_id_digest = Sha256::digest(&match_id_parts);
        println!("Match ID: {}", hex::encode(match_id_digest));

        let board_initial_state = Board::default().to_string();

        // Whites move 1
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

        let (receipt, move1_result) = play_chess(&whites_move_1, None);

        assert_eq!(
            move1_result.match_state,
            MatchState::OnGoing(NextMove::Blacks),
            "zkVM output should have the correct board match state."
        );

        assert_eq!(
            move1_result.board_state, "rnbqkbnr/pppppppp/8/8/4P3/8/PPPP1PPP/RNBQKBNR b KQkq e3 0 1",
            "zkVM output should have the correct board state."
        );

        // Blacks move 1
        let blacks_move = r"e7e5".to_string();

        let blacks_sig_parts = [
            match_id_digest.as_slice(),
            move1_result.board_state.clone().as_bytes(),
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
            board_state: move1_result.board_state,
            player_move: blacks_move,
            player_sig: blacks_sig.to_vec(),
        };

        let (_, move2_result) = play_chess(&blacks_move_1, Some(receipt));

        assert_eq!(
            move2_result.match_state,
            MatchState::OnGoing(NextMove::Whites),
            "zkVM output should have the correct board match state."
        );

        // assert_eq!(
        //     result.board_state, "rnbqkbnr/pppppppp/8/8/4P3/8/PPPP1PPP/RNBQKBNR b KQkq e3 0 1",
        //     "zkVM output should have the correct board state."
        // );

    }
}
