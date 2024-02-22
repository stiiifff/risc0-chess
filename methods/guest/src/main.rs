#![no_main]
#![no_std]

extern crate alloc;

use alloc::{format, string::ToString};

use chess_core::{ChessMove, ChessMoveResult, MatchState, NextMove};
use core::str::FromStr;
use cozy_chess::{Board, Color, GameStatus, Move};
use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use risc0_zkvm::{
    guest::env,
    sha::{Digest, Impl, Sha256},
};

risc0_zkvm::guest::entry!(main);

pub fn main() {
    let inputs: ChessMove = env::read();

    // Verify provided match ID correlates with provided player pub keys & nonce
    // env::log(&format!("Match ID: {}", hex::encode(&inputs.match_id)));
    let match_id_digest = Digest::try_from(inputs.match_id).unwrap();

    let match_id_parts = [
        inputs.whites_pubkey.as_slice(),
        inputs.blacks_pubkey.as_slice(),
        inputs.nonce.as_slice(),
    ]
    .concat();

    let expected_digest = Impl::hash_bytes(&match_id_parts);
    if match_id_digest != *expected_digest {
        env::log(&format!(
            "Match ID verification failed: expected digest {} but received {}",
            hex::encode(*expected_digest),
            hex::encode(inputs.match_id)
        ));
        panic!("Provided Match ID does not match provided players' pub keys & nonce")
    }

    let mut board = Board::from_str(&inputs.board_state).expect("Invalid board encoding");

    // Check whose turn it is (supposedly) to play, and pick pub key to use for signature verification
    let player_pubkey = match board.side_to_move() {
        Color::White => inputs.whites_pubkey,
        Color::Black => inputs.blacks_pubkey,
    };

    // Verify provided signature for message {match ID, board state, player move}
    let verifying_key = VerifyingKey::try_from(player_pubkey.as_slice()).unwrap();
    let signature = Signature::try_from(inputs.player_sig.as_slice()).unwrap();
    let message_parts = [
        inputs.match_id.as_slice(),
        inputs.board_state.as_bytes(),
        inputs.player_move.as_bytes(),
    ]
    .concat();

    // Verify ECDSA signature
    verifying_key
        .verify(&message_parts, &signature)
        .expect("ECDSA signature verification failed");

    // Signature was validated, so the player performing the move is the correct one,
    // as one of the two players playing the game, and whose turn it is to play based
    // on the current board state.

    // Play the requested move. This could panick if it's an invalid move based on current board state.
    let mv: Move = Move::from_str(&inputs.player_move).expect("Invalid move encoding");
    board.play(mv);

    // Move was succesfully played. Publish updated board state & match status to the journal.

    let result = ChessMoveResult {
        board_state: board.to_string(),
        match_state: match board.status() {
            GameStatus::Ongoing => match board.side_to_move() {
                Color::White => MatchState::OnGoing(NextMove::Whites),
                Color::Black => MatchState::OnGoing(NextMove::Blacks),
            },
            GameStatus::Won => MatchState::Won,
            GameStatus::Drawn => MatchState::Drawn,
        },
    };
    env::log(&format!("Execution cycles: {}", env::cycle_count()));
    env::commit(&result);
}
