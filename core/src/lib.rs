use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChessMove {
    // Match ID is SHA256 of {whites pub key, blacks pub key, nonce}
    pub match_id: [u8; 32],
    pub nonce: [u8; 16],
    #[serde(with = "serde_bytes")]
    pub whites_pubkey: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub blacks_pubkey: Vec<u8>,
    pub board_state: String,
    pub player_move: String,
    // ECDSA signature of {match ID, board state, player move}
    // by player whose turn it is to play at current board state.
    #[serde(with = "serde_bytes")]
    pub player_sig: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum NextMove {
    Whites,
    Blacks,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum MatchState {
    OnGoing(NextMove),
    Won,
    Drawn,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChessMoveResult {
    pub board_state: String,
    pub match_state: MatchState,
}
