use secp::Point;
use serde::{Deserialize, Serialize};

use crate::serialization;

/// The agent who provides the on-chain capital to facilitate the ticketed DLC.
/// Could be one of the players in the DLC, or could be a neutral 3rd party
/// who wishes to profit by leveraging their capital.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct MarketMaker {
    /// The market maker's pubkey.
    pub pubkey: Point,
}

/// A player in a ticketed DLC. Each player is identified by a public key,
/// but also by their ticket hash. If a player can learn the preimage of
/// their ticket hash (usually by purchasing it via Lightning), they can
/// claim winnings from DLC outcomes.
///
/// Every player must use a public key which is distinct from every other
/// player's key and from the market maker's key, along with a unique ticket
/// hash and a unique payout hash. Signing sessions identify signers by key, so
/// a shared key can never complete a session, and a reused hash would let one
/// revealed preimage unlock another player's spending path. The same person may
/// join a DLC several times using a fresh key and fresh hashes each time.
#[derive(Debug, Clone, Ord, PartialOrd, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct Player {
    /// An ephemeral public key controlled by the player.
    ///
    /// It should be ephemeral because once the player receives an off-chain
    /// payout, they can choose to reveal their secret key to the market
    /// maker, which allows the market maker to use key-spending (instead
    /// of inefficient script spending) to reclaim the on-chain capital.
    pub pubkey: Point,

    /// The ticket hashes used for HTLCs. To buy into the DLC, players must
    /// purchase the preimages of these hashes.
    #[serde(with = "serialization::byte_array")]
    pub ticket_hash: [u8; 32],

    /// A hash used for unlocking the split TX output early. To allow winning
    /// players to receive off-chain payouts, they must provide this `payout_hash`,
    /// for which they know the preimage. By selling the preimage to the market maker,
    /// they allow the market maker to reclaim the on-chain funds.
    #[serde(with = "serialization::byte_array")]
    pub payout_hash: [u8; 32],
}
