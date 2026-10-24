#![no_std]
//! Minimal ERC-8004-style reputation registry — a stand-in for stellar-8004 that
//! the Eunomia demo controls. Exposes the `reputation_of(agent) -> i128` interface the
//! treasury's reputation gate reads. In production the score is earned from settled
//! work (see the Casper trust layer); here the admin sets it for demonstration.
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
    Score(Address),
}

const LEDGERS_PER_WEEK: u32 = 120_960;
const SCORE_TTL_THRESHOLD: u32 = 8 * LEDGERS_PER_WEEK;
const SCORE_TTL_EXTEND_TO: u32 = 17 * LEDGERS_PER_WEEK;

#[contract]
pub struct ReputationOracle;

#[contractimpl]
impl ReputationOracle {
    pub fn __constructor(env: Env, admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    /// Admin sets an agent's reputation score. (Production: earned, not set.)
    pub fn set_score(env: Env, agent: Address, score: i128) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        let key = DataKey::Score(agent);
        env.storage().persistent().set(&key, &score);
        env.storage()
            .persistent()
            .extend_ttl(&key, SCORE_TTL_THRESHOLD, SCORE_TTL_EXTEND_TO);
    }

    pub fn reputation_of(env: Env, agent: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Score(agent))
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::{
        testutils::{storage::Persistent as _, Address as _},
        Env,
    };

    #[test]
    fn set_and_read_score() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let id = env.register(ReputationOracle, (admin,));
        let client = ReputationOracleClient::new(&env, &id);

        let agent = Address::generate(&env);
        assert_eq!(client.reputation_of(&agent), 0);
        client.set_score(&agent, &75_i128);
        assert_eq!(client.reputation_of(&agent), 75);

        let ttl = env.as_contract(&id, || {
            env.storage()
                .persistent()
                .get_ttl(&DataKey::Score(agent.clone()))
        });
        assert!(ttl >= SCORE_TTL_EXTEND_TO - 1);
    }
}
