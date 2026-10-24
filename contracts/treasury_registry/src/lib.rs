#![no_std]
//! Eunomia Treasury Registry — a permissionless on-chain index of "which treasuries
//! does this wallet own?", so a user can recover their treasury from any device
//! instead of relying on one browser's localStorage.
//!
//! Deliberately minimal: no admin, no constructor. Only the owner can change their own
//! list (`owner.require_auth`) and pays their own storage rent, so no cap is needed.
//!
//! An entry is a claim the app acts on — it adopts the treasuries listed under a wallet —
//! so `register` checks the claim instead of storing it as given (review H2): the treasury
//! must name `owner` as its admin. Otherwise one signature on a zero-value "back up your
//! treasury" call could list an attacker-administered treasury under a victim, who would
//! then fund it. The check reads what the contract at `treasury` says about itself, so it
//! stops a real treasury run by someone else, not a contract written to lie; the app
//! checks the code it adopts for that. `unregister` lets an owner drop an entry.
use soroban_sdk::{
    contract, contractclient, contractimpl, contracttype, symbol_short, Address, Env, Vec,
};

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Owned(Address),
}

/// The treasury's `Config`, mirrored for the one field read here (same field names and
/// order = same XDR map).
#[contracttype]
#[derive(Clone)]
pub struct Config {
    pub admin: Address,
    pub agent: Address,
    pub token: Address,
    pub daily_limit: i128,
    pub per_task_limit: i128,
}

#[contractclient(name = "TreasuryClient")]
pub trait TreasuryApi {
    fn get_config(env: Env) -> Config;
}

const LEDGERS_PER_WEEK: u32 = 120_960;
const OWNED_TTL_THRESHOLD: u32 = 8 * LEDGERS_PER_WEEK;
const OWNED_TTL_EXTEND_TO: u32 = 17 * LEDGERS_PER_WEEK;

#[contract]
pub struct TreasuryRegistry;

#[contractimpl]
impl TreasuryRegistry {
    /// Record that `owner` operates `treasury`. Owner-signed; duplicates are a no-op.
    /// Refused unless the treasury's admin is `owner`.
    pub fn register(env: Env, owner: Address, treasury: Address) {
        owner.require_auth();
        if TreasuryClient::new(&env, &treasury).get_config().admin != owner {
            panic!("treasury is not administered by owner");
        }
        let key = DataKey::Owned(owner.clone());
        let mut owned: Vec<Address> = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or(Vec::new(&env));
        if !owned.contains(&treasury) {
            owned.push_back(treasury.clone());
            env.storage().persistent().set(&key, &owned);
            env.events()
                .publish((symbol_short!("regd"), owner), treasury);
        }
        env.storage()
            .persistent()
            .extend_ttl(&key, OWNED_TTL_THRESHOLD, OWNED_TTL_EXTEND_TO);
    }

    /// Drop `treasury` from `owner`'s list. Owner-signed; an absent entry is a no-op.
    /// No admin check: removing a listing can only take something away from the owner.
    pub fn unregister(env: Env, owner: Address, treasury: Address) {
        owner.require_auth();
        let key = DataKey::Owned(owner.clone());
        let owned: Vec<Address> = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or(Vec::new(&env));
        let Some(i) = owned.first_index_of(&treasury) else {
            return;
        };
        let mut owned = owned;
        owned.remove(i);
        if owned.is_empty() {
            env.storage().persistent().remove(&key);
        } else {
            env.storage().persistent().set(&key, &owned);
            env.storage()
                .persistent()
                .extend_ttl(&key, OWNED_TTL_THRESHOLD, OWNED_TTL_EXTEND_TO);
        }
        env.events()
            .publish((symbol_short!("unregd"), owner), treasury);
    }

    /// Every treasury registered by `owner`, oldest → newest (empty when none).
    pub fn treasuries_of(env: Env, owner: Address) -> Vec<Address> {
        env.storage()
            .persistent()
            .get(&DataKey::Owned(owner))
            .unwrap_or(Vec::new(&env))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::testutils::{storage::Persistent as _, Address as _};

    /// Stands in for a treasury: answers `get_config` with the admin it was built with.
    #[contract]
    struct FakeTreasury;

    #[contractimpl]
    impl FakeTreasury {
        pub fn __constructor(env: Env, admin: Address) {
            env.storage().instance().set(&symbol_short!("admin"), &admin);
        }

        pub fn get_config(env: Env) -> Config {
            let admin: Address = env.storage().instance().get(&symbol_short!("admin")).unwrap();
            Config {
                admin: admin.clone(),
                agent: admin,
                token: Address::generate(&env),
                daily_limit: 1,
                per_task_limit: 1,
            }
        }
    }

    fn treasury_of(env: &Env, admin: &Address) -> Address {
        env.register(FakeTreasury, (admin.clone(),))
    }

    fn registry(env: &Env) -> TreasuryRegistryClient<'_> {
        TreasuryRegistryClient::new(env, &env.register(TreasuryRegistry, ()))
    }

    #[test]
    fn register_lists_and_dedupes() {
        let env = Env::default();
        env.mock_all_auths();
        let client = registry(&env);

        let owner = Address::generate(&env);
        let t1 = treasury_of(&env, &owner);
        let t2 = treasury_of(&env, &owner);

        client.register(&owner, &t1);
        client.register(&owner, &t2);
        client.register(&owner, &t1); // duplicate — no-op

        let owned = client.treasuries_of(&owner);
        assert_eq!(owned.len(), 2);
        assert_eq!(owned.get(0).unwrap(), t1); // insertion order preserved
        assert_eq!(owned.get(1).unwrap(), t2);
    }

    #[test]
    fn register_requires_owner_auth() {
        let env = Env::default();
        let client = registry(&env);

        let owner = Address::generate(&env);
        let t1 = treasury_of(&env, &owner);

        env.set_auths(&[]);
        assert!(client.try_register(&owner, &t1).is_err());
        assert_eq!(client.treasuries_of(&owner).len(), 0);
    }

    /// H2: the victim signs, but the treasury is the attacker's — the listing is refused.
    #[test]
    fn a_treasury_someone_else_administers_cannot_be_listed() {
        let env = Env::default();
        env.mock_all_auths();
        let client = registry(&env);

        let victim = Address::generate(&env);
        let attackers = treasury_of(&env, &Address::generate(&env));

        assert!(client.try_register(&victim, &attackers).is_err());
        assert_eq!(client.treasuries_of(&victim).len(), 0);
    }

    /// An address with no treasury behind it has no config to check, so nothing is listed.
    #[test]
    fn an_address_that_is_not_a_treasury_cannot_be_listed() {
        let env = Env::default();
        env.mock_all_auths();
        let client = registry(&env);

        let owner = Address::generate(&env);
        assert!(client.try_register(&owner, &Address::generate(&env)).is_err());
    }

    #[test]
    fn unregister_drops_only_that_entry() {
        let env = Env::default();
        env.mock_all_auths();
        let client = registry(&env);

        let owner = Address::generate(&env);
        let t1 = treasury_of(&env, &owner);
        let t2 = treasury_of(&env, &owner);
        client.register(&owner, &t1);
        client.register(&owner, &t2);

        client.unregister(&owner, &t1);
        let owned = client.treasuries_of(&owner);
        assert_eq!(owned.len(), 1);
        assert_eq!(owned.get(0).unwrap(), t2);

        client.unregister(&owner, &t1); // absent — no-op
        client.unregister(&owner, &t2);
        assert_eq!(client.treasuries_of(&owner).len(), 0);
    }

    #[test]
    fn unregister_requires_owner_auth() {
        let env = Env::default();
        env.mock_all_auths();
        let client = registry(&env);
        let owner = Address::generate(&env);
        let t1 = treasury_of(&env, &owner);
        client.register(&owner, &t1);

        env.set_auths(&[]);
        assert!(client.try_unregister(&owner, &t1).is_err());
        assert_eq!(client.treasuries_of(&owner).len(), 1);
    }

    #[test]
    fn unknown_owner_returns_empty() {
        let env = Env::default();
        let client = registry(&env);
        assert_eq!(client.treasuries_of(&Address::generate(&env)).len(), 0);
    }

    #[test]
    fn register_extends_owned_ttl() {
        let env = Env::default();
        env.mock_all_auths();
        let client = registry(&env);
        let owner = Address::generate(&env);
        let t1 = treasury_of(&env, &owner);

        client.register(&owner, &t1);
        let ttl = env.as_contract(&client.address, || {
            env.storage()
                .persistent()
                .get_ttl(&DataKey::Owned(owner.clone()))
        });
        assert!(ttl >= OWNED_TTL_EXTEND_TO - 1);
    }
}
