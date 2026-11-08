//! Fees paid to validators. `pool = carry + what every address can claim` and a fixed total supply
//! must hold after every block, whatever the transactions and however the set changes.

mod common;

use common::*;
use qubits_crypto::SecretKey;
use qubits_execution::{TxError, claimable, read_reward_totals};
use qubits_types::*;

/// A chain whose validators can change, and which remembers everyone who ever held coins.
struct Rig {
    chain: Chain,
    council: Vec<SecretKey>,
    seats: Vec<Validator>,
    /// Every address that ever had a seat.
    payouts: Vec<Address>,
    holders: Vec<Address>,
    supply: Amount,
}

fn payout(seed: u8) -> Address {
    address(&key(seed))
}

fn seat(key_seed: u8, payout_seed: u8) -> Validator {
    Validator {
        key: key(key_seed).public_key().clone(),
        payout: payout(payout_seed),
    }
}

impl Rig {
    fn new(funded: &[&SecretKey]) -> Rig {
        let chain = Chain::new(funded);
        let first = Validator::self_paid(chain.validator.public_key().clone());
        let mut holders: Vec<Address> = funded.iter().map(|k| address(k)).collect();
        holders.push(governance_address());
        let supply = holders.iter().map(|a| chain.balance(a)).sum();
        Rig {
            council: vec![chain.validator.clone()],
            payouts: vec![first.payout],
            seats: vec![first],
            chain,
            holders,
            supply,
        }
    }

    fn pool(&self) -> Amount {
        self.chain.balance(&rewards_address())
    }

    fn claimable(&self, who: &Address) -> Amount {
        claimable(&self.chain.state, who).unwrap()
    }

    fn check(&self) {
        let totals = read_reward_totals(&self.chain.state).unwrap();
        let owed: Amount = self.payouts.iter().map(|p| self.claimable(p)).sum();
        assert_eq!(
            self.pool(),
            totals.carry + owed,
            "the pool pays what is owed"
        );
        // left from a larger set if it shrank, until the next fee
        assert!(totals.carry < limits::MAX_VALIDATORS as Amount);
        let mut held: Vec<Address> = self.holders.iter().chain(&self.payouts).copied().collect();
        held.sort();
        held.dedup();
        let total: Amount = held.iter().map(|a| self.chain.balance(a)).sum();
        assert_eq!(total + self.pool(), self.supply, "no coin made or lost");
    }

    /// Governance signs with the keys of the current set, and each new key joins it.
    fn seat(&mut self, next: Vec<Validator>, keys: Vec<SecretKey>) {
        let policy = self.chain.account(&governance_address()).auth.unwrap();
        let signers: Vec<&SecretKey> = self.council.iter().collect();
        let signers = &signers[..usize::from(policy.threshold)];
        let mut tx = self
            .chain
            .signed(
                &self.council[0],
                governance_address(),
                &policy,
                Payload::SetValidators {
                    validators: next.clone(),
                },
            )
            .tx;
        // the helper signs once, and a quorum makes the transaction larger
        let size = SignedTransaction::sign(tx.clone(), &policy, None, signers)
            .unwrap()
            .encode()
            .len();
        tx.fee = qubits_execution::min_fee(&params(), size);
        let stx = SignedTransaction::sign(tx, &policy, None, signers).unwrap();
        self.chain.submit(stx).unwrap();
        self.council = keys;
        for v in &next {
            if !self.payouts.contains(&v.payout) {
                self.payouts.push(v.payout);
            }
        }
        self.seats = next;
        self.check();
    }

    fn pay(&mut self, from: &SecretKey, to: Address, amount: Amount) -> Amount {
        let stx = self.chain.from(
            from,
            Payload::Transfer {
                to,
                asset: AssetId::NATIVE,
                amount,
            },
        );
        let fee = stx.tx.fee;
        self.chain.submit(stx).unwrap();
        if !self.holders.contains(&to) {
            self.holders.push(to);
        }
        self.check();
        fee
    }

    fn claim(&mut self, from: &SecretKey, payout: Address) -> Result<Amount, TxError> {
        let stx = self.chain.from(from, Payload::ClaimRewards { payout });
        let fee = stx.tx.fee;
        self.chain.submit(stx)?;
        self.check();
        Ok(fee)
    }
}

#[test]
fn fees_wait_in_the_pool_until_they_are_claimed() {
    let alice = key(1);
    let mut rig = Rig::new(&[&alice]);
    let validator = rig.seats[0].payout;
    assert_eq!((rig.pool(), rig.claimable(&validator)), (0, 0));

    let fee = rig.pay(&alice, payout(2), 10);
    assert_eq!(rig.pool(), fee);
    assert_eq!(rig.claimable(&validator), fee);
    assert_eq!(rig.chain.balance(&validator), 0, "nothing moves by itself");

    let before = rig.chain.balance(&address(&alice));
    let claim_fee = rig.claim(&alice, validator).unwrap();
    assert_eq!(rig.chain.balance(&validator), fee);
    assert_eq!(rig.chain.balance(&address(&alice)), before - claim_fee);
    assert_eq!(
        rig.pool(),
        claim_fee,
        "the claim's own fee is the next reward"
    );
    assert_eq!(rig.claimable(&validator), claim_fee);
}

/// One validator earns alone, four join, and the next fees go to all five: the old one keeps
/// everything from before, and the new ones get nothing of it.
#[test]
fn a_new_validator_earns_only_from_the_day_it_joins() {
    let alice = key(1);
    let mut rig = Rig::new(&[&alice]);
    let old = rig.seats[0].clone();
    rig.pay(&alice, payout(2), 10);
    rig.pay(&alice, payout(2), 10);

    let mut next = vec![old.clone()];
    let mut keys = vec![rig.council[0].clone()];
    for i in 0..4 {
        next.push(seat(100 + i, 110 + i));
        keys.push(key(100 + i));
    }
    rig.seat(next.clone(), keys);
    let alone = rig.claimable(&old.payout);
    assert_eq!(
        alone,
        rig.pool(),
        "the change's own fee went to the set it replaced"
    );
    for v in &next[1..] {
        assert_eq!(rig.claimable(&v.payout), 0);
    }

    let totals = read_reward_totals(&rig.chain.state).unwrap();
    let fee = rig.pay(&alice, payout(2), 10);
    let share = (totals.carry + fee) / 5;
    assert_eq!(rig.claimable(&old.payout), alone + share);
    for v in &next[1..] {
        assert_eq!(rig.claimable(&v.payout), share);
    }
}

#[test]
fn a_validator_that_leaves_keeps_what_it_earned() {
    let alice = key(1);
    let mut rig = Rig::new(&[&alice]);
    let old = rig.seats[0].clone();
    rig.pay(&alice, payout(2), 10);

    let stays = seat(100, 110);
    rig.seat(vec![stays.clone()], vec![key(100)]);
    let earned = rig.claimable(&old.payout);
    assert!(earned > 0);

    rig.pay(&alice, payout(2), 10);
    assert_eq!(rig.claimable(&old.payout), earned, "not earning any more");
    assert!(rig.claimable(&stays.payout) > 0);

    rig.claim(&alice, old.payout).unwrap();
    assert_eq!(rig.chain.balance(&old.payout), earned);
    assert_eq!(rig.claimable(&old.payout), 0);
    assert_eq!(
        rig.claim(&alice, old.payout).unwrap_err().to_string(),
        TxError::NothingToClaim.to_string()
    );

    rig.seat(
        vec![stays.clone(), old.clone()],
        vec![key(100), rig.chain.validator.clone()],
    );
    assert_eq!(rig.claimable(&old.payout), 0);
    let totals = read_reward_totals(&rig.chain.state).unwrap();
    let fee = rig.pay(&alice, payout(2), 10);
    assert_eq!(rig.claimable(&old.payout), (totals.carry + fee) / 2);
}

#[test]
fn a_validator_can_change_its_key_or_its_payout() {
    let alice = key(1);
    let mut rig = Rig::new(&[&alice]);
    let old = rig.seats[0].clone();
    rig.pay(&alice, payout(2), 10);

    let moved = Validator {
        key: key(100).public_key().clone(),
        payout: old.payout,
    };
    rig.seat(vec![moved.clone()], vec![key(100)]);
    let earned = rig.claimable(&old.payout);
    rig.pay(&alice, payout(2), 10);
    assert!(rig.claimable(&old.payout) > earned);

    let kept = rig.claimable(&old.payout);
    rig.seat(vec![seat(100, 111)], vec![key(100)]);
    assert!(
        rig.claimable(&old.payout) > kept,
        "the change paid its own fee"
    );
    let kept = rig.claimable(&old.payout);
    rig.pay(&alice, payout(2), 10);
    assert_eq!(rig.claimable(&old.payout), kept);
    assert!(rig.claimable(&payout(111)) > 0);
}

#[test]
fn what_does_not_divide_evenly_waits_for_the_next_fee() {
    let alice = key(1);
    let mut rig = Rig::new(&[&alice]);
    let next: Vec<_> = (0..3).map(|i| seat(100 + i, 110 + i)).collect();
    let keys: Vec<_> = (0..3).map(|i| key(100 + i)).collect();
    rig.seat(next.clone(), keys);

    let before = read_reward_totals(&rig.chain.state).unwrap();
    let mut carried = before.carry;
    let mut share = 0;
    for _ in 0..6 {
        let fee = rig.pay(&alice, payout(2), 10);
        let due = carried + fee;
        share += due / 3;
        carried = due % 3;
        let totals = read_reward_totals(&rig.chain.state).unwrap();
        assert_eq!(totals.carry, carried);
        assert_eq!(rig.claimable(&next[2].payout), share);
    }
}

#[test]
fn gas_that_comes_back_is_not_paid_out() {
    let alice = key(1);
    let mut rig = Rig::new(&[&alice]);
    let token = token(&mut rig.chain, &address(&alice), 1_000);
    rig.check();

    let pool = rig.pool();
    let before = rig.chain.balance(&address(&alice));
    let call = call_payload(token, "transfer", send_args(&payout(2), 5), 0, GAS);
    let stx = rig.chain.from(&alice, call);
    let fee = stx.tx.fee;
    rig.chain.submit(stx).unwrap();
    let paid = before - rig.chain.balance(&address(&alice));
    assert!(paid < fee, "unused gas came back");
    assert_eq!(rig.pool() - pool, paid);
    rig.check();

    let pool = rig.pool();
    let before = rig.chain.balance(&address(&alice));
    let call = call_payload(token, "transfer", send_args(&payout(2), 1_000_000), 0, GAS);
    let stx = rig.chain.from(&alice, call);
    rig.chain.submit(stx).unwrap();
    assert_eq!(
        rig.pool() - pool,
        before - rig.chain.balance(&address(&alice))
    );
    rig.check();
}

#[test]
fn a_refused_transaction_pays_nobody() {
    let alice = key(1);
    let mut rig = Rig::new(&[&alice]);
    let mut stx = rig.chain.from(
        &alice,
        Payload::Transfer {
            to: payout(2),
            asset: AssetId::NATIVE,
            amount: 1,
        },
    );
    stx.tx.nonce = 9;
    assert!(rig.chain.submit(stx).is_err());
    assert_eq!(rig.pool(), 0);
    assert!(matches!(
        rig.claim(&alice, payout(50)),
        Err(TxError::NothingToClaim)
    ));
    assert_eq!(rig.pool(), 0);
    rig.check();
}

#[test]
fn a_vault_can_claim_without_waiting_because_nothing_leaves_it() {
    let alice = key(1);
    let vault = key(2);
    let mut rig = Rig::new(&[&alice, &vault]);
    let validator = rig.seats[0].payout;
    rig.pay(&alice, payout(3), 10);
    let policy = VaultPolicy {
        delay_ms: DELAY,
        recovery: None,
    };
    let stx = rig.chain.from(
        &vault,
        Payload::SetVault {
            vault: Some(policy),
        },
    );
    rig.chain.submit(stx).unwrap();

    let earned = rig.claimable(&validator);
    rig.claim(&vault, validator).unwrap();
    assert_eq!(rig.chain.balance(&validator), earned);
    assert!(rig.chain.account(&address(&vault)).pending.is_empty());
}

#[test]
fn two_claims_in_one_block_each_take_what_they_find() {
    let alice = key(1);
    let mut rig = Rig::new(&[&alice]);
    let validator = rig.seats[0].payout;
    rig.pay(&alice, payout(2), 10);

    let first = rig
        .chain
        .from(&alice, Payload::ClaimRewards { payout: validator });
    let mut second = rig
        .chain
        .from(&alice, Payload::ClaimRewards { payout: validator });
    second.tx.nonce += 1;
    let policy = rig.chain.account(&address(&alice)).auth.unwrap();
    let second = SignedTransaction::sign(second.tx, &policy, None, &[&alice]).unwrap();
    let pool = rig.pool();
    rig.chain.block(&[first.clone(), second.clone()]).unwrap();
    assert_eq!(rig.chain.balance(&validator), pool + first.tx.fee);
    assert_eq!(rig.claimable(&validator), second.tx.fee);
    rig.check();
}

/// Random traffic, claims and changes of validators, with the two sums checked after each block.
#[test]
fn the_books_balance_whatever_happens() {
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move |below: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % below
    };
    let people = [key(1), key(2), key(3)];
    let refs: Vec<&SecretKey> = people.iter().collect();
    let mut rig = Rig::new(&refs);
    let token = token(&mut rig.chain, &address(&people[0]), 1_000_000);
    rig.check();

    let validator_keys: Vec<SecretKey> = (0..8).map(|i| key(100 + i)).collect();
    let mut changes = 0;
    for _ in 0..300 {
        let who = &people[next(3) as usize];
        match next(10) {
            0..=4 => {
                let to = payout(20 + next(5) as u8);
                rig.pay(who, to, 1 + u128::from(next(1_000)));
            }
            5..=6 => {
                let target = rig.payouts[next(rig.payouts.len() as u64) as usize];
                match rig.claim(who, target) {
                    Ok(_) | Err(TxError::NothingToClaim) => {}
                    Err(e) => panic!("{e}"),
                }
            }
            7 => {
                // a call that works or reverts, from whoever it happens to be
                let call = call_payload(token, "transfer", send_args(&payout(20), 1), 0, GAS);
                let stx = rig.chain.from(who, call);
                rig.chain.submit(stx).unwrap();
                rig.check();
            }
            8 => {
                let size = 1 + next(6) as usize;
                let start = next(8) as usize;
                let chosen: Vec<usize> = (0..size).map(|i| (start + i) % 8).collect();
                let seats = chosen
                    .iter()
                    .map(|&i| Validator {
                        key: validator_keys[i].public_key().clone(),
                        payout: payout(140 + i as u8),
                    })
                    .collect();
                let keys = chosen.iter().map(|&i| validator_keys[i].clone()).collect();
                rig.seat(seats, keys);
                changes += 1;
            }
            _ => {
                let totals = read_reward_totals(&rig.chain.state).unwrap();
                rig.chain.block(&[]).unwrap();
                assert_eq!(read_reward_totals(&rig.chain.state).unwrap(), totals);
            }
        }
    }
    assert!(changes > 10, "the run changed validators {changes} times");

    for payout in rig.payouts.clone() {
        match rig.claim(&people[0], payout) {
            Ok(_) | Err(TxError::NothingToClaim) => {}
            Err(e) => panic!("{e}"),
        }
    }
}
