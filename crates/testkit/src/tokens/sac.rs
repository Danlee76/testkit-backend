use std::cell::Cell;
use std::collections::BTreeMap;

use soroban_sdk::testutils::{MockAuth, MockAuthInvoke};
use soroban_sdk::token::{StellarAssetClient, TokenClient};
use soroban_sdk::{Address, Env, IntoVal};

use crate::core::{TestEnv, TestkitError};

/// The decimal precision every Stellar Asset Contract uses. This is fixed
/// by the protocol (the classic Stellar asset precision), not something a
/// deployer can choose — verified against soroban-sdk 27.0.6:
/// `register_stellar_asset_contract_v2` takes no decimals parameter, and a
/// freshly deployed SAC's own `decimals()` always returns 7.
const SAC_DECIMALS: u32 = 7;

/// A deployed Stellar Asset Contract test double, with one-line mint/balance
/// helpers so tests don't hand-roll SAC setup boilerplate.
///
/// # Administrative authorization
///
/// The double deploys the SAC with a fresh test address as its admin and
/// mocks that admin's authorization for [`TestToken::mint`] /
/// [`TestToken::mint_raw`] only — minting therefore works with no global auth
/// mocking enabled. Every other operation (transfers, burns, approvals) still
/// needs the test to authorize the caller with `mock_all_auths` or a per-call
/// `mock_auths`; see [`crate::tokens`] for the same rule stated module-wide.
pub struct TestToken {
    env: Env,
    address: Address,
    admin: Address,
    total_tracked: Cell<i128>,
}

impl TestToken {
    fn new(env: &Env, admin: Address) -> Self {
        let sac = env.register_stellar_asset_contract_v2(admin.clone());
        Self {
            env: env.clone(),
            address: sac.address(),
            admin,
            total_tracked: Cell::new(0),
        }
    }

    /// The token contract's address.
    pub fn address(&self) -> Address {
        self.address.clone()
    }

    /// The token's decimal precision. Always `7`, fixed by the protocol.
    pub fn decimals(&self) -> u32 {
        SAC_DECIMALS
    }

    /// Mint `amount` **whole units** to `to` (converted internally to base
    /// units, i.e. `amount * 10^decimals`).
    ///
    /// The Stellar Asset Contract admin's authorization is mocked for this
    /// call, so it succeeds with no global auth mocking enabled.
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::Misuse`] if the conversion to base
    /// units would overflow `i128`; use [`TestToken::mint_raw`] for amounts
    /// already in base units.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let token = env.token();
    /// let alice = env.address();
    ///
    /// token.mint(&alice, 100);
    /// token.assert_balance(&alice, 1_000_000_000); // 100 * 10^7
    /// ```
    /// Convert `amount` whole units into base units (stroops) at this token's decimal precision.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let token = env.token();
    /// assert_eq!(token.to_base_units(5).unwrap(), 50_000_000);
    /// ```
    pub fn to_base_units(&self, whole: i128) -> Result<i128, TestkitError> {
        whole_to_base_units(whole, self.decimals())
    }

    /// Convert `base` units into whole units at this token's decimal precision.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let token = env.token();
    /// assert_eq!(token.to_whole_units(50_000_000).unwrap(), 5);
    /// ```
    pub fn to_whole_units(&self, base: i128) -> Result<i128, TestkitError> {
        base_to_whole_units(base, self.decimals())
    }

    /// Mint `amount` **whole units** to `to` (converted internally to base
    /// units, i.e. `amount * 10^decimals`).
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::Misuse`] if the conversion to base
    /// units would overflow `i128`, or if the contract invocation fails or traps.
    /// Use [`TestToken::mint_raw`] for amounts already in base units, or
    /// [`TestToken::try_mint`] for fallible invocations.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let token = env.token();
    /// let alice = env.address();
    ///
    /// token.mint(&alice, 100);
    /// token.assert_balance(&alice, 1_000_000_000); // 100 * 10^7
    /// ```
    pub fn mint(&self, to: &Address, amount: i128) {
        let raw = self.to_base_units(amount).unwrap_or_else(|err| {
            panic!(
                "{}",
                TestkitError::Misuse(format!(
                    "mint({amount}) overflows i128 once converted to base units at {} \
                     decimals; use mint_raw for amounts already in base units: {err}",
                    self.decimals()
                ))
            )
        });
        self.mint_raw(to, raw);
    }

    /// Attempt to mint `amount` **whole units** to `to`, returning
    /// `Err(TestkitError)` if conversion overflows or if the mint traps.
    ///
    /// If the mint traps, `total_tracked` remains unchanged and consistent.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let token = env.token();
    /// let alice = env.address();
    /// assert!(token.try_mint(&alice, 10).is_ok());
    /// ```
    pub fn try_mint(&self, to: &Address, amount: i128) -> Result<(), TestkitError> {
        let raw = self.to_base_units(amount)?;
        self.try_mint_raw(to, raw)
    }

    /// Mint `amount` **base units** (stroops) to `to`, with no unit
    /// conversion.
    ///
    /// The Stellar Asset Contract admin's authorization is mocked for this
    /// call, so it succeeds with no global auth mocking enabled.
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError`] if the mint traps or fails.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let token = env.token();
    /// let alice = env.address();
    ///
    /// token.mint_raw(&alice, 42);
    /// token.assert_balance(&alice, 42);
    /// ```
    pub fn mint_raw(&self, to: &Address, amount: i128) {
        if let Err(err) = self.try_mint_raw(to, amount) {
            panic!("{err}");
        }
    }

    /// Attempt to mint `amount` **base units** (stroops) to `to`.
    ///
    /// If the contract invocation traps or rejects the mint, `total_tracked`
    /// remains consistent (unchanged) and a [`TestkitError`] is returned with
    /// actionable context.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let token = env.token();
    /// let alice = env.address();
    /// assert!(token.try_mint_raw(&alice, 42).is_ok());
    /// ```
    pub fn try_mint_raw(&self, to: &Address, amount: i128) -> Result<(), TestkitError> {
        if amount < 0 {
            return Err(TestkitError::Misuse(format!(
                "cannot mint negative amount {amount} to {to:?}"
            )));
        }

        let new_total = self
            .total_tracked
            .get()
            .checked_add(amount)
            .ok_or_else(|| {
                TestkitError::Misuse(format!(
                    "minting {amount} base units would overflow tracked supply (current total: {})",
                    self.total_tracked.get()
                ))
            })?;

        let invoke_res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            StellarAssetClient::new(&self.env, &self.address)
                .mock_auths(&[MockAuth {
                    address: &self.admin,
                    invoke: &MockAuthInvoke {
                        contract: &self.address,
                        fn_name: "mint",
                        args: (to.clone(), amount).into_val(&self.env),
                        sub_invokes: &[],
                    },
                }])
                .try_mint(to, &amount)
        }));

        match invoke_res {
            Ok(Ok(Ok(()))) => {
                self.total_tracked.set(new_total);
                Ok(())
            }
            Ok(Err(err)) => Err(TestkitError::AssertionFailed(format!(
                "mint of {amount} base units to {to:?} failed or trapped: {err:?}"
            ))),
            Ok(Ok(Err(err))) => Err(TestkitError::DecodeFailed(format!(
                "mint response decoding failed: {err:?}"
            ))),
            Err(_) => Err(TestkitError::AssertionFailed(format!(
                "mint of {amount} base units to {to:?} trapped with panic"
            ))),
        }
    }

    /// The balance of `of`, in **base units**.
    pub fn balance(&self, of: &Address) -> i128 {
        TokenClient::new(&self.env, &self.address).balance(of)
    }

    /// Assert that `of`'s balance equals `expected`, in **base units**.
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::AssertionFailed`] showing the expected
    /// and actual balances if they differ.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let token = env.token();
    /// let alice = env.address();
    ///
    /// token.mint_raw(&alice, 10);
    /// token.assert_balance(&alice, 10);
    /// ```
    pub fn assert_balance(&self, of: &Address, expected: i128) {
        let actual = self.balance(of);
        if actual != expected {
            panic!(
                "{}",
                TestkitError::AssertionFailed(format!(
                    "expected balance of {of:?} to be {expected}, found {actual}"
                ))
            );
        }
    }

    /// The whole-unit balance of `of` (truncated).
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let token = env.token();
    /// let alice = env.address();
    /// token.mint(&alice, 10);
    /// assert_eq!(token.balance_whole(&alice), 10);
    /// ```
    pub fn balance_whole(&self, of: &Address) -> i128 {
        let raw = self.balance(of);
        self.to_whole_units(raw).unwrap_or_else(|err| {
            panic!("{err}");
        })
    }

    /// Assert that `of`'s whole-unit balance equals `expected_whole`.
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::Misuse`] if scaling `expected_whole`
    /// to base units overflows `i128`.
    /// Panics with a [`TestkitError::AssertionFailed`] if balances differ.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let token = env.token();
    /// let alice = env.address();
    /// token.mint(&alice, 10);
    /// token.assert_balance_whole(&alice, 10);
    /// ```
    pub fn assert_balance_whole(&self, of: &Address, expected_whole: i128) {
        let raw_expected = self.to_base_units(expected_whole).unwrap_or_else(|err| {
            panic!("{err}");
        });
        self.assert_balance(of, raw_expected);
    }

    /// Total **base units** minted through this `TestToken` (via
    /// [`TestToken::mint`] or [`TestToken::mint_raw`]) across every
    /// recipient — for supply-conservation assertions.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let token = env.token();
    /// token.mint_raw(&env.address(), 10);
    /// token.mint_raw(&env.address(), 5);
    /// assert_eq!(token.total_tracked(), 15);
    /// ```
    pub fn total_tracked(&self) -> i128 {
        self.total_tracked.get()
    }

    /// Mint multiple (recipient, amount) allocations in **whole units** for table-driven fixtures.
    ///
    /// Amounts are converted internally to base units (stroops). The Stellar Asset
    /// Contract admin's authorization is mocked for all mints, so this succeeds
    /// with no global auth mocking enabled.
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::Misuse`] if any allocation's amount is negative
    /// or if conversion to base units overflows `i128`.
    /// Panics with a [`TestkitError::AssertionFailed`] if any contract invocation traps.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let token = env.token();
    /// let alice = env.address();
    /// let bob = env.address();
    ///
    /// token.mint_many([(&alice, 10), (&bob, 20)]);
    /// token.assert_balance_whole(&alice, 10);
    /// token.assert_balance_whole(&bob, 20);
    /// ```
    pub fn mint_many<I>(&self, allocations: I)
    where
        I: IntoIterator,
        I::Item: MintAllocation,
    {
        if let Err(err) = self.try_mint_many(allocations) {
            panic!("{err}");
        }
    }

    /// Attempt to mint multiple (recipient, amount) allocations in **whole units**.
    ///
    /// Returns `Err(TestkitError)` if any conversion overflows or if any mint traps.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let token = env.token();
    /// let alice = env.address();
    ///
    /// assert!(token.try_mint_many([(&alice, 10)]).is_ok());
    /// ```
    pub fn try_mint_many<I>(&self, allocations: I) -> Result<(), TestkitError>
    where
        I: IntoIterator,
        I::Item: MintAllocation,
    {
        let items: Vec<_> = allocations.into_iter().collect();
        let mut raw_items = Vec::with_capacity(items.len());
        for item in &items {
            let amount = item.amount();
            let to = item.recipient();
            if amount < 0 {
                return Err(TestkitError::Misuse(format!(
                    "cannot mint negative amount {amount} to {to:?}"
                )));
            }
            let raw = self.to_base_units(amount).map_err(|err| {
                TestkitError::Misuse(format!(
                    "mint_many({amount}) overflows i128 once converted to base units: {err}"
                ))
            })?;
            raw_items.push((to, raw));
        }
        for (to, raw) in raw_items {
            self.try_mint_raw(to, raw)?;
        }
        Ok(())
    }

    /// Mint multiple (recipient, amount) allocations in **base units** (stroops) with no unit conversion.
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError`] if any amount is negative, overflows tracked supply,
    /// or if any invocation traps.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let token = env.token();
    /// let alice = env.address();
    /// let bob = env.address();
    ///
    /// token.mint_many_raw([(&alice, 100), (&bob, 200)]);
    /// token.assert_balance(&alice, 100);
    /// token.assert_balance(&bob, 200);
    /// ```
    pub fn mint_many_raw<I>(&self, allocations: I)
    where
        I: IntoIterator,
        I::Item: MintAllocation,
    {
        if let Err(err) = self.try_mint_many_raw(allocations) {
            panic!("{err}");
        }
    }

    /// Attempt to mint multiple (recipient, amount) allocations in **base units** (stroops).
    pub fn try_mint_many_raw<I>(&self, allocations: I) -> Result<(), TestkitError>
    where
        I: IntoIterator,
        I::Item: MintAllocation,
    {
        let items: Vec<_> = allocations.into_iter().collect();
        for item in &items {
            let amount = item.amount();
            let to = item.recipient();
            if amount < 0 {
                return Err(TestkitError::Misuse(format!(
                    "cannot mint negative amount {amount} to {to:?}"
                )));
            }
        }
        for item in items {
            self.try_mint_raw(item.recipient(), item.amount())?;
        }
        Ok(())
    }

    /// Assert that running `f` changes the tracked token supply by exactly
    /// `expected_delta` **base units** (stroops) (after minus before).
    ///
    /// The delta is signed: minting increases tracked supply (positive delta).
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::AssertionFailed`] showing the before
    /// and after supplies and the actual delta if it differs from `expected_delta`.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let token = env.token();
    /// let alice = env.address();
    ///
    /// token.assert_supply_delta(100, || {
    ///     token.mint_raw(&alice, 100);
    /// });
    /// ```
    pub fn assert_supply_delta(&self, expected_delta: i128, f: impl FnOnce()) {
        let before = self.total_tracked();
        f();
        let after = self.total_tracked();
        let delta = after.checked_sub(before).unwrap_or_else(|| {
            panic!(
                "{}",
                TestkitError::AssertionFailed(format!(
                    "tracked supply delta overflowed i128: before={before}, after={after}"
                ))
            );
        });
        if delta != expected_delta {
            panic!(
                "{}",
                TestkitError::AssertionFailed(format!(
                    "expected the call to change tracked token supply by {expected_delta} base units, \
                     but it went from {before} to {after} (delta={delta})"
                ))
            );
        }
    }

    /// Assert that running `f` changes the tracked token supply by exactly
    /// `expected_delta_whole` **whole units** (after minus before).
    ///
    /// Converted internally to base units at this token's decimal precision.
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::Misuse`] if scaling `expected_delta_whole`
    /// overflows `i128`.
    /// Panics with a [`TestkitError::AssertionFailed`] if the actual change
    /// differs from `expected_delta_whole`.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let token = env.token();
    /// let alice = env.address();
    ///
    /// token.assert_supply_delta_whole(5, || {
    ///     token.mint(&alice, 5);
    /// });
    /// ```
    pub fn assert_supply_delta_whole(&self, expected_delta_whole: i128, f: impl FnOnce()) {
        let expected_raw = self
            .to_base_units(expected_delta_whole)
            .unwrap_or_else(|err| {
                panic!("{err}");
            });
        let before = self.total_tracked();
        f();
        let after = self.total_tracked();
        let delta = after.checked_sub(before).unwrap_or_else(|| {
            panic!(
                "{}",
                TestkitError::AssertionFailed(format!(
                    "tracked supply delta overflowed i128: before={before}, after={after}"
                ))
            );
        });
        if delta != expected_raw {
            panic!(
                "{}",
                TestkitError::AssertionFailed(format!(
                    "expected the call to change tracked token supply by {expected_delta_whole} whole units \
                     ({expected_raw} base units), but it went from {before} to {after} (delta={delta})"
                ))
            );
        }
    }

    /// Assert that running `f` changes the balance of `of` by exactly
    /// `expected_delta` **base units** (stroops) (after minus before).
    ///
    /// The delta is signed: receiving tokens yields a positive delta, while
    /// sending, burning, or spending tokens yields a negative delta.
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::AssertionFailed`] showing the before
    /// and after balances and the actual delta if it differs from `expected_delta`.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let token = env.token();
    /// let alice = env.address();
    ///
    /// token.assert_balance_delta(&alice, 50, || {
    ///     token.mint_raw(&alice, 50);
    /// });
    /// ```
    pub fn assert_balance_delta(&self, of: &Address, expected_delta: i128, f: impl FnOnce()) {
        let before = self.balance(of);
        f();
        let after = self.balance(of);
        let delta = after.checked_sub(before).unwrap_or_else(|| {
            panic!(
                "{}",
                TestkitError::AssertionFailed(format!(
                    "balance delta for {of:?} overflowed i128: before={before}, after={after}"
                ))
            );
        });
        if delta != expected_delta {
            panic!(
                "{}",
                TestkitError::AssertionFailed(format!(
                    "expected the call to change balance of {of:?} by {expected_delta} base units, \
                     but it went from {before} to {after} (delta={delta})"
                ))
            );
        }
    }

    /// Assert that running `f` changes the balance of `of` by exactly
    /// `expected_delta_whole` **whole units** (after minus before).
    ///
    /// Converted internally to base units at this token's decimal precision.
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::Misuse`] if scaling `expected_delta_whole`
    /// overflows `i128`.
    /// Panics with a [`TestkitError::AssertionFailed`] if the actual change
    /// differs from `expected_delta_whole`.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let token = env.token();
    /// let alice = env.address();
    ///
    /// token.assert_balance_delta_whole(&alice, 10, || {
    ///     token.mint(&alice, 10);
    /// });
    /// ```
    pub fn assert_balance_delta_whole(
        &self,
        of: &Address,
        expected_delta_whole: i128,
        f: impl FnOnce(),
    ) {
        let expected_raw = self
            .to_base_units(expected_delta_whole)
            .unwrap_or_else(|err| {
                panic!("{err}");
            });
        let before = self.balance(of);
        f();
        let after = self.balance(of);
        let delta = after.checked_sub(before).unwrap_or_else(|| {
            panic!(
                "{}",
                TestkitError::AssertionFailed(format!(
                    "balance delta for {of:?} overflowed i128: before={before}, after={after}"
                ))
            );
        });
        if delta != expected_raw {
            panic!(
                "{}",
                TestkitError::AssertionFailed(format!(
                    "expected the call to change balance of {of:?} by {expected_delta_whole} whole units \
                     ({expected_raw} base units), but it went from {before} to {after} (delta={delta})"
                ))
            );
        }
    }

    /// Assert that running `f` changes the balances of multiple accounts by their
    /// respective `expected_delta` in **base units** (stroops).
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let token = env.token();
    /// let alice = env.address();
    /// let bob = env.address();
    ///
    /// token.assert_balances_delta([(&alice, 100), (&bob, 200)], || {
    ///     token.mint_raw(&alice, 100);
    ///     token.mint_raw(&bob, 200);
    /// });
    /// ```
    pub fn assert_balances_delta<I>(&self, expected_deltas: I, f: impl FnOnce())
    where
        I: IntoIterator,
        I::Item: BalanceDeltaAllocation,
    {
        let deltas: Vec<(Address, i128)> = expected_deltas
            .into_iter()
            .map(|item| (item.account().clone(), item.expected_delta()))
            .collect();
        let before: Vec<(Address, i128, i128)> = deltas
            .iter()
            .map(|(addr, expected)| (addr.clone(), self.balance(addr), *expected))
            .collect();
        f();
        for (addr, before_bal, expected_delta) in before {
            let after_bal = self.balance(&addr);
            let delta = after_bal.checked_sub(before_bal).unwrap_or_else(|| {
                panic!(
                    "{}",
                    TestkitError::AssertionFailed(format!(
                        "balance delta for {addr:?} overflowed i128: before={before_bal}, after={after_bal}"
                    ))
                );
            });
            if delta != expected_delta {
                panic!(
                    "{}",
                    TestkitError::AssertionFailed(format!(
                        "expected the call to change balance of {addr:?} by {expected_delta} base units, \
                         but it went from {before_bal} to {after_bal} (delta={delta})"
                    ))
                );
            }
        }
    }

    /// Assert that running `f` changes the balances of multiple accounts by their
    /// respective `expected_delta_whole` in **whole units**.
    pub fn assert_balances_delta_whole<I>(&self, expected_deltas: I, f: impl FnOnce())
    where
        I: IntoIterator,
        I::Item: BalanceDeltaAllocation,
    {
        let deltas: Vec<(Address, i128)> = expected_deltas
            .into_iter()
            .map(|item| {
                let raw = self
                    .to_base_units(item.expected_delta())
                    .unwrap_or_else(|err| {
                        panic!("{err}");
                    });
                (item.account().clone(), raw)
            })
            .collect();
        self.assert_balances_delta(deltas, f);
    }

    /// Capture a point-in-time [`TokenSnapshot`] for `account`, recording its
    /// balance and the current tracked token supply.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let token = env.token();
    /// let alice = env.address();
    ///
    /// let snap = token.snapshot(&alice);
    /// assert_eq!(snap.balance(), 0);
    /// assert_eq!(snap.tracked_supply(), 0);
    /// ```
    #[allow(clippy::mutable_key_type)]
    pub fn snapshot(&self, account: &Address) -> TokenSnapshot {
        let bal = self.balance(account);
        let mut balances = BTreeMap::new();
        balances.insert(account.clone(), bal);
        TokenSnapshot {
            token: self.address(),
            account: Some(account.clone()),
            balance: Some(bal),
            tracked_supply: self.total_tracked(),
            balances,
        }
    }

    /// Capture a point-in-time [`TokenSnapshot`] of the token's tracked supply
    /// without a primary account.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let token = env.token();
    ///
    /// let snap = token.snapshot_supply();
    /// assert_eq!(snap.tracked_supply(), 0);
    /// ```
    pub fn snapshot_supply(&self) -> TokenSnapshot {
        TokenSnapshot {
            token: self.address(),
            account: None,
            balance: None,
            tracked_supply: self.total_tracked(),
            balances: BTreeMap::new(),
        }
    }

    /// Capture a point-in-time [`TokenSnapshot`] across multiple accounts.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let token = env.token();
    /// let alice = env.address();
    /// let bob = env.address();
    ///
    /// let snap = token.snapshot_accounts([&alice, &bob]);
    /// assert_eq!(snap.balance_of(&alice), Some(0));
    /// assert_eq!(snap.balance_of(&bob), Some(0));
    /// ```
    #[allow(clippy::mutable_key_type)]
    pub fn snapshot_accounts<'a, I>(&self, accounts: I) -> TokenSnapshot
    where
        I: IntoIterator<Item = &'a Address>,
    {
        let mut balances = BTreeMap::new();
        for addr in accounts {
            balances.insert(addr.clone(), self.balance(addr));
        }
        TokenSnapshot {
            token: self.address(),
            account: None,
            balance: None,
            tracked_supply: self.total_tracked(),
            balances,
        }
    }
}

/// A helper trait for table-driven mint fixtures that converts various tuple shapes into an address reference and amount.
pub trait MintAllocation {
    /// The recipient address.
    fn recipient(&self) -> &Address;
    /// The mint amount.
    fn amount(&self) -> i128;
}

impl MintAllocation for (&Address, i128) {
    fn recipient(&self) -> &Address {
        self.0
    }
    fn amount(&self) -> i128 {
        self.1
    }
}

impl MintAllocation for &(&Address, i128) {
    fn recipient(&self) -> &Address {
        self.0
    }
    fn amount(&self) -> i128 {
        self.1
    }
}

impl MintAllocation for (&Address, &i128) {
    fn recipient(&self) -> &Address {
        self.0
    }
    fn amount(&self) -> i128 {
        *self.1
    }
}

impl MintAllocation for &(&Address, &i128) {
    fn recipient(&self) -> &Address {
        self.0
    }
    fn amount(&self) -> i128 {
        *self.1
    }
}

impl MintAllocation for (Address, i128) {
    fn recipient(&self) -> &Address {
        &self.0
    }
    fn amount(&self) -> i128 {
        self.1
    }
}

impl MintAllocation for &(Address, i128) {
    fn recipient(&self) -> &Address {
        &self.0
    }
    fn amount(&self) -> i128 {
        self.1
    }
}

impl MintAllocation for (Address, &i128) {
    fn recipient(&self) -> &Address {
        &self.0
    }
    fn amount(&self) -> i128 {
        *self.1
    }
}

impl MintAllocation for &(Address, &i128) {
    fn recipient(&self) -> &Address {
        &self.0
    }
    fn amount(&self) -> i128 {
        *self.1
    }
}

/// A helper trait for table-driven balance delta assertions.
pub trait BalanceDeltaAllocation {
    /// The account address.
    fn account(&self) -> &Address;
    /// The expected delta.
    fn expected_delta(&self) -> i128;
}

impl BalanceDeltaAllocation for (&Address, i128) {
    fn account(&self) -> &Address {
        self.0
    }
    fn expected_delta(&self) -> i128 {
        self.1
    }
}

impl BalanceDeltaAllocation for &(&Address, i128) {
    fn account(&self) -> &Address {
        self.0
    }
    fn expected_delta(&self) -> i128 {
        self.1
    }
}

impl BalanceDeltaAllocation for (&Address, &i128) {
    fn account(&self) -> &Address {
        self.0
    }
    fn expected_delta(&self) -> i128 {
        *self.1
    }
}

impl BalanceDeltaAllocation for &(&Address, &i128) {
    fn account(&self) -> &Address {
        self.0
    }
    fn expected_delta(&self) -> i128 {
        *self.1
    }
}

impl BalanceDeltaAllocation for (Address, i128) {
    fn account(&self) -> &Address {
        &self.0
    }
    fn expected_delta(&self) -> i128 {
        self.1
    }
}

impl BalanceDeltaAllocation for &(Address, i128) {
    fn account(&self) -> &Address {
        &self.0
    }
    fn expected_delta(&self) -> i128 {
        self.1
    }
}

impl BalanceDeltaAllocation for (Address, &i128) {
    fn account(&self) -> &Address {
        &self.0
    }
    fn expected_delta(&self) -> i128 {
        *self.1
    }
}

impl BalanceDeltaAllocation for &(Address, &i128) {
    fn account(&self) -> &Address {
        &self.0
    }
    fn expected_delta(&self) -> i128 {
        *self.1
    }
}

/// A point-in-time snapshot of token balances and supply, taken with
/// [`TestToken::snapshot`] and compared with [`TokenSnapshot::diff`].
///
/// # Example
///
/// ```
/// use soroban_testkit::core::TestEnv;
///
/// let env = TestEnv::new();
/// let token = env.token();
/// let alice = env.address();
///
/// let before = token.snapshot(&alice);
/// token.mint_raw(&alice, 100);
/// let after = token.snapshot(&alice);
///
/// let diff = before.diff(&after);
/// assert_eq!(diff.balance_delta(), 100);
/// assert_eq!(diff.supply_delta(), 100);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenSnapshot {
    token: Address,
    account: Option<Address>,
    balance: Option<i128>,
    tracked_supply: i128,
    balances: BTreeMap<Address, i128>,
}

impl TokenSnapshot {
    /// The token contract's address.
    pub fn token(&self) -> &Address {
        &self.token
    }

    /// The primary account this snapshot was taken for, if any.
    pub fn account(&self) -> Option<&Address> {
        self.account.as_ref()
    }

    /// The balance of the primary account in **base units** (stroops).
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::Misuse`] if this snapshot was not taken
    /// for a single primary account. Use [`TokenSnapshot::balance_of`] to query
    /// arbitrary accounts.
    pub fn balance(&self) -> i128 {
        self.balance.unwrap_or_else(|| {
            panic!(
                "{}",
                TestkitError::Misuse(
                    "snapshot has no primary account; use balance_of(&address) instead".into()
                )
            );
        })
    }

    /// The whole-unit balance of the primary account (truncated).
    ///
    /// # Errors
    ///
    /// Returns `Err(TestkitError)` if scaling overflows.
    pub fn balance_whole(&self) -> Result<i128, TestkitError> {
        base_to_whole_units(self.balance(), SAC_DECIMALS)
    }

    /// The balance of `account` in **base units** (stroops) recorded in this snapshot.
    pub fn balance_of(&self, account: &Address) -> Option<i128> {
        self.balances.get(account).copied().or_else(|| {
            if self.account.as_ref() == Some(account) {
                self.balance
            } else {
                None
            }
        })
    }

    /// The whole-unit balance of `account` recorded in this snapshot.
    ///
    /// # Errors
    ///
    /// Returns `Err(TestkitError)` if scaling overflows.
    pub fn balance_of_whole(&self, account: &Address) -> Result<Option<i128>, TestkitError> {
        match self.balance_of(account) {
            Some(raw) => base_to_whole_units(raw, SAC_DECIMALS).map(Some),
            None => Ok(None),
        }
    }

    /// Total **base units** minted through the `TestToken` at the time of the snapshot.
    pub fn tracked_supply(&self) -> i128 {
        self.tracked_supply
    }

    /// Total **whole units** minted through the `TestToken` at the time of the snapshot.
    ///
    /// # Errors
    ///
    /// Returns `Err(TestkitError)` if scaling overflows.
    pub fn tracked_supply_whole(&self) -> Result<i128, TestkitError> {
        base_to_whole_units(self.tracked_supply, SAC_DECIMALS)
    }

    /// All account balances captured in this snapshot.
    #[allow(clippy::mutable_key_type)]
    pub fn balances(&self) -> &BTreeMap<Address, i128> {
        &self.balances
    }

    /// Compare this snapshot to a `later` snapshot of the same token, computing the
    /// changes in balances and tracked supply.
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::Misuse`] if `later` is from a different token contract
    /// or was taken for a different primary account.
    #[allow(clippy::mutable_key_type)]
    pub fn diff(&self, later: &TokenSnapshot) -> TokenDiff {
        if self.token != later.token {
            panic!(
                "{}",
                TestkitError::Misuse(format!(
                    "cannot diff snapshots from different tokens: {:?} vs {:?}",
                    self.token, later.token
                ))
            );
        }
        if self.account != later.account {
            panic!(
                "{}",
                TestkitError::Misuse(format!(
                    "cannot diff snapshots for different primary accounts: {:?} vs {:?}",
                    self.account, later.account
                ))
            );
        }

        let balance_delta = match (self.balance, later.balance) {
            (Some(b1), Some(b2)) => Some(b2.checked_sub(b1).unwrap_or_else(|| {
                panic!(
                    "{}",
                    TestkitError::AssertionFailed(format!(
                        "primary account balance delta overflowed i128: before={b1}, after={b2}"
                    ))
                );
            })),
            _ => None,
        };

        let supply_delta = later
            .tracked_supply
            .checked_sub(self.tracked_supply)
            .unwrap_or_else(|| {
                panic!(
                    "{}",
                    TestkitError::AssertionFailed(format!(
                        "tracked supply delta overflowed i128: before={}, after={}",
                        self.tracked_supply, later.tracked_supply
                    ))
                );
            });

        let mut balance_deltas = BTreeMap::new();
        for (addr, b1) in &self.balances {
            if let Some(b2) = later.balances.get(addr) {
                balance_deltas.insert(addr.clone(), b2 - b1);
            }
        }
        for (addr, b2) in &later.balances {
            if !self.balances.contains_key(addr) {
                if let Some(b1) = self.balances.get(addr) {
                    balance_deltas.insert(addr.clone(), b2 - b1);
                }
            }
        }

        TokenDiff {
            token: self.token.clone(),
            account: self.account.clone(),
            balance_delta,
            supply_delta,
            balance_deltas,
        }
    }
}

/// The difference between two [`TokenSnapshot`] readings of the same token contract.
///
/// # Example
///
/// ```
/// use soroban_testkit::core::TestEnv;
///
/// let env = TestEnv::new();
/// let token = env.token();
/// let alice = env.address();
///
/// let before = token.snapshot(&alice);
/// token.mint_raw(&alice, 100);
/// let after = token.snapshot(&alice);
///
/// let diff = before.diff(&after);
/// diff.assert_balance_delta(100);
/// diff.assert_supply_delta(100);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenDiff {
    token: Address,
    account: Option<Address>,
    balance_delta: Option<i128>,
    supply_delta: i128,
    balance_deltas: BTreeMap<Address, i128>,
}

impl TokenDiff {
    /// The token contract address.
    pub fn token(&self) -> &Address {
        &self.token
    }

    /// The primary account this diff was computed for, if any.
    pub fn account(&self) -> Option<&Address> {
        self.account.as_ref()
    }

    /// The signed change in balance of the primary account in **base units** (stroops) (after minus before).
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::Misuse`] if the snapshots were not taken for a primary account.
    pub fn balance_delta(&self) -> i128 {
        self.balance_delta.unwrap_or_else(|| {
            panic!(
                "{}",
                TestkitError::Misuse("diff has no primary account balance delta".into())
            );
        })
    }

    /// The signed change in balance of the primary account in **whole units**.
    ///
    /// # Errors
    ///
    /// Returns `Err(TestkitError)` if scaling overflows.
    pub fn balance_delta_whole(&self) -> Result<i128, TestkitError> {
        base_to_whole_units(self.balance_delta(), SAC_DECIMALS)
    }

    /// The signed change in balance of `account` in **base units** (after minus before).
    pub fn balance_delta_of(&self, account: &Address) -> Option<i128> {
        self.balance_deltas.get(account).copied().or_else(|| {
            if self.account.as_ref() == Some(account) {
                self.balance_delta
            } else {
                None
            }
        })
    }

    /// The signed change in balance of `account` in **whole units**.
    ///
    /// # Errors
    ///
    /// Returns `Err(TestkitError)` if scaling overflows.
    pub fn balance_delta_of_whole(&self, account: &Address) -> Result<Option<i128>, TestkitError> {
        match self.balance_delta_of(account) {
            Some(raw) => base_to_whole_units(raw, SAC_DECIMALS).map(Some),
            None => Ok(None),
        }
    }

    /// All individual account balance deltas.
    #[allow(clippy::mutable_key_type)]
    pub fn balance_deltas(&self) -> &BTreeMap<Address, i128> {
        &self.balance_deltas
    }

    /// The signed change in tracked supply in **base units** (after minus before).
    pub fn supply_delta(&self) -> i128 {
        self.supply_delta
    }

    /// The signed change in tracked supply in **whole units**.
    ///
    /// # Errors
    ///
    /// Returns `Err(TestkitError)` if scaling overflows.
    pub fn supply_delta_whole(&self) -> Result<i128, TestkitError> {
        base_to_whole_units(self.supply_delta, SAC_DECIMALS)
    }

    /// Assert that the primary account's balance delta equals `expected_delta` base units.
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::AssertionFailed`] if actual delta differs from `expected_delta`.
    pub fn assert_balance_delta(&self, expected_delta: i128) {
        let actual = self.balance_delta();
        if actual != expected_delta {
            panic!(
                "{}",
                TestkitError::AssertionFailed(format!(
                    "expected snapshot balance delta of {:?} to be {expected_delta} base units, found {actual}",
                    self.account
                ))
            );
        }
    }

    /// Assert that the primary account's balance delta equals `expected_delta_whole` whole units.
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::Misuse`] if scaling overflows, or [`TestkitError::AssertionFailed`]
    /// if actual delta differs.
    pub fn assert_balance_delta_whole(&self, expected_delta_whole: i128) {
        let expected_raw =
            whole_to_base_units(expected_delta_whole, SAC_DECIMALS).unwrap_or_else(|err| {
                panic!("{err}");
            });
        self.assert_balance_delta(expected_raw);
    }

    /// Assert that the supply delta equals `expected_delta` base units.
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::AssertionFailed`] if actual supply delta differs.
    pub fn assert_supply_delta(&self, expected_delta: i128) {
        if self.supply_delta != expected_delta {
            panic!(
                "{}",
                TestkitError::AssertionFailed(format!(
                    "expected snapshot supply delta of {:?} to be {expected_delta} base units, found {}",
                    self.token, self.supply_delta
                ))
            );
        }
    }

    /// Assert that the supply delta equals `expected_delta_whole` whole units.
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::Misuse`] if scaling overflows, or [`TestkitError::AssertionFailed`]
    /// if actual supply delta differs.
    pub fn assert_supply_delta_whole(&self, expected_delta_whole: i128) {
        let expected_raw =
            whole_to_base_units(expected_delta_whole, SAC_DECIMALS).unwrap_or_else(|err| {
                panic!("{err}");
            });
        self.assert_supply_delta(expected_raw);
    }
}

/// Convert a whole-unit amount into base units at the given decimal precision without overflowing.
///
/// Returns `Err(TestkitError::Misuse)` with actionable context if `10^decimals` or the
/// multiplication overflows `i128`.
///
/// # Example
///
/// ```
/// use soroban_testkit::tokens::whole_to_base_units;
///
/// let raw = whole_to_base_units(10, 7).unwrap();
/// assert_eq!(raw, 100_000_000);
/// ```
pub fn whole_to_base_units(whole: i128, decimals: u32) -> Result<i128, TestkitError> {
    let scale = 10i128.checked_pow(decimals).ok_or_else(|| {
        TestkitError::Misuse(format!(
            "decimal precision {decimals} is too large: 10^{decimals} overflows i128"
        ))
    })?;
    whole.checked_mul(scale).ok_or_else(|| {
        TestkitError::Misuse(format!(
            "converting {whole} whole units at {decimals} decimals overflows i128 (scale factor: {scale})"
        ))
    })
}

/// Convert a base-unit amount into whole units at the given decimal precision.
///
/// Returns `Err(TestkitError::Misuse)` with actionable context if `10^decimals` overflows `i128`.
///
/// # Example
///
/// ```
/// use soroban_testkit::tokens::base_to_whole_units;
///
/// let whole = base_to_whole_units(100_000_000, 7).unwrap();
/// assert_eq!(whole, 10);
/// ```
pub fn base_to_whole_units(base: i128, decimals: u32) -> Result<i128, TestkitError> {
    let scale = 10i128.checked_pow(decimals).ok_or_else(|| {
        TestkitError::Misuse(format!(
            "decimal precision {decimals} is too large: 10^{decimals} overflows i128"
        ))
    })?;
    Ok(base / scale)
}

impl TestEnv {
    /// Deploy a Stellar Asset Contract with the standard 7 decimals, using a
    /// fresh test address as its admin.
    ///
    /// The admin's authorization is mocked for minting, so [`TestToken::mint`]
    /// / [`TestToken::mint_raw`] need no global auth mocking; other operations
    /// still do — see [`crate::tokens`].
    ///
    /// The token admin is an implementation detail of the double and does **not**
    /// advance the `TestEnv` address stream. Calling `token()` before, after, or
    /// between [`TestEnv::address`] / [`TestEnv::addresses`] calls therefore has
    /// no effect on subsequent address generation: the seeded sequence remains
    /// stable regardless of call order.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let token = env.token();
    /// assert_eq!(token.decimals(), 7);
    /// ```
    pub fn token(&self) -> TestToken {
        // Use the raw SDK generator for the admin address so that calling
        // token() does not advance the TestEnv's own address counter.  The
        // admin is an internal implementation detail of the double; tests
        // should never need to refer to it.  Keeping it off the TestEnv
        // stream means the seeded address sequence stays stable regardless
        // of how many tokens are created and in what order.
        use soroban_sdk::testutils::Address as _;
        let admin = Address::generate(self.env());
        TestToken::new(self.env(), admin)
    }

    /// Deploy a Stellar Asset Contract, asserting it uses `decimals`.
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::Misuse`] if `decimals != 7`. Stellar
    /// Asset Contracts fix their decimal precision at 7 (the classic
    /// Stellar asset precision) — verified against soroban-sdk 27.0.6,
    /// where `register_stellar_asset_contract_v2` takes no decimals
    /// parameter. This method exists so a test that expects a specific
    /// precision fails loudly if that ever changes, rather than silently
    /// assuming it.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let token = env.token_with_decimals(7);
    /// assert_eq!(token.decimals(), 7);
    /// ```
    pub fn token_with_decimals(&self, decimals: u32) -> TestToken {
        if decimals != SAC_DECIMALS {
            panic!(
                "{}",
                TestkitError::Misuse(format!(
                    "token_with_decimals({decimals}): Stellar Asset Contracts fix decimals at \
                     {SAC_DECIMALS} and cannot be deployed with a different precision; use \
                     token() for the standard {SAC_DECIMALS}-decimal token"
                ))
            );
        }
        self.token()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{contract, contractimpl};

    #[test]
    fn token_is_immediately_usable_for_transfers() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();
        let bob = env.address();
        token.mint_raw(&alice, 100);

        TokenClient::new(env.env(), &token.address())
            .mock_auths(&[MockAuth {
                address: &alice,
                invoke: &MockAuthInvoke {
                    contract: &token.address(),
                    fn_name: "transfer",
                    args: (alice.clone(), bob.clone(), 30_i128).into_val(env.env()),
                    sub_invokes: &[],
                },
            }])
            .transfer(&alice, soroban_sdk::MuxedAddress::from(bob.clone()), &30);

        token.assert_balance(&alice, 70);
        token.assert_balance(&bob, 30);
    }

    #[test]
    fn mint_works_with_no_global_auth_mocking() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();

        // No mock_all_auths/mock_auths anywhere: the double mocks the SAC
        // admin's authorization for mint itself.
        token.mint(&alice, 2);
        token.mint_raw(&alice, 42);

        token.assert_balance(&alice, 2 * 10i128.pow(7) + 42);
    }

    #[test]
    fn transfers_still_require_authorization() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();
        let bob = env.address();
        token.mint_raw(&alice, 100);

        // Only minting is mocked; an un-authorized transfer must still fail.
        env.assert_requires_auth(|| {
            TokenClient::new(env.env(), &token.address()).transfer(
                &alice,
                soroban_sdk::MuxedAddress::from(bob.clone()),
                &10,
            );
        });
    }

    #[test]
    fn mint_converts_whole_units_at_seven_decimals() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();
        token.mint(&alice, 100);
        token.assert_balance(&alice, 1_000_000_000);
    }

    #[test]
    fn mint_and_mint_raw_disagree_by_exactly_ten_pow_decimals() {
        let env = TestEnv::new();
        let token = env.token();
        let a = env.address();
        let b = env.address();

        token.mint(&a, 1);
        token.mint_raw(&b, 1);

        assert_eq!(token.balance(&a), token.balance(&b) * 10i128.pow(7));
    }

    #[test]
    #[should_panic(expected = "token_with_decimals(6)")]
    fn token_with_decimals_rejects_non_seven() {
        let env = TestEnv::new();
        let _ = env.token_with_decimals(6);
    }

    #[test]
    fn total_tracked_sums_every_mint() {
        let env = TestEnv::new();
        let token = env.token();
        token.mint_raw(&env.address(), 10);
        token.mint(&env.address(), 1);
        assert_eq!(token.total_tracked(), 10 + 10i128.pow(7));
    }

    #[contract]
    struct Wallet;

    #[contractimpl]
    impl Wallet {
        pub fn send(env: Env, token: Address, from: Address, to: Address, amount: i128) {
            TokenClient::new(&env, &token).transfer(
                &from,
                soroban_sdk::MuxedAddress::from(to),
                &amount,
            );
        }

        pub fn spend(env: Env, token: Address, from: Address, amount: i128) {
            TokenClient::new(&env, &token).burn(&from, &amount);
        }

        pub fn allow(
            env: Env,
            token: Address,
            from: Address,
            spender: Address,
            amount: i128,
            live_until: u32,
        ) {
            TokenClient::new(&env, &token).approve(&from, &spender, &amount, &live_until);
        }
    }

    #[test]
    fn works_with_a_contract_that_transfers_burns_and_approves() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();
        let bob = env.address();
        let spender = env.address();
        token.mint_raw(&alice, 1_000);

        env.env().mock_all_auths_allowing_non_root_auth();
        let wallet_id = env.env().register(Wallet, ());
        let wallet = WalletClient::new(env.env(), &wallet_id);

        wallet.send(&token.address(), &alice, &bob, &300);
        token.assert_balance(&alice, 700);
        token.assert_balance(&bob, 300);

        wallet.spend(&token.address(), &alice, &200);
        token.assert_balance(&alice, 500);

        wallet.allow(&token.address(), &alice, &spender, &50, &1_000);
        let allowance = TokenClient::new(env.env(), &token.address()).allowance(&alice, &spender);
        assert_eq!(allowance, 50);
    }

    // ── Bug #462 regression: token() must not advance the TestEnv address stream ──

    #[test]
    fn token_does_not_consume_a_slot_in_the_address_stream() {
        // Without the fix, creating a token before generating addresses would
        // shift every subsequent address by one slot.
        let with_token_first = TestEnv::with_seed(42);
        let without_token = TestEnv::with_seed(42);

        let _token = with_token_first.token();
        let a1 = with_token_first.address();

        let a2 = without_token.address();

        assert_eq!(
            a1, a2,
            "token() shifted the address stream; the admin must not draw from TestEnv::address()"
        );
    }

    #[test]
    fn address_sequence_is_stable_regardless_of_token_call_position() {
        // token() called before, between, and after address() calls must
        // produce the same sequence a plain env with no token calls would.
        let env = TestEnv::with_seed(99);
        let reference = TestEnv::with_seed(99);

        let _t0 = env.token(); // token before first address
        let a1 = env.address();
        let _t1 = env.token(); // token between addresses
        let a2 = env.address();
        let _t2 = env.token(); // token after second address

        let r1 = reference.address();
        let r2 = reference.address();

        assert_eq!(a1, r1, "first address shifted by leading token() call");
        assert_eq!(a2, r2, "second address shifted by interleaved token() call");
    }

    #[test]
    fn multiple_tokens_do_not_shift_seeded_address_stream() {
        let env = TestEnv::with_seed(7);
        let reference = TestEnv::with_seed(7);

        // Create several tokens then generate a batch.
        let _t1 = env.token();
        let _t2 = env.token();
        let _t3 = env.token();
        let batch = env.addresses(4);

        let ref_batch = reference.addresses(4);

        assert_eq!(batch, ref_batch, "batch shifted by preceding token() calls");
    }

    // ── Table-driven fixture mint_many tests ──

    #[test]
    fn mint_many_funds_multiple_accounts_from_various_fixture_shapes() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();
        let bob = env.address();
        let carol = env.address();

        // 1. Array of references [(&Address, i128)]
        token.mint_many([(&alice, 10), (&bob, 20)]);
        token.assert_balance_whole(&alice, 10);
        token.assert_balance_whole(&bob, 20);

        // 2. Slice of references &[(&Address, i128)]
        token.mint_many(&[(&alice, 5), (&carol, 15)]);
        token.assert_balance_whole(&alice, 15);
        token.assert_balance_whole(&carol, 15);

        // 3. Vector of references vec![(&Address, i128)]
        token.mint_many(vec![(&bob, 5), (&carol, 5)]);
        token.assert_balance_whole(&bob, 25);
        token.assert_balance_whole(&carol, 20);

        // 4. Owned addresses [(Address, i128)]
        token.mint_many([(alice.clone(), 1), (bob.clone(), 2)]);
        token.assert_balance_whole(&alice, 16);
        token.assert_balance_whole(&bob, 27);

        // 5. Empty fixture is a no-op
        let total_before = token.total_tracked();
        token.mint_many(&[(&alice, 0)][..0]);
        assert_eq!(token.total_tracked(), total_before);
    }

    #[test]
    fn mint_many_raw_funds_in_base_units() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();
        let bob = env.address();

        token.mint_many_raw([(&alice, 100), (&bob, 200)]);
        token.assert_balance(&alice, 100);
        token.assert_balance(&bob, 200);
        assert_eq!(token.total_tracked(), 300);
    }

    #[test]
    fn try_mint_many_rejects_negative_amounts_cleanly() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();
        let bob = env.address();

        let err = token
            .try_mint_many([(&alice, 10), (&bob, -5)])
            .expect_err("negative amount should fail");
        assert!(err.is_misuse());
        assert!(err.message().contains("cannot mint negative amount -5"));
        assert_eq!(token.total_tracked(), 0);
    }

    #[test]
    #[should_panic(expected = "cannot mint negative amount -10")]
    fn mint_many_panics_on_negative_amount() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();
        token.mint_many([(&alice, -10)]);
    }

    #[test]
    #[should_panic(expected = "overflows i128")]
    fn mint_many_panics_on_overflow_amount() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();
        token.mint_many([(&alice, i128::MAX)]);
    }

    // ── Supply delta assertion tests ──

    #[test]
    fn assert_supply_delta_passes_on_matching_delta() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();

        // Positive delta on mint
        token.assert_supply_delta(100, || {
            token.mint_raw(&alice, 100);
        });

        // Zero delta when no mint occurs
        token.assert_supply_delta(0, || {
            // No minting
        });

        // Multiple mints combined
        token.assert_supply_delta(150, || {
            token.mint_raw(&alice, 50);
            token.mint_raw(&alice, 100);
        });
    }

    #[test]
    fn assert_supply_delta_whole_passes_on_matching_delta() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();

        token.assert_supply_delta_whole(5, || {
            token.mint(&alice, 5);
        });
    }

    #[test]
    #[should_panic(
        expected = "expected the call to change tracked token supply by 50 base units, but it went from 0 to 100 (delta=100)"
    )]
    fn assert_supply_delta_fails_when_delta_differs() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();

        token.assert_supply_delta(50, || {
            token.mint_raw(&alice, 100);
        });
    }

    #[test]
    #[should_panic(
        expected = "expected the call to change tracked token supply by 2 whole units (20000000 base units), but it went from 0 to 10000000 (delta=10000000)"
    )]
    fn assert_supply_delta_whole_fails_when_delta_differs() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();

        token.assert_supply_delta_whole(2, || {
            token.mint(&alice, 1);
        });
    }

    // ── Balance delta assertion tests ──

    #[test]
    fn assert_balance_delta_passes_on_positive_and_negative_changes() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();
        let bob = env.address();

        // Positive delta (mint)
        token.assert_balance_delta(&alice, 1_000, || {
            token.mint_raw(&alice, 1_000);
        });

        // Transfer: Alice decreases, Bob increases
        env.env().mock_all_auths_allowing_non_root_auth();
        let wallet_id = env.env().register(Wallet, ());
        let wallet = WalletClient::new(env.env(), &wallet_id);

        token.assert_balance_delta(&alice, -300, || {
            wallet.send(&token.address(), &alice, &bob, &300);
        });
        token.assert_balance(&alice, 700);
        token.assert_balance(&bob, 300);

        // Burn: Alice decreases
        token.assert_balance_delta(&alice, -200, || {
            wallet.spend(&token.address(), &alice, &200);
        });
        token.assert_balance(&alice, 500);

        // Zero delta
        token.assert_balance_delta(&alice, 0, || {
            // no-op
        });
    }

    #[test]
    fn assert_balance_delta_whole_passes() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();

        token.assert_balance_delta_whole(&alice, 10, || {
            token.mint(&alice, 10);
        });
        token.assert_balance_whole(&alice, 10);
    }

    #[test]
    #[should_panic(expected = "expected the call to change balance of")]
    fn assert_balance_delta_fails_on_mismatch() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();

        token.assert_balance_delta(&alice, 50, || {
            token.mint_raw(&alice, 30);
        });
    }

    #[test]
    #[should_panic(expected = "expected the call to change balance of")]
    fn assert_balance_delta_whole_fails_on_mismatch() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();

        token.assert_balance_delta_whole(&alice, 5, || {
            token.mint(&alice, 2);
        });
    }

    #[test]
    fn assert_balances_delta_checks_multiple_accounts() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();
        let bob = env.address();
        token.mint_raw(&alice, 500);

        env.env().mock_all_auths_allowing_non_root_auth();
        let wallet_id = env.env().register(Wallet, ());
        let wallet = WalletClient::new(env.env(), &wallet_id);

        // Simultaneous sender decrease and recipient increase
        token.assert_balances_delta([(&alice, -200), (&bob, 200)], || {
            wallet.send(&token.address(), &alice, &bob, &200);
        });
        token.assert_balance(&alice, 300);
        token.assert_balance(&bob, 200);

        // Whole unit multi-balance delta assertion
        token.assert_balances_delta_whole([(&alice, 5), (&bob, 10)], || {
            token.mint(&alice, 5);
            token.mint(&bob, 10);
        });
    }

    #[test]
    #[should_panic(expected = "expected the call to change balance of")]
    fn assert_balances_delta_fails_when_any_account_mismatches() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();
        let bob = env.address();

        token.assert_balances_delta([(&alice, 100), (&bob, 200)], || {
            token.mint_raw(&alice, 100);
            token.mint_raw(&bob, 150); // Mismatch!
        });
    }

    // ── Token snapshot and diff tests ──

    #[test]
    fn token_snapshot_and_diff_reports_deltas_and_asserts() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();
        let bob = env.address();

        let before = token.snapshot(&alice);
        assert_eq!(before.balance(), 0);
        assert_eq!(before.balance_whole().unwrap(), 0);
        assert_eq!(before.tracked_supply(), 0);
        assert_eq!(before.account(), Some(&alice));
        assert_eq!(before.token(), &token.address());

        token.mint(&alice, 10); // 100_000_000 stroops
        token.mint_raw(&bob, 500);

        let after = token.snapshot(&alice);
        assert_eq!(after.balance(), 100_000_000);
        assert_eq!(after.balance_whole().unwrap(), 10);
        assert_eq!(after.tracked_supply(), 100_000_500);

        let diff = before.diff(&after);
        assert_eq!(diff.token(), &token.address());
        assert_eq!(diff.account(), Some(&alice));
        assert_eq!(diff.balance_delta(), 100_000_000);
        assert_eq!(diff.balance_delta_whole().unwrap(), 10);
        assert_eq!(diff.supply_delta(), 100_000_500);

        diff.assert_balance_delta(100_000_000);
        diff.assert_balance_delta_whole(10);
        diff.assert_supply_delta(100_000_500);
    }

    #[test]
    fn snapshot_supply_and_snapshot_accounts_work() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();
        let bob = env.address();

        let snap_supply_before = token.snapshot_supply();
        assert_eq!(snap_supply_before.tracked_supply(), 0);
        assert_eq!(snap_supply_before.account(), None);

        token.mint_many([(&alice, 5), (&bob, 10)]);

        let snap_supply_after = token.snapshot_supply();
        assert_eq!(snap_supply_after.tracked_supply_whole().unwrap(), 15);

        let diff_supply = snap_supply_before.diff(&snap_supply_after);
        diff_supply.assert_supply_delta_whole(15);

        let accounts_snap = token.snapshot_accounts([&alice, &bob]);
        assert_eq!(accounts_snap.balance_of(&alice), Some(50_000_000));
        assert_eq!(accounts_snap.balance_of_whole(&alice).unwrap(), Some(5));
        assert_eq!(accounts_snap.balance_of(&bob), Some(100_000_000));
        assert_eq!(accounts_snap.balance_of_whole(&bob).unwrap(), Some(10));
    }

    #[test]
    #[should_panic(expected = "cannot diff snapshots from different tokens")]
    fn diff_rejects_snapshots_from_different_tokens() {
        let env = TestEnv::new();
        let t1 = env.token();
        let t2 = env.token();
        let alice = env.address();

        let s1 = t1.snapshot(&alice);
        let s2 = t2.snapshot(&alice);
        let _ = s1.diff(&s2);
    }

    #[test]
    #[should_panic(expected = "cannot diff snapshots for different primary accounts")]
    fn diff_rejects_snapshots_from_different_accounts() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();
        let bob = env.address();

        let s1 = token.snapshot(&alice);
        let s2 = token.snapshot(&bob);
        let _ = s1.diff(&s2);
    }

    #[test]
    #[should_panic(expected = "snapshot has no primary account")]
    fn balance_panics_on_supply_only_snapshot() {
        let env = TestEnv::new();
        let token = env.token();
        let snap = token.snapshot_supply();
        let _ = snap.balance();
    }

    #[test]
    #[should_panic(expected = "diff has no primary account balance delta")]
    fn balance_delta_panics_on_supply_only_diff() {
        let env = TestEnv::new();
        let token = env.token();
        let s1 = token.snapshot_supply();
        let s2 = token.snapshot_supply();
        let diff = s1.diff(&s2);
        let _ = diff.balance_delta();
    }

    #[test]
    #[should_panic(expected = "expected snapshot balance delta of")]
    fn diff_assert_balance_delta_panics_on_mismatch() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();

        let s1 = token.snapshot(&alice);
        token.mint_raw(&alice, 100);
        let s2 = token.snapshot(&alice);

        s1.diff(&s2).assert_balance_delta(50);
    }

    #[test]
    #[should_panic(expected = "expected snapshot supply delta of")]
    fn diff_assert_supply_delta_panics_on_mismatch() {
        let env = TestEnv::new();
        let token = env.token();
        let alice = env.address();

        let s1 = token.snapshot(&alice);
        token.mint_raw(&alice, 100);
        let s2 = token.snapshot(&alice);

        s1.diff(&s2).assert_supply_delta(50);
    }
}
