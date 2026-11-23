use soroban_sdk::Address;

use crate::core::{TestEnv, TestkitError};

type InvokeFn<'a> = Box<dyn Fn(&Address) -> Result<(), soroban_sdk::Error> + 'a>;

/// What actually happened when one (entry point, caller) cell was invoked.
enum Outcome {
    /// The call succeeded.
    Pass,
    /// The call was rejected by an authorization failure (or any non-contract
    /// error / panic, which is how the host surfaces a failed `require_auth`).
    AuthRejected,
    /// The call failed with a contract-defined error (`ScErrorType::Contract`)
    /// — a business-logic failure such as "insufficient balance", which says
    /// nothing about whether the caller was authorized.
    ContractError(String),
}

impl Outcome {
    fn from_result(result: Result<(), soroban_sdk::Error>) -> Self {
        match result {
            Ok(()) => Outcome::Pass,
            Err(e) if e.is_type(soroban_sdk::xdr::ScErrorType::Contract) => {
                Outcome::ContractError(format!("{e:?}"))
            }
            Err(_) => Outcome::AuthRejected,
        }
    }

    fn from_panic(payload: &(dyn std::any::Any + Send)) -> Self {
        match contract_error_in_panic(payload) {
            Some(err) => Outcome::ContractError(err),
            None => Outcome::AuthRejected,
        }
    }

    fn label(&self) -> String {
        match self {
            Outcome::Pass => "pass".into(),
            Outcome::AuthRejected => "reject".into(),
            Outcome::ContractError(err) => format!("error {err} (not an auth rejection)"),
        }
    }
}

/// If a panic payload is a Soroban host error raised by a contract-defined
/// error (`HostError: Error(Contract, #N)`), return the `Error(Contract, #N)`
/// text. Any other panic — including `Error(Auth, ...)` — returns `None`.
fn contract_error_in_panic(payload: &(dyn std::any::Any + Send)) -> Option<String> {
    let message = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())?;
    let start = message.find("Error(Contract, ")?;
    let end = start + message[start..].find(')')? + 1;
    Some(message[start..end].to_string())
}

struct EntryPointSpec<'a> {
    name: String,
    allowed: Vec<Address>,
    invoke: InvokeFn<'a>,
}

/// A declarative table of who may call what, so that a contract's full
/// caller/entry-point grid is checked by default instead of the four cases
/// someone thought to write by hand.
///
/// Register each privileged entry point with [`AuthMatrix::entry_point`],
/// then call [`AuthMatrix::assert_enforced`] to check that every allowed
/// address succeeds and every other **known actor** is rejected, for every
/// entry point.
///
/// # What counts as a "known actor"
///
/// A *known actor* is any address named in at least one entry point's
/// `allowed` list — the de-duplicated union across every registered entry
/// point, returned by [`AuthMatrix::known_actors`]. The matrix cross-checks
/// each known actor against *every* entry point, not only the one that named
/// it: that is how an actor permitted elsewhere gets caught on a privileged
/// entry point that should have rejected it.
///
/// An address that is never listed on any entry point is **not** a known
/// actor and is never placed in the grid, so a caller that should be rejected
/// must still be named on at least one entry point to be covered.
pub struct AuthMatrix<'a> {
    // Ties the matrix's lifetime to its TestEnv; entry point closures
    // capture their own references into it independently.
    #[allow(dead_code)]
    env: &'a TestEnv,
    entry_points: Vec<EntryPointSpec<'a>>,
}

impl<'a> AuthMatrix<'a> {
    /// Start an empty matrix against `env`.
    pub fn new(env: &'a TestEnv) -> Self {
        Self {
            env,
            entry_points: Vec::new(),
        }
    }

    /// Register a privileged entry point: its name (for failure messages),
    /// the addresses permitted to call it, and a closure that attempts the
    /// call as a given caller, returning `Ok(())` if it succeeded and
    /// `Err` if the contract rejected it.
    ///
    /// # Authorization failures vs. unrelated contract errors
    ///
    /// Only an *authorization* failure counts as a rejection. Return a
    /// non-contract error for it — for example
    /// `soroban_sdk::Error::from((ScErrorType::Auth, ScErrorCode::InvalidAction))`,
    /// which is what the host raises for a failed `require_auth`, or map a
    /// typed client's `Err(Err(InvokeError::Abort))` to it. A panic inside
    /// `invoke` is also treated as a rejection.
    ///
    /// An error of type `ScErrorType::Contract` (a `#[contracterror]` value
    /// such as "insufficient balance", or a panic carrying
    /// `HostError: Error(Contract, #N)`) is an **unrelated contract error**:
    /// the call failed before it proved anything about authorization, so it
    /// is never accepted as a rejection and is reported as a mismatch.
    ///
    /// An `allowed` list may be empty: the entry point then permits nobody,
    /// and every known actor (named on some *other* entry point) must be
    /// rejected by it.
    ///
    /// `invoke` is typically built from a generated client's `try_*`
    /// method with the candidate address mocked as the caller — see
    /// [`AuthMatrix::assert_enforced`]'s example.
    ///
    /// # Duplicates
    ///
    /// Repeating an address in `allowed` is harmless: the matrix de-duplicates
    /// addresses before building its grid, so a duplicated caller is still
    /// checked exactly once per entry point rather than being counted (or
    /// reported) twice.
    ///
    /// Entry-point *names* are not required to be unique. Registering the same
    /// name twice produces two independently-checked sections in the report —
    /// useful when one contract function is expected to behave differently
    /// under two different setups — but the failure message will name both
    /// with the same string, so give them distinct names unless the
    /// duplication is deliberate.
    pub fn entry_point(
        mut self,
        name: &str,
        allowed: &[Address],
        invoke: impl Fn(&Address) -> Result<(), soroban_sdk::Error> + 'a,
    ) -> Self {
        self.entry_points.push(EntryPointSpec {
            name: name.to_string(),
            allowed: allowed.to_vec(),
            invoke: Box::new(invoke),
        });
        self
    }

    /// The matrix's **known actors**: every address named in any entry
    /// point's `allowed` list, de-duplicated and kept in first-seen order.
    ///
    /// These are exactly the addresses [`AuthMatrix::assert_enforced`] places
    /// in its grid; an address that never appears as `allowed` on any entry
    /// point is not a known actor and is not checked.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::auth::AuthMatrix;
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let alice = env.address();
    /// let bob = env.address();
    ///
    /// let matrix = AuthMatrix::new(&env)
    ///     .entry_point("a", &[alice.clone()], |_| Ok(()))
    ///     .entry_point("b", &[alice.clone(), bob.clone()], |_| Ok(()));
    ///
    /// // `alice` is named on both entry points but appears once.
    /// assert_eq!(matrix.known_actors(), vec![alice, bob]);
    /// ```
    pub fn known_actors(&self) -> Vec<Address> {
        let mut known: Vec<Address> = Vec::new();
        for ep in &self.entry_points {
            for addr in &ep.allowed {
                if !known.contains(addr) {
                    known.push(addr.clone());
                }
            }
        }
        known
    }

    /// Reset all authorization entries and mock authorizations in the test environment.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    /// use soroban_testkit::auth::AuthMatrix;
    ///
    /// let env = TestEnv::new();
    /// let matrix = AuthMatrix::new(&env);
    /// matrix.reset_auth();
    /// ```
    pub fn reset_auth(&self) {
        self.env.env().set_auths(&[]);
    }

    /// For every registered entry point, assert every allowed address
    /// succeeds and every other **known actor** (see [`AuthMatrix`] and
    /// [`AuthMatrix::known_actors`]) fails.
    ///
    /// Known addresses are de-duplicated, so an address listed more than once
    /// — on one entry point or across several — is still checked (and counted)
    /// exactly once per entry point.
    ///
    /// A cell expected to be rejected only passes when the call fails with an
    /// authorization failure; an unrelated contract error is reported as a
    /// mismatch (see [`AuthMatrix::entry_point`]).
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::AssertionFailed`] naming every
    /// violating (entry point, caller) cell, followed by the full grid
    /// (every cell's expected vs. actual outcome) so a passing cell isn't
    /// mistaken for a gap in coverage.
    ///
    /// Panics with a [`TestkitError::Misuse`] if the grid would be empty —
    /// no entry point was registered, or every entry point's `allowed` list
    /// is empty so there are no known actors — because such a matrix checks
    /// nothing and would otherwise pass vacuously.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_sdk::xdr::{ScErrorCode, ScErrorType};
    /// use soroban_testkit::auth::AuthMatrix;
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let owner = env.address();
    ///
    /// // A single-entry-point matrix where the only allowed caller is
    /// // itself: trivially enforced.
    /// AuthMatrix::new(&env)
    ///     .entry_point("noop", &[owner.clone()], move |caller| {
    ///         if *caller == owner {
    ///             Ok(())
    ///         } else {
    ///             Err(soroban_sdk::Error::from((ScErrorType::Auth, ScErrorCode::InvalidAction)))
    ///         }
    ///     })
    ///     .assert_enforced();
    /// ```
    pub fn assert_enforced(self) {
        let known = self.known_actors();

        if self.entry_points.is_empty() {
            panic!(
                "{}",
                TestkitError::Misuse(
                    "auth matrix has no registered entry points, so it checks nothing; \
                     register each privileged entry point with AuthMatrix::entry_point \
                     before calling assert_enforced"
                        .into()
                )
            );
        }
        if known.is_empty() {
            let names: Vec<&str> = self
                .entry_points
                .iter()
                .map(|ep| ep.name.as_str())
                .collect();
            panic!(
                "{}",
                TestkitError::Misuse(format!(
                    "auth matrix has no known actors: every entry point ({}) has an empty \
                     allowed list, so no caller is checked; name at least one address in \
                     some entry point's allowed list",
                    names.join(", ")
                ))
            );
        }

        let mut violations = Vec::new();
        let mut grid = format!(
            "known actors = union of all entry points' allowed lists ({} address(es)); \
             each is checked against every entry point\n",
            known.len()
        );

        for ep in &self.entry_points {
            grid.push_str(&format!("  [{}]\n", ep.name));
            for addr in &known {
                let expected = ep.allowed.contains(addr);
                // Reset auth state before invoking this actor case so that
                // previously mocked or recorded auths do not leak into it.
                self.reset_auth();
                let actual = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    (ep.invoke)(addr)
                })) {
                    Ok(result) => Outcome::from_result(result),
                    Err(payload) => Outcome::from_panic(payload.as_ref()),
                };
                let matches = match actual {
                    Outcome::Pass => expected,
                    Outcome::AuthRejected => !expected,
                    // A contract error proves nothing about authorization:
                    // it is never an acceptable outcome for any cell.
                    Outcome::ContractError(_) => false,
                };
                // Reset auth state immediately after invocation to keep the
                // slate clean for the next actor case.
                self.reset_auth();

                grid.push_str(&format!(
                    "    {addr:?}: expected={} actual={}{}\n",
                    if expected { "pass" } else { "reject" },
                    actual.label(),
                    if matches { "" } else { "  <-- MISMATCH" },
                ));
                if !matches {
                    violations.push(format!(
                        "entry point {:?}: caller {addr:?} expected to {} but {}",
                        ep.name,
                        if expected {
                            "succeed"
                        } else {
                            "be rejected for authorization"
                        },
                        match &actual {
                            Outcome::Pass => "succeeded".to_string(),
                            Outcome::AuthRejected => "was rejected".to_string(),
                            Outcome::ContractError(err) => format!(
                                "failed with unrelated contract error {err}, which is not an \
                                 authorization failure (check the call's arguments and contract \
                                 state so it reaches the auth check)"
                            ),
                        },
                    ));
                }
            }
        }

        if !violations.is_empty() {
            panic!(
                "{}",
                TestkitError::AssertionFailed(format!(
                    "auth matrix violated ({} of {} cells):\n{}\nfull grid:\n{grid}",
                    violations.len(),
                    self.entry_points.len() * known.len(),
                    violations.join("\n"),
                ))
            );
        }
    }
}

impl TestEnv {
    /// Reset any active authorizations or mocked auths in this environment.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// env.reset_auth();
    /// ```
    pub fn reset_auth(&self) {
        self.env().set_auths(&[]);
    }

    /// Assert that `f` fails when it runs without the authorization it
    /// requires — the single-call counterpart to [`AuthMatrix`], for a
    /// caller that just needs "this must reject an unauthorized attempt"
    /// without a full grid.
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::AssertionFailed`] if `f` completes
    /// (returns) instead of failing. The message names the exact address(es)
    /// whose authorization the call recorded (for example a caller `f` mocked
    /// itself), or states that no address authorized it — meaning the call
    /// never reached a `require_auth` check.
    ///
    /// Also panics with a [`TestkitError::AssertionFailed`] if `f` fails with
    /// an unrelated contract error (`HostError: Error(Contract, #N)`), since
    /// that failure says nothing about whether authorization is enforced.
    ///
    /// # Example
    ///
    /// ```should_panic
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// // A closure that succeeds unconditionally can never satisfy this.
    /// env.assert_requires_auth(|| {});
    /// ```
    pub fn assert_requires_auth(&self, f: impl FnOnce()) {
        self.reset_auth();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        // Capture who authorized the call before resetting auth state.
        let callers: Vec<Address> = match result {
            Ok(()) => self
                .env()
                .auths()
                .into_iter()
                .map(|(addr, _)| addr)
                .collect(),
            Err(_) => Vec::new(),
        };
        self.reset_auth();
        match result {
            Ok(()) => {
                let by = if callers.is_empty() {
                    "no address authorized it, so the call never reached a require_auth check"
                        .to_string()
                } else {
                    let names: Vec<String> = callers.iter().map(|a| format!("{a:?}")).collect();
                    format!("it was authorized by caller(s) {}", names.join(", "))
                };
                panic!(
                    "{}",
                    TestkitError::AssertionFailed(format!(
                        "expected the call to fail without authorization, but it succeeded: {by}"
                    ))
                );
            }
            Err(payload) => {
                if let Some(err) = contract_error_in_panic(payload.as_ref()) {
                    panic!(
                        "{}",
                        TestkitError::AssertionFailed(format!(
                            "expected the call to fail for lack of authorization, but it failed \
                             with unrelated contract error {err}; fix the call's arguments or \
                             contract state so it reaches the auth check"
                        ))
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{MockAuth, MockAuthInvoke};
    use soroban_sdk::IntoVal;
    use vault::{VaultClient, VaultError};

    fn flatten<T>(
        result: Result<
            Result<T, soroban_sdk::ConversionError>,
            Result<VaultError, soroban_sdk::InvokeError>,
        >,
    ) -> Result<(), soroban_sdk::Error> {
        match result {
            Ok(Ok(_)) => Ok(()),
            // A contract-defined error is preserved so the matrix can tell it
            // apart from an authorization failure.
            Err(Ok(err)) => Err(err.into()),
            // Typed clients surface a failed `require_auth` as an abort.
            _ => Err(auth_error()),
        }
    }

    fn auth_error() -> soroban_sdk::Error {
        soroban_sdk::Error::from((
            soroban_sdk::xdr::ScErrorType::Auth,
            soroban_sdk::xdr::ScErrorCode::InvalidAction,
        ))
    }

    fn mock_withdraw_checked(
        env: &TestEnv,
        vault_id: &Address,
        caller: &Address,
        amount: i128,
    ) -> Result<(), soroban_sdk::Error> {
        let result = VaultClient::new(env.env(), vault_id)
            .mock_auths(&[MockAuth {
                address: caller,
                invoke: &MockAuthInvoke {
                    contract: vault_id,
                    fn_name: "withdraw_checked",
                    args: (amount,).into_val(env.env()),
                    sub_invokes: &[],
                },
            }])
            .try_withdraw_checked(&amount);
        flatten(result)
    }

    fn panic_message(err: Box<dyn std::any::Any + Send>) -> String {
        err.downcast_ref::<String>()
            .cloned()
            .or_else(|| err.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default()
    }

    #[test]
    fn known_actors_is_the_deduped_union_in_first_seen_order() {
        let env = TestEnv::new();
        let alice = env.address();
        let bob = env.address();
        let carol = env.address();

        let matrix = AuthMatrix::new(&env)
            .entry_point("a", &[alice.clone(), bob.clone()], |_| Ok(()))
            .entry_point("b", &[bob.clone(), carol.clone()], |_| Ok(()));

        // `bob` is named on both entry points but appears once; order follows
        // first appearance.
        assert_eq!(matrix.known_actors(), vec![alice, bob, carol]);
    }

    #[test]
    fn known_actors_ignores_addresses_never_listed() {
        let env = TestEnv::new();
        let listed = env.address();
        let never_listed = env.address();

        let matrix =
            AuthMatrix::new(&env).entry_point("only", std::slice::from_ref(&listed), |_| Ok(()));

        let known = matrix.known_actors();
        assert_eq!(known, vec![listed]);
        assert!(
            !known.contains(&never_listed),
            "an address never listed as allowed is not a known actor"
        );
    }

    #[test]
    fn assert_enforced_report_states_the_known_actor_definition() {
        let env = TestEnv::new();
        let owner = env.address();
        let attacker = env.address();

        // `open` allows both callers (making both "known"), while `guarded`
        // is buggy: it allows everyone. `attacker` is known from `open` and so
        // is cross-checked against `guarded`, where it wrongly succeeds.
        let matrix = AuthMatrix::new(&env)
            .entry_point("open", &[owner.clone(), attacker.clone()], |_| Ok(()))
            .entry_point("guarded", std::slice::from_ref(&owner), |_| Ok(()));

        let err =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| matrix.assert_enforced()))
                .expect_err("guarded allows everyone, so the attacker cell must be caught");
        let message = panic_message(err);

        assert!(
            message.contains("known actors = union of all entry points' allowed lists"),
            "the report must state the definition of a known actor: {message}"
        );
        assert!(
            message.contains(&format!("{attacker:?}")),
            "the report must name the offending known actor: {message}"
        );
    }

    #[test]
    fn assert_enforced_catches_a_real_missing_auth_bug() {
        let env = TestEnv::new();
        let owner = env.address();
        let attacker = env.address();
        let vault_id = env.env().register(vault::Vault, ());
        VaultClient::new(env.env(), &vault_id).initialize(&owner);
        VaultClient::new(env.env(), &vault_id).deposit(&100);

        // `deposit` is legitimately open to anyone, which is what puts
        // `attacker` into the matrix's "known addresses" set. `withdraw`
        // (the buggy entry point) never calls owner.require_auth(), so
        // when we check that only `owner` may withdraw, `attacker` — a
        // known address the matrix now cross-checks against every entry
        // point — incorrectly succeeds too. That's exactly the bug.
        let matrix = AuthMatrix::new(&env)
            .entry_point(
                "deposit",
                &[owner.clone(), attacker.clone()],
                |caller: &Address| {
                    let result = VaultClient::new(env.env(), &vault_id)
                        .mock_auths(&[MockAuth {
                            address: caller,
                            invoke: &MockAuthInvoke {
                                contract: &vault_id,
                                fn_name: "deposit",
                                args: (1_i128,).into_val(env.env()),
                                sub_invokes: &[],
                            },
                        }])
                        .try_deposit(&1);
                    flatten(result)
                },
            )
            .entry_point(
                "withdraw",
                std::slice::from_ref(&owner),
                |caller: &Address| {
                    let result = VaultClient::new(env.env(), &vault_id)
                        .mock_auths(&[MockAuth {
                            address: caller,
                            invoke: &MockAuthInvoke {
                                contract: &vault_id,
                                fn_name: "withdraw",
                                args: (10_i128,).into_val(env.env()),
                                sub_invokes: &[],
                            },
                        }])
                        .try_withdraw(&10);
                    flatten(result)
                },
            );

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            matrix.assert_enforced();
        }));

        let err = result.expect_err("expected assert_enforced to catch the missing auth check");
        let message = err
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| err.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default();
        assert!(
            message.contains("withdraw"),
            "failure message should name the entry point: {message}"
        );
        assert!(
            message.contains(&format!("{attacker:?}")),
            "failure message should name the offending caller: {message}"
        );
    }

    #[test]
    fn assert_enforced_passes_once_the_bug_is_fixed() {
        let env = TestEnv::new();
        let owner = env.address();
        let other = env.address();
        let vault_id = env.env().register(vault::Vault, ());
        VaultClient::new(env.env(), &vault_id).initialize(&owner);
        VaultClient::new(env.env(), &vault_id).deposit(&100);

        // Same shape as the buggy-case test (two entry points, so `other`
        // is a known address cross-checked against withdraw_checked), but
        // against the fixed entry point: `other` is correctly rejected.
        AuthMatrix::new(&env)
            .entry_point(
                "deposit",
                &[owner.clone(), other.clone()],
                |caller: &Address| {
                    let result = VaultClient::new(env.env(), &vault_id)
                        .mock_auths(&[MockAuth {
                            address: caller,
                            invoke: &MockAuthInvoke {
                                contract: &vault_id,
                                fn_name: "deposit",
                                args: (1_i128,).into_val(env.env()),
                                sub_invokes: &[],
                            },
                        }])
                        .try_deposit(&1);
                    flatten(result)
                },
            )
            .entry_point(
                "withdraw_checked",
                std::slice::from_ref(&owner),
                |caller: &Address| {
                    let result = VaultClient::new(env.env(), &vault_id)
                        .mock_auths(&[MockAuth {
                            address: caller,
                            invoke: &MockAuthInvoke {
                                contract: &vault_id,
                                fn_name: "withdraw_checked",
                                args: (10_i128,).into_val(env.env()),
                                sub_invokes: &[],
                            },
                        }])
                        .try_withdraw_checked(&10);
                    flatten(result)
                },
            )
            .assert_enforced();
    }

    #[test]
    fn a_duplicated_allowed_address_is_checked_once_not_twice() {
        let env = TestEnv::new();
        let alice = env.address();

        // The same actor listed twice in one `allowed` list must still count
        // as a single known address: the report should cover one cell, not two.
        let matrix =
            AuthMatrix::new(&env).entry_point("dup", &[alice.clone(), alice.clone()], |_| {
                Err(auth_error())
            });

        let err =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| matrix.assert_enforced()))
                .expect_err("alice is expected to pass but is rejected");
        let message = panic_message(err);

        assert!(
            message.contains("of 1 cells"),
            "a duplicated actor must be counted once: {message}"
        );
    }

    #[test]
    fn duplicate_entry_point_names_produce_independent_sections() {
        let env = TestEnv::new();
        let alice = env.address();

        // Deliberately reusing a name: both sections are checked separately,
        // one violating and one passing, and both appear in the report.
        let matrix = AuthMatrix::new(&env)
            .entry_point("deposit", std::slice::from_ref(&alice), |_| {
                Err(auth_error())
            })
            .entry_point("deposit", std::slice::from_ref(&alice), |_| Ok(()));

        let err =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| matrix.assert_enforced()))
                .expect_err("the first `deposit` rejects alice and must be flagged");
        let message = panic_message(err);

        assert_eq!(
            message.matches("[deposit]").count(),
            2,
            "two entry points sharing a name must both be reported: {message}"
        );
        assert!(
            message.contains("of 2 cells"),
            "each same-named entry point still gets its own cells: {message}"
        );
    }

    // ── #152: authorization failures vs. unrelated contract errors ─────────

    #[test]
    fn an_unrelated_contract_error_is_not_counted_as_an_auth_rejection() {
        let env = TestEnv::new();
        let owner = env.address();
        let attacker = env.address();
        let vault_id = env.env().register(vault::Vault, ());
        // Initialized but never funded: every withdrawal hits
        // `InsufficientBalance`, whoever the caller is.
        VaultClient::new(env.env(), &vault_id).initialize(&owner);

        // `withdraw` has no auth check at all. With an empty vault the attacker
        // still fails — but with a business error, not an auth rejection. The
        // matrix must not mistake that for proof that auth is enforced.
        let matrix = AuthMatrix::new(&env)
            .entry_point("open", &[owner.clone(), attacker.clone()], |_| Ok(()))
            .entry_point("withdraw", std::slice::from_ref(&owner), |caller| {
                let result = VaultClient::new(env.env(), &vault_id)
                    .mock_auths(&[MockAuth {
                        address: caller,
                        invoke: &MockAuthInvoke {
                            contract: &vault_id,
                            fn_name: "withdraw",
                            args: (10_i128,).into_val(env.env()),
                            sub_invokes: &[],
                        },
                    }])
                    .try_withdraw(&10);
                flatten(result)
            });

        let err =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| matrix.assert_enforced()))
                .expect_err("a contract error must not satisfy an expected auth rejection");
        let message = panic_message(err);

        assert!(
            message.contains(&format!(
                "entry point \"withdraw\": caller {attacker:?} expected to be rejected for \
                 authorization but failed with unrelated contract error Error(Contract, #2)"
            )),
            "the report must name the unrelated contract error for the attacker: {message}"
        );
        assert!(
            message.contains("not an auth rejection"),
            "the grid must label the cell as a non-auth failure: {message}"
        );
    }

    #[test]
    fn a_contract_error_panic_is_not_counted_as_an_auth_rejection() {
        let env = TestEnv::new();
        let owner = env.address();
        let attacker = env.address();
        let vault_id = env.env().register(vault::Vault, ());
        VaultClient::new(env.env(), &vault_id).initialize(&owner);

        // Same bug, but invoked through the panicking (non-`try_`) client.
        let matrix = AuthMatrix::new(&env)
            .entry_point("open", &[owner.clone(), attacker.clone()], |_| Ok(()))
            .entry_point("withdraw", std::slice::from_ref(&owner), |_| {
                env.env().mock_all_auths();
                VaultClient::new(env.env(), &vault_id).withdraw(&10);
                Ok(())
            });

        let err =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| matrix.assert_enforced()))
                .expect_err("a contract-error panic must not satisfy an expected auth rejection");
        let message = panic_message(err);

        assert!(
            message.contains("unrelated contract error Error(Contract, #2)"),
            "the report must name the contract error behind the panic: {message}"
        );
    }

    #[test]
    fn a_real_auth_failure_still_counts_as_a_rejection() {
        let env = TestEnv::new();
        let owner = env.address();
        let other = env.address();
        let vault_id = env.env().register(vault::Vault, ());
        VaultClient::new(env.env(), &vault_id).initialize(&owner);
        VaultClient::new(env.env(), &vault_id).deposit(&100);

        // `withdraw_checked` rejects `other` with Error(Auth, InvalidAction),
        // which surfaces from the typed client as an abort.
        AuthMatrix::new(&env)
            .entry_point("open", &[owner.clone(), other.clone()], |_| Ok(()))
            .entry_point("withdraw_checked", std::slice::from_ref(&owner), |caller| {
                mock_withdraw_checked(&env, &vault_id, caller, 10)
            })
            .assert_enforced();
    }

    // ── #154: a matrix with no registered entry points ─────────────────────

    #[test]
    fn a_matrix_with_no_entry_points_is_rejected_as_misuse() {
        let env = TestEnv::new();
        let matrix = AuthMatrix::new(&env);

        assert!(matrix.known_actors().is_empty());

        let err =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| matrix.assert_enforced()))
                .expect_err("an empty matrix checks nothing and must not pass vacuously");
        let message = panic_message(err);

        assert!(
            message
                .starts_with("misuse of testkit API: auth matrix has no registered entry points"),
            "an empty matrix must be reported as misuse: {message}"
        );
    }

    // ── #155: entry points with an empty allowed list ──────────────────────

    #[test]
    fn an_empty_allowed_list_requires_every_known_actor_to_be_rejected() {
        let env = TestEnv::new();
        let alice = env.address();
        let bob = env.address();

        // `frozen` permits nobody: both known actors must be rejected there.
        AuthMatrix::new(&env)
            .entry_point("open", &[alice.clone(), bob.clone()], |_| Ok(()))
            .entry_point("frozen", &[], |_| Err(auth_error()))
            .assert_enforced();
    }

    #[test]
    fn an_empty_allowed_list_flags_a_caller_that_succeeds() {
        let env = TestEnv::new();
        let alice = env.address();
        let bob = env.address();

        // `frozen` should permit nobody but lets `bob` through.
        let matrix = AuthMatrix::new(&env)
            .entry_point("open", &[alice.clone(), bob.clone()], |_| Ok(()))
            .entry_point("frozen", &[], |caller| {
                if *caller == bob {
                    Ok(())
                } else {
                    Err(auth_error())
                }
            });

        let err =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| matrix.assert_enforced()))
                .expect_err("bob succeeding on an entry point that allows nobody must be caught");
        let message = panic_message(err);

        assert!(
            message.contains(&format!(
                "entry point \"frozen\": caller {bob:?} expected to be rejected for \
                 authorization but succeeded"
            )),
            "the report must name the caller that got through: {message}"
        );
        assert!(
            message.contains("(1 of 4 cells)"),
            "the empty-allowed entry point still gets a cell per known actor: {message}"
        );
    }

    #[test]
    fn only_empty_allowed_lists_leave_no_known_actors_and_are_rejected_as_misuse() {
        let env = TestEnv::new();
        let matrix = AuthMatrix::new(&env)
            .entry_point("frozen", &[], |_| Ok(()))
            .entry_point("sealed", &[], |_| Ok(()));

        assert!(matrix.known_actors().is_empty());

        let err =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| matrix.assert_enforced()))
                .expect_err("a matrix with no known actors checks nothing");
        let message = panic_message(err);

        assert!(
            message.contains("auth matrix has no known actors")
                && message.contains("frozen, sealed"),
            "the misuse message must name the empty entry points: {message}"
        );
    }

    #[test]
    fn assert_requires_auth_passes_when_call_panics() {
        let env = TestEnv::new();
        env.assert_requires_auth(|| panic!("simulated auth failure"));
    }

    #[test]
    #[should_panic(expected = "expected the call to fail without authorization")]
    fn assert_requires_auth_panics_when_call_succeeds() {
        let env = TestEnv::new();
        env.assert_requires_auth(|| {});
    }

    #[test]
    fn assert_requires_auth_passes_on_a_real_auth_failure() {
        let env = TestEnv::new();
        let owner = env.address();
        let vault_id = env.env().register(vault::Vault, ());
        VaultClient::new(env.env(), &vault_id).initialize(&owner);
        VaultClient::new(env.env(), &vault_id).deposit(&100);

        env.assert_requires_auth(|| {
            VaultClient::new(env.env(), &vault_id).withdraw_checked(&10);
        });
    }

    #[test]
    fn assert_requires_auth_rejects_an_unrelated_contract_error() {
        let env = TestEnv::new();
        let vault_id = env.env().register(vault::Vault, ());
        // Not initialized: `withdraw_checked` fails with NotInitialized
        // before it ever reaches `require_auth`.
        let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            env.assert_requires_auth(|| {
                VaultClient::new(env.env(), &vault_id).withdraw_checked(&10);
            });
        }))
        .expect_err("a contract error is not proof that auth is required");
        let message = panic_message(err);

        assert!(
            message.contains("failed with unrelated contract error Error(Contract, #1)"),
            "the failure must name the unrelated contract error: {message}"
        );
    }

    // ── #153: the exact caller in assert_requires_auth failures ────────────

    #[test]
    fn assert_requires_auth_failure_names_the_exact_caller() {
        let env = TestEnv::new();
        let owner = env.address();
        let vault_id = env.env().register(vault::Vault, ());
        VaultClient::new(env.env(), &vault_id).initialize(&owner);
        VaultClient::new(env.env(), &vault_id).deposit(&100);

        // The closure mocks the owner's signature, so the call succeeds; the
        // failure must say exactly whose authorization let it through.
        let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            env.assert_requires_auth(|| {
                mock_withdraw_checked(&env, &vault_id, &owner, 10)
                    .expect("owner is authorized to withdraw");
            });
        }))
        .expect_err("the call succeeded, so the assertion must fail");
        let message = panic_message(err);

        assert!(
            message.contains(&format!("it was authorized by caller(s) {owner:?}")),
            "the failure must name the exact caller: {message}"
        );
    }

    #[test]
    fn assert_requires_auth_failure_says_when_no_caller_authorized() {
        let env = TestEnv::new();
        let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            env.assert_requires_auth(|| {});
        }))
        .expect_err("the call succeeded, so the assertion must fail");
        let message = panic_message(err);

        assert!(
            message.contains("no address authorized it"),
            "the failure must say no caller authorized the call: {message}"
        );
    }
}
