# Tests

```bash
pip install -r requirements.txt
python tests/run_all.py            # everything, one line per suite
python tests/test_demo_flow.py     # or any single file
```

No Google, Active Directory or network is needed. Nothing touches your real database or secrets.

## The suites

| File | Kind | Covers |
|---|---|---|
| `test_permissions.py` | rules | Roles, permissions, who may manage whom, capabilities for the pages, password rules |
| `test_twofa.py` | rules | Code checking and replay, drift, lockout, recovery codes, encrypted secrets, the pairing window |
| `test_loginlock.py` | rules | Password lockout, unknown-name tracking, memory pruning that never evicts active locks |
| `test_directory_cache.py` | rules | In-place cache updates, provisional lifetime, rebuilds, one failing group not breaking a rebuild |
| `test_twofa_flow.py` | end to end | Sign-in with and without two-step, enrolment, recovery codes, lockout, replay, audit log |
| `test_accounts_flow.py` | end to end | Creating, editing, deleting and resetting accounts; named roles; every protected route for every account type; hidden buttons |
| `test_lockout_and_profile_flow.py` | end to end | Password lockouts across sessions, username and email changes, no leaking of which names exist |
| `test_setup_prompts.py` | rules | First-run password prompts: a wrong confirmation repeats only the confirmation; short passwords are refused first |
| `test_ignore_list_flow.py` | end to end | The Settings > Ignore list page: what it shows, removing items, notes (length limit, editing, escaping), the dashboard "N ignored" link, and who may read or change it |
| `test_ou_cleanup_flow.py` | end to end | Deleting OUs Google no longer has: empty only, deepest first, ignore list, renames, failures, and the protections (base DN, outsiders, Domain Controllers) |
| `test_demo_flow.py` | end to end | A fresh install with no credentials, a full sync on the sample data, no email in Demo, the Demo / Live switch and its guards |

## How the end-to-end tests work

`tests/test_support.py` copies the project into a throwaway folder, builds a database in the **old** layout (to prove upgrades work),
and starts the real Flask app on it. It uses a controllable clock, so a test never waits for the next 30-second code, and a small
helper that behaves like a person: sign in, read the page, find the token, submit the form.

Because these drive the real routes and templates, a test fails if a page is broken, not just a function.

## What the tests do not cover

- The real Google Admin SDK and real LDAP. Demo's pretend connectors implement the same methods and return shapes, and are exercised end to end,
  but only a live run proves your environment works. Use Settings > Connection > *Run connection check*.
- Browser layout. The screenshots in `docs/images` were taken from a real headless browser run of the demo.

## Adding a test

Copy the nearest suite. Each file is a list of named steps; the runner prints PASS or FAIL per step and stops at the first failure in a flow.
A good habit that was used here: after writing a test, **deliberately break the code it guards and confirm it fails**, then put it back.
