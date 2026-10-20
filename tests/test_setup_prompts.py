"""
test_setup_prompts.py
=====================
The first-run prompts in setup_secrets.py: password, then confirm password.
A wrong confirmation must say so and ask for the confirmation again (not restart or quit),
and a too-short password must be refused before confirmation is asked.

    python tests/test_setup_prompts.py
"""
import io
import os
import sys
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import setup_secrets as S


def run(answers):
    """Feed the answers to the password prompts; return (password, the prompts that were shown, the printed text)"""
    answers, asked = list(answers), []
    def fake(prompt=''):
        asked.append(prompt)
        return answers.pop(0)
    real = S.getpass.getpass
    S.getpass.getpass = fake
    out = io.StringIO()
    try:
        with redirect_stdout(out):
            result = S._ask_new_password('Owner password (8+ characters)', 8)
    finally:
        S.getpass.getpass = real
    assert not answers, 'the prompts stopped asking before the answers ran out'
    return result, asked, out.getvalue()


def t_matching_confirmation_is_accepted():
    pw, asked, out = run(['long enough pw', 'long enough pw'])
    assert pw == 'long enough pw'
    assert asked == ['Owner password (8+ characters): ', 'Confirm password: '], asked
    assert 'match' not in out

def t_wrong_confirmation_asks_for_the_confirmation_again():
    pw, asked, out = run(['long enough pw', 'long enough px', 'long enough pw'])
    assert pw == 'long enough pw'
    assert asked == ['Owner password (8+ characters): ', 'Confirm password: ', 'Confirm password: '], asked   # the first prompt is not repeated
    assert out.count('do not match') == 1

def t_several_wrong_confirmations_keep_asking():
    pw, asked, out = run(['long enough pw', 'a', 'b', 'c', 'long enough pw'])
    assert pw == 'long enough pw' and asked.count('Confirm password: ') == 4 and out.count('do not match') == 3

def t_short_password_is_refused_before_confirming():
    pw, asked, out = run(['short', 'long enough pw', 'long enough pw'])
    assert pw == 'long enough pw'
    assert asked[0].startswith('Owner password') and asked[1].startswith('Owner password') and asked[2] == 'Confirm password: '
    assert 'Too short' in out and 'do not match' not in out

CHECKS = [(k[2:].replace('_', ' ').capitalize(), v) for k, v in list(globals().items()) if k.startswith('t_') and callable(v)]

if __name__ == '__main__':
    failed = 0
    for i, (name, fn) in enumerate(CHECKS, 1):
        try:
            fn(); print(f"PASS  {i:2d}. {name}")
        except Exception:
            import traceback; print(f"FAIL  {i:2d}. {name}"); traceback.print_exc(); failed += 1
    print(f"\n{len(CHECKS) - failed} of {len(CHECKS)} checks passed")
    sys.exit(1 if failed else 0)
