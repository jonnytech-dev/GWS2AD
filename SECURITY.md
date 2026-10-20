# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for a security problem. Use GitHub's private
"Report a vulnerability" feature on the repository's Security tab, or contact the maintainers privately,
with the steps to reproduce and what you think the impact is. We will acknowledge it and work on a fix before details are made public.

## If you committed a secret by accident

Treat it as exposed: rotate it. For this project that means a new Google service account key (delete the old one in the Google Cloud console),
a new AD service account password, and a new mail app password. Removing the file from a later commit does not remove it from git history.

## Scope notes

- The known, documented limitations are in [docs/security.md](docs/security.md#known-limitations). Reports about those are welcome as improvements, but they are not surprises.
- Please test only against Demo mode or your own systems.
