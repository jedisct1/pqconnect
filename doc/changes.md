**[`pqconnect-1.2.2.tar.gz`](pqconnect-1.2.2.tar.gz)**

Add configuration checker (`pqconnect-server-check`) for sysadmins to
diagnose configuration issues.

Fix unhandled connectivity-loss error.

Fix handling malformed static-key requests; thanks Jan Mojzis.

Port to Python 3.13,
by moving thread creation into `run_server`.

Python dependencies: use the `lib25519` wrapper
rather than the `ondesmartenot/py25519` wrapper.

Handle miscellaneous installation issues on Debian and Alpine.

Many test improvements.

Small code cleanups.

Include `./package.do` for tarball creation.

Include `./autogen.do` for package preprocessing
(currently just rebuilding `doc/html`).

Documentation improvements:
note dependency on `wget` and `sudo`;
use `203.0.113.113` as example IP address;
link to NDSS 2025 slides.

**[`pqconnect-1.2.1.tar.gz`](pqconnect-1.2.1.tar.gz)**

First public release.
