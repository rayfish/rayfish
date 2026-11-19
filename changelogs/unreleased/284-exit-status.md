### Fixed

- Exit-node status lists IPv4 and IPv6 capabilities, marks unsupported families
  as blocked, and says when traffic still goes out directly.
- Daemon shutdown releases its startup lock even when a subprocess inherits the
  lock descriptor, allowing an immediate restart.
