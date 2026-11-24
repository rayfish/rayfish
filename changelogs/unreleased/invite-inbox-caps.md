### Changed

- You can now send one person invites to many networks at once. Someone who
  shares no network with you holds one pending invite from you; the rest wait
  and arrive automatically once they accept it. People you already share a
  network with can hold up to 64 pending invites from you.

### Fixed

- An invite sent past the recipient's limit is no longer refused for good. The
  sender keeps retrying it until it expires, so it lands once the recipient
  has room.
