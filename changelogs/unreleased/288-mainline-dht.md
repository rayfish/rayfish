### Changed

- Publish and discover networks and peers through the Mainline DHT as well as
  HTTPS, so discovery can continue if the default HTTPS server is down.

### Fixed

- Confirm the signed roster before reporting a successful admin grant, so a
  coordinator can stop after handing over responsibility.
