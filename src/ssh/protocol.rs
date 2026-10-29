//! SSH protocol configuration shared by desktop platforms.

use std::borrow::Cow;
use std::time::Duration;

use russh::keys::PrivateKey;
use russh::server::Config;
use russh::{MethodKind, MethodSet, Preferred, compression};

pub(super) fn server_config(key: PrivateKey) -> Config {
    Config {
        keys: vec![key],
        methods: MethodSet::from(&[MethodKind::None][..]),
        inactivity_timeout: None,
        keepalive_interval: Some(Duration::from_secs(15)),
        keepalive_max: 3,
        auth_rejection_time: Duration::from_secs(1),
        // Russh's receive-side zlib state breaks after the first channel packet.
        // Keep the same uncompressed protocol on every desktop platform.
        preferred: Preferred {
            compression: Cow::Borrowed(&[compression::NONE]),
            ..Preferred::DEFAULT
        },
        ..Default::default()
    }
}
