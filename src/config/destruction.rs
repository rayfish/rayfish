//! Retain signed deletion proofs after removing network membership and keys.

use std::{fs, io::ErrorKind, path::Path};

use anyhow::{Result, ensure};
use iroh::{EndpointId, SecretKey};
use iroh_dns::pkarr::SignedPacket;

use crate::dht::{self, destruction};

const DIRECTORY: &str = "destroyed-networks";

pub(crate) fn load(network: EndpointId) -> Result<Option<SignedPacket>> {
    load_in(&super::config_dir_for_read()?, network)
}

pub(super) fn load_in(dir: &Path, network: EndpointId) -> Result<Option<SignedPacket>> {
    let bytes = match fs::read(dir.join(DIRECTORY).join(format!("{network}.pkarr"))) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let packet = dht::verify_network_record(&bytes, network)?;
    ensure!(
        destruction::is_destroyed(&packet),
        "invalid saved destruction proof"
    );
    Ok(Some(packet))
}

pub(crate) fn save(packet: &SignedPacket, key: Option<&SecretKey>) -> Result<()> {
    let dir = super::config_dir()?;
    let _guard = super::NETWORK_CONFIG_LOCK
        .write()
        .unwrap_or_else(|e| e.into_inner());
    save_in(&dir, packet, key)
}

fn save_in(dir: &Path, packet: &SignedPacket, key: Option<&SecretKey>) -> Result<()> {
    ensure!(destruction::is_destroyed(packet), "not a destruction proof");
    let parent = dir;
    let dir = dir.join(DIRECTORY);
    let network = packet.public_key();
    if let Some(key) = key {
        let index = destruction::encode_index(key, packet)?;
        super::write_file(
            &dir.join(format!("{network}.index")),
            index.as_bytes(),
            false,
        )?;
    }
    super::write_file(
        &dir.join(format!("{network}.pkarr")),
        packet.as_bytes(),
        false,
    )?;
    // The first proof also creates DIRECTORY. Persist that directory entry
    // before the caller removes membership and its network key.
    super::write::sync_dir(parent)
}

pub(crate) fn all() -> Result<Vec<SignedPacket>> {
    all_in(&super::config_dir_for_read()?)
}

/// Every saved proof and index under `dir`. One unreadable or invalid file is
/// skipped with a warning: it must not stop the others from being republished.
fn all_in(dir: &Path) -> Result<Vec<SignedPacket>> {
    let dir = dir.join(DIRECTORY);
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut packets = Vec::new();
    for entry in entries {
        let path = match entry {
            Ok(entry) => entry.path(),
            Err(error) => {
                tracing::warn!(%error, "skipping an unreadable destruction proof entry");
                continue;
            }
        };
        if path
            .extension()
            .is_none_or(|e| e != "pkarr" && e != "index")
        {
            continue;
        }
        let Some(network) = path
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(|s| s.parse::<EndpointId>().ok())
        else {
            continue;
        };
        match read_saved(&path, network) {
            Ok(packet) => packets.push(packet),
            Err(error) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %format!("{error:#}"),
                    "skipping an invalid destruction proof"
                );
            }
        }
    }
    Ok(packets)
}

fn read_saved(path: &Path, network: EndpointId) -> Result<SignedPacket> {
    let packet = SignedPacket::from_bytes(&fs::read(path)?)?;
    if path.extension().is_some_and(|e| e == "index") {
        destruction::decode_index(&packet, network)?;
    } else {
        ensure!(
            packet.public_key() == network && destruction::is_destroyed(&packet),
            "invalid saved destruction proof"
        );
    }
    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deletion_survives_membership_removal_and_rejects_a_live_record() {
        let dir = tempfile::tempdir().unwrap();
        let key = SecretKey::from([7; 32]);
        let record = destruction::encode(&key).unwrap();
        assert!(load_in(dir.path(), key.public()).unwrap().is_none());
        save_in(dir.path(), &record, Some(&key)).unwrap();
        // No membership or secret key is needed to recover the proof.
        assert_eq!(
            load_in(dir.path(), key.public())
                .unwrap()
                .unwrap()
                .as_bytes(),
            record.as_bytes()
        );
        let live = dht::encode_network_record(&key, &blake3::hash(b"roster"), &[]).unwrap();
        assert!(save_in(dir.path(), &live, None).is_err());
        assert!(load_in(dir.path(), key.public()).unwrap().is_some());
    }

    #[test]
    fn one_bad_file_does_not_hide_the_other_proofs() {
        let dir = tempfile::tempdir().unwrap();
        let key = SecretKey::from([8; 32]);
        let record = destruction::encode(&key).unwrap();
        save_in(dir.path(), &record, None).unwrap();
        let other = SecretKey::from([9; 32]).public();
        fs::write(
            dir.path().join(DIRECTORY).join(format!("{other}.pkarr")),
            b"not a packet",
        )
        .unwrap();

        let packets = all_in(dir.path()).unwrap();

        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].as_bytes(), record.as_bytes());
    }
}
