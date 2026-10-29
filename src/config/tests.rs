use super::*;

#[cfg(unix)]
#[test]
fn blob_store_moves_to_the_state_directory_once() {
    let root = tempfile::tempdir().expect("tempdir is creatable in tests");
    let old = root.path().join("etc-blobs");
    let new = root.path().join("var-blobs");
    std::fs::create_dir(&old).expect("create old store");
    std::fs::write(old.join("blobs.db"), b"db").expect("seed old store");

    assert_eq!(migrate_blobs(&old, &new), new);
    assert!(!old.exists());
    assert_eq!(std::fs::read(new.join("blobs.db")).expect("moved"), b"db");
    // Second start: nothing left to move.
    assert_eq!(migrate_blobs(&old, &new), new);
}

#[cfg(unix)]
#[test]
fn blob_store_migration_never_overwrites_the_new_location() {
    let root = tempfile::tempdir().expect("tempdir is creatable in tests");
    let old = root.path().join("etc-blobs");
    let new = root.path().join("var-blobs");
    std::fs::create_dir(&old).expect("create old store");
    std::fs::create_dir(&new).expect("create new store");
    assert_eq!(migrate_blobs(&old, &new), new);
    assert!(old.exists());
}

#[cfg(unix)]
#[test]
fn blob_store_copy_matches_and_replaces_nothing_on_failure() {
    let root = tempfile::tempdir().expect("tempdir is creatable in tests");
    let old = root.path().join("etc-blobs");
    std::fs::create_dir_all(old.join("data").join("ab")).expect("create old store");
    std::fs::write(old.join("blobs.db"), b"db").expect("seed old store");
    std::fs::write(old.join("data").join("ab").join("blob"), vec![7u8; 70_000])
        .expect("seed old store");
    let new = root.path().join("var-blobs");

    copy_blob_store(&old, &new).expect("copy succeeds");
    assert_eq!(std::fs::read(new.join("blobs.db")).expect("copied"), b"db");
    assert_eq!(
        std::fs::metadata(new.join("data").join("ab").join("blob"))
            .expect("copied")
            .len(),
        70_000
    );
    assert!(
        old.join("blobs.db").exists(),
        "the original is left for the caller"
    );
    assert!(!root.path().join(".blobs.migrating").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&new)
            .expect("copied")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    // Copying onto an existing store fails at the rename and leaves it be.
    std::fs::write(new.join("blobs.db"), b"newer").expect("touch new store");
    std::fs::write(new.join("extra"), b"x").expect("touch new store");
    assert!(copy_blob_store(&old, &new).is_err());
    assert_eq!(std::fs::read(new.join("blobs.db")).expect("kept"), b"newer");
    assert!(!root.path().join(".blobs.migrating").exists());
}

#[cfg(unix)]
#[test]
fn blob_store_stays_put_when_it_cannot_move() {
    let root = tempfile::tempdir().expect("tempdir is creatable in tests");
    let old = root.path().join("etc-blobs");
    std::fs::create_dir(&old).expect("create old store");
    let new = root.path().join("missing-parent").join("blobs");
    assert_eq!(migrate_blobs(&old, &new), old);
    assert!(old.exists());
}
use std::net::Ipv6Addr;

use iroh::{EndpointAddr, EndpointId, TransportAddr};

/// `ray-mobile` used to publish its config directory by writing
/// `RAYFISH_CONFIG_DIR`, which mutates the process environment and so is
/// undefined behaviour once other threads run. The embedder override
/// replaces that write, so it has to win over the variable the way the
/// overwrite did. `ray-mobile`'s own tests cover the wiring end to end;
/// this is the precedence on its own, with nothing global touched.
#[test]
fn the_embedder_override_beats_the_env_var() {
    let from_env = OsString::from("/srv/rayfish-from-env");
    let from_code = PathBuf::from("/srv/rayfish-from-code");

    assert_eq!(
        resolve_override(None, Some(from_env.clone())),
        Some(PathBuf::from("/srv/rayfish-from-env"))
    );
    assert_eq!(
        resolve_override(Some(from_code.clone()), Some(from_env)),
        Some(from_code.clone())
    );
    // Still in effect with no variable at all: the platform default is what
    // the override exists to displace on Android.
    assert_eq!(
        resolve_override(Some(from_code.clone()), None),
        Some(from_code)
    );
    assert_eq!(resolve_override(None, None), None);
}

/// An embedder handing over an empty path is the same accident the env var
/// already guards against, and must not resolve config to the process's
/// current directory. It falls through to the variable, then the default.
#[test]
fn an_empty_embedder_override_is_no_override() {
    assert_eq!(resolve_override(Some(PathBuf::new()), None), None);
    assert_eq!(
        resolve_override(Some(PathBuf::new()), Some(OsString::from("/srv/rayfish"))),
        Some(PathBuf::from("/srv/rayfish"))
    );
}

fn test_id(seed: u8) -> EndpointId {
    let mut key_bytes = [0u8; 32];
    key_bytes[0] = seed;
    SecretKey::from(key_bytes).public()
}

/// A bare `ray config get` used to print a hand-kept list of five keys, so a
/// new setting was reachable but invisible. It now lists the whole enum.
#[test]
fn the_bare_listing_covers_every_global_key() {
    let rows = config_get(&AppConfig::default(), None);
    let names: Vec<&str> = rows.iter().map(|(k, _)| k.as_str()).collect();
    for k in settings::GlobalKey::ALL {
        assert!(names.contains(&k.name()), "{} not listed", k.name());
    }
    assert_eq!(rows.len(), settings::GlobalKey::ALL.len());
}

#[test]
fn config_dir_override_ignores_unset_and_empty() {
    assert_eq!(config_dir_override(None), None);
    // An exported-but-empty var must not resolve the tree to `""` (which
    // `create_dir_all` would reject) or to the process's cwd.
    assert_eq!(config_dir_override(Some(OsString::new())), None);
    assert_eq!(
        config_dir_override(Some(OsString::from("/srv/rayfish"))),
        Some(PathBuf::from("/srv/rayfish"))
    );
}

#[cfg(windows)]
#[test]
fn windows_stage_names_are_random_and_create_new() {
    let dir = tempfile::tempdir().unwrap();
    let first = windows_config_stage_path(dir.path(), "settings.toml");
    let second = windows_config_stage_path(dir.path(), "settings.toml");
    assert_ne!(first, second);
    let name = first.file_name().unwrap().to_string_lossy();
    let nonce = name.strip_prefix(".settings.toml.tmp.").unwrap();
    assert_eq!(nonce.len(), 64);
    assert!(nonce.bytes().all(|byte| byte.is_ascii_hexdigit()));

    drop(create_windows_config_stage(&first).unwrap());
    assert!(create_windows_config_stage(&first).is_err());
}

#[test]
fn test_serialize_roundtrip() {
    let config = AppConfig {
        networks: vec![
            NetworkConfig {
                name: "gaming".to_string(),
                group_mode: GroupMode::Open,
                members: vec![
                    MemberEntry {
                        identity: test_id(2),
                        is_coordinator: true,
                        hostname: None,
                    },
                    MemberEntry {
                        identity: test_id(3),
                        is_coordinator: false,
                        hostname: None,
                    },
                ],
                approved: vec![],
                network_secret_key: None,
                network_public_key: None,
                join_certificate_issuer: None,
                independent_paired_devices: vec![],
                last_group_hash: None,
                last_group_hash_published: true,
                my_hostname: None,
                pending_hostname: None,
                transport: None,
                auto_accept_firewall: false,
                auto_accept_files: false,
                admins: vec![],
                direct: false,
                direct_peer: None,
                ssh_allow: vec![],
                managed_ssh_allow: vec![],
                aliases: BTreeMap::new(),
                ephemeral_ttl_secs: None,
                exit_allow: vec![],
                exit_node_use: None,
            },
            NetworkConfig {
                name: "work".to_string(),
                group_mode: GroupMode::Restricted,
                members: vec![],
                approved: vec![],
                network_secret_key: None,
                network_public_key: None,
                join_certificate_issuer: None,
                independent_paired_devices: vec![],
                last_group_hash: None,
                last_group_hash_published: true,
                my_hostname: None,
                pending_hostname: None,
                transport: None,
                auto_accept_firewall: false,
                auto_accept_files: false,
                admins: vec![],
                direct: false,
                direct_peer: None,
                ssh_allow: vec![],
                managed_ssh_allow: vec![],
                aliases: BTreeMap::new(),
                ephemeral_ttl_secs: None,
                exit_allow: vec![],
                exit_node_use: None,
            },
        ],
        ..Default::default()
    };

    let toml_str = toml::to_string_pretty(&config).unwrap();
    let parsed: AppConfig = toml::from_str(&toml_str).unwrap();
    assert_eq!(parsed.networks.len(), 2);
    assert_eq!(parsed.networks[0].name, "gaming");
    assert_eq!(parsed.networks[0].members.len(), 2);
    assert_eq!(parsed.networks[1].name, "work");
}

#[test]
fn test_deserialize_empty() {
    let config: AppConfig = toml::from_str("").unwrap();
    assert!(config.networks.is_empty());
}

#[test]
fn test_upsert_new() {
    let mut config = AppConfig::default();
    let net = NetworkConfig {
        name: "test".to_string(),
        group_mode: GroupMode::Open,
        members: vec![],
        approved: vec![],
        network_secret_key: None,
        network_public_key: None,
        join_certificate_issuer: None,
        independent_paired_devices: vec![],
        last_group_hash: None,
        last_group_hash_published: true,
        my_hostname: None,
        pending_hostname: None,
        transport: None,
        auto_accept_firewall: false,
        auto_accept_files: false,
        admins: vec![],
        direct: false,
        direct_peer: None,
        ssh_allow: vec![],
        managed_ssh_allow: vec![],
        aliases: BTreeMap::new(),
        ephemeral_ttl_secs: None,
        exit_allow: vec![],
        exit_node_use: None,
    };
    upsert_network(&mut config, net);
    assert_eq!(config.networks.len(), 1);
    assert_eq!(config.networks[0].name, "test");
    assert_eq!(config.networks[0].group_mode, GroupMode::Open);
}

#[test]
fn test_upsert_replaces_existing() {
    let mut config = AppConfig {
        networks: vec![NetworkConfig {
            name: "test".to_string(),
            group_mode: GroupMode::Restricted,
            members: vec![],
            approved: vec![],
            network_secret_key: None,
            network_public_key: None,
            join_certificate_issuer: None,
            independent_paired_devices: vec![],
            last_group_hash: None,
            last_group_hash_published: true,
            my_hostname: None,
            pending_hostname: None,
            transport: None,
            auto_accept_firewall: false,
            auto_accept_files: false,
            admins: vec![],
            direct: false,
            direct_peer: None,
            ssh_allow: vec![],
            managed_ssh_allow: vec![],
            aliases: BTreeMap::new(),
            ephemeral_ttl_secs: None,
            exit_allow: vec![],
            exit_node_use: None,
        }],
        ..Default::default()
    };
    let updated = NetworkConfig {
        name: "test".to_string(),
        group_mode: GroupMode::Open,
        members: vec![],
        approved: vec![],
        network_secret_key: None,
        network_public_key: None,
        join_certificate_issuer: None,
        independent_paired_devices: vec![],
        last_group_hash: None,
        last_group_hash_published: true,
        my_hostname: None,
        pending_hostname: None,
        transport: None,
        auto_accept_firewall: false,
        auto_accept_files: false,
        admins: vec![],
        direct: false,
        direct_peer: None,
        ssh_allow: vec![],
        managed_ssh_allow: vec![],
        aliases: BTreeMap::new(),
        ephemeral_ttl_secs: None,
        exit_allow: vec![],
        exit_node_use: None,
    };
    upsert_network(&mut config, updated.clone());
    assert_eq!(config.networks.len(), 1);
    assert_eq!(config.networks[0].group_mode, GroupMode::Open);
}

#[test]
fn test_remove_network() {
    let mut config = AppConfig {
        networks: vec![
            NetworkConfig {
                name: "keep".to_string(),
                group_mode: GroupMode::Restricted,
                members: vec![],
                approved: vec![],
                network_secret_key: None,
                network_public_key: None,
                join_certificate_issuer: None,
                independent_paired_devices: vec![],
                last_group_hash: None,
                last_group_hash_published: true,
                my_hostname: None,
                pending_hostname: None,
                transport: None,
                auto_accept_firewall: false,
                auto_accept_files: false,
                admins: vec![],
                direct: false,
                direct_peer: None,
                ssh_allow: vec![],
                managed_ssh_allow: vec![],
                aliases: BTreeMap::new(),
                ephemeral_ttl_secs: None,
                exit_allow: vec![],
                exit_node_use: None,
            },
            NetworkConfig {
                name: "remove-me".to_string(),
                group_mode: GroupMode::Restricted,
                members: vec![],
                approved: vec![],
                network_secret_key: None,
                network_public_key: None,
                join_certificate_issuer: None,
                independent_paired_devices: vec![],
                last_group_hash: None,
                last_group_hash_published: true,
                my_hostname: None,
                pending_hostname: None,
                transport: None,
                auto_accept_firewall: false,
                auto_accept_files: false,
                admins: vec![],
                direct: false,
                direct_peer: None,
                ssh_allow: vec![],
                managed_ssh_allow: vec![],
                aliases: BTreeMap::new(),
                ephemeral_ttl_secs: None,
                exit_allow: vec![],
                exit_node_use: None,
            },
        ],
        ..Default::default()
    };
    assert!(remove_network(&mut config, "remove-me"));
    assert_eq!(config.networks.len(), 1);
    assert_eq!(config.networks[0].name, "keep");
}

#[test]
fn test_remove_nonexistent() {
    let mut config = AppConfig::default();
    assert!(!remove_network(&mut config, "nope"));
}

#[test]
fn test_serialize_with_approved() {
    let id1 = test_id(1);
    let id2 = test_id(2);
    let config = AppConfig {
        networks: vec![NetworkConfig {
            name: "gaming".to_string(),
            group_mode: GroupMode::Restricted,
            members: vec![MemberEntry {
                identity: id1,
                is_coordinator: true,
                hostname: None,
            }],
            approved: vec![ApprovedConfigEntry {
                identity: id2,
                hostname: None,
            }],
            network_secret_key: None,
            network_public_key: None,
            join_certificate_issuer: None,
            independent_paired_devices: vec![],
            last_group_hash: None,
            last_group_hash_published: true,
            my_hostname: None,
            pending_hostname: None,
            transport: None,
            auto_accept_firewall: false,
            auto_accept_files: false,
            admins: vec![],
            direct: false,
            direct_peer: None,
            ssh_allow: vec![],
            managed_ssh_allow: vec![],
            aliases: BTreeMap::new(),
            ephemeral_ttl_secs: None,
            exit_allow: vec![],
            exit_node_use: None,
        }],
        ..Default::default()
    };
    let toml_str = toml::to_string_pretty(&config).unwrap();
    let parsed: AppConfig = toml::from_str(&toml_str).unwrap();
    assert_eq!(parsed.networks[0].approved.len(), 1);
    assert_eq!(parsed.networks[0].approved[0].identity, id2);
}

#[test]
fn test_serialize_with_network_key() {
    let secret = SecretKey::generate();
    let public = secret.public();
    let config = AppConfig {
        networks: vec![NetworkConfig {
            name: "gaming".to_string(),
            group_mode: GroupMode::Restricted,
            members: vec![],
            approved: vec![],
            network_secret_key: Some(secret.clone()),
            network_public_key: Some(public),
            join_certificate_issuer: None,
            independent_paired_devices: vec![],
            last_group_hash: None,
            last_group_hash_published: true,
            my_hostname: None,
            pending_hostname: None,
            transport: None,
            auto_accept_firewall: false,
            auto_accept_files: false,
            admins: vec![],
            direct: false,
            direct_peer: None,
            ssh_allow: vec![],
            managed_ssh_allow: vec![],
            aliases: BTreeMap::new(),
            ephemeral_ttl_secs: None,
            exit_allow: vec![],
            exit_node_use: None,
        }],
        ..Default::default()
    };
    let toml_str = toml::to_string_pretty(&config).unwrap();
    let parsed: AppConfig = toml::from_str(&toml_str).unwrap();
    assert_eq!(parsed.networks[0].network_public_key, Some(public));
    assert!(parsed.networks[0].network_secret_key.is_some());
}

#[test]
fn test_direct_flag_default_false() {
    let toml_str = r#"
[[networks]]
name = "team-alice"
"#;
    let config: AppConfig = toml::from_str(toml_str).unwrap();
    assert!(!config.networks[0].direct);
}

#[test]
fn test_deserialize_minimal() {
    let toml_str = r#"
[[networks]]
name = "test"
"#;
    let config: AppConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(config.networks.len(), 1);
    assert_eq!(config.networks[0].name, "test");
    assert_eq!(config.networks[0].group_mode, GroupMode::Restricted);
    assert!(config.networks[0].members.is_empty());
    assert!(config.networks[0].approved.is_empty());
    assert!(config.networks[0].network_secret_key.is_none());
    assert!(config.networks[0].network_public_key.is_none());
}

#[test]
fn ephemeral_ttl_roundtrips_and_defaults_none() {
    let mut n = net("eph");
    n.ephemeral_ttl_secs = Some(3600);
    let text = toml::to_string(&n).unwrap();
    let back: NetworkConfig = toml::from_str(&text).unwrap();
    assert_eq!(back.ephemeral_ttl_secs, Some(3600));
    // A config written before the field existed omits the key -> None.
    let minimal: NetworkConfig = toml::from_str("name = \"x\"").unwrap();
    assert_eq!(minimal.ephemeral_ttl_secs, None);
}

#[test]
fn last_group_hash_roundtrips_and_defaults_none() {
    let hash = blake3::hash(b"complete signed roster");
    let mut n = net("cached");
    n.last_group_hash = Some(hash);
    n.last_group_hash_published = false;
    let text = toml::to_string(&n).unwrap();
    let back: NetworkConfig = toml::from_str(&text).unwrap();
    assert_eq!(back.last_group_hash, Some(hash));
    assert!(!back.last_group_hash_published);

    let minimal: NetworkConfig = toml::from_str("name = \"x\"").unwrap();
    assert_eq!(minimal.last_group_hash, None);
    assert!(minimal.last_group_hash_published);
}

fn net(name: &str) -> NetworkConfig {
    NetworkConfig {
        name: name.to_string(),
        group_mode: GroupMode::Restricted,
        my_hostname: None,
        pending_hostname: None,
        members: vec![],
        approved: vec![],
        network_secret_key: Some(SecretKey::generate()),
        network_public_key: None,
        join_certificate_issuer: None,
        independent_paired_devices: vec![],
        last_group_hash: None,
        last_group_hash_published: true,
        transport: None,
        auto_accept_firewall: false,
        auto_accept_files: false,
        admins: vec![],
        direct: false,
        direct_peer: None,
        ssh_allow: vec![],
        managed_ssh_allow: vec![],
        aliases: BTreeMap::new(),
        ephemeral_ttl_secs: None,
        exit_allow: vec![],
        exit_node_use: None,
    }
}

#[test]
fn per_network_roundtrip_and_delete() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    save_network_unlocked(dir, &net("homelab")).unwrap();
    save_network_unlocked(dir, &net("genesis")).unwrap();
    save_settings_in(
        dir,
        &AppConfig {
            default_hostname: Some("laptop".into()),
            ..Default::default()
        },
    )
    .unwrap();

    let loaded = load_in(dir).unwrap();
    assert_eq!(loaded.networks.len(), 2);
    assert_eq!(loaded.default_hostname.as_deref(), Some("laptop"));

    // Single-network load.
    assert!(load_network_unlocked(dir, "homelab").unwrap().is_some());
    assert!(load_network_unlocked(dir, "absent").unwrap().is_none());

    // Deleting one leaves the other untouched.
    assert!(delete_network_unlocked(dir, "homelab").unwrap());
    assert!(!delete_network_unlocked(dir, "homelab").unwrap());
    let after = load_in(dir).unwrap();
    assert_eq!(after.networks.len(), 1);
    assert_eq!(after.networks[0].name, "genesis");
}

/// A rename moves the whole config, keys and node-local settings included,
/// and the network's invite ledger, over one an earlier network left under
/// the new name, and leaves nothing saved under the old name.
#[test]
fn rename_moves_a_network_to_its_new_name() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let mut home = net("homelab");
    home.aliases.insert("alice".into(), "id-alice".into());
    save_network_unlocked(dir, &home).unwrap();
    let ledger = crate::invite::ledger_path_in(dir, "homelab");
    std::fs::create_dir_all(ledger.parent().unwrap()).unwrap();
    std::fs::write(&ledger, "# homelab's invites\n").unwrap();
    let left = crate::invite::ledger_path_in(dir, "lab");
    std::fs::write(&left, "# invites of a network once saved as lab\n").unwrap();

    let renamed = rename_network_in(dir, "homelab", "lab").unwrap().unwrap();
    assert!(load_network_unlocked(dir, "homelab").unwrap().is_none());
    assert!(!ledger.exists());
    assert_eq!(
        std::fs::read_to_string(&left).unwrap(),
        "# homelab's invites\n"
    );
    let lab = load_network_unlocked(dir, "lab").unwrap().unwrap();
    let expected = NetworkConfig {
        name: "lab".into(),
        ..home
    };
    for config in [&renamed, &lab] {
        assert_eq!(
            ::toml::to_string(config).unwrap(),
            ::toml::to_string(&expected).unwrap()
        );
    }
    // The name inside the file moved too, so updates under the new name work.
    assert!(update_network_in(dir, "lab", |_| Ok(())).unwrap().is_some());
    assert_eq!(load_in(dir).unwrap().networks.len(), 1);
    // The intent outlives the move, for the caller's firewall rules.
    assert_eq!(
        load_rename_intent(dir).unwrap(),
        Some(RenameIntent {
            from: "homelab".into(),
            to: "lab".into(),
        })
    );
    clear_rename_intent_in(dir).unwrap();
    assert!(load_rename_intent(dir).unwrap().is_none());
    assert!(
        rename_network_in(dir, "homelab", "office")
            .unwrap()
            .is_none()
    );
}

/// A crash part-way through a rename leaves one of three states, and the
/// saved intent finishes each. Between the move and the rewrite, the network
/// is listed under a name that cannot load it, so nothing could restore it,
/// and its invite ledger is still under the old name.
#[test]
fn an_interrupted_rename_is_finished_from_its_intent() {
    let intent = RenameIntent {
        from: "homelab".into(),
        to: "lab".into(),
    };
    for crash in ["before the move", "before the rewrite", "after the rewrite"] {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let home = net("homelab");
        save_network_unlocked(dir, &home).unwrap();
        let ledger = crate::invite::ledger_path_in(dir, "homelab");
        std::fs::create_dir_all(ledger.parent().unwrap()).unwrap();
        std::fs::write(&ledger, "# homelab's invites\n").unwrap();
        write_atomic(
            &dir.join(RENAME_INTENT_FILE),
            &::toml::to_string(&intent).unwrap(),
            false,
        )
        .unwrap();
        match crash {
            "before the rewrite" => {
                let ndir = dir.join(NETWORKS_SUBDIR);
                std::fs::rename(ndir.join("homelab.toml"), ndir.join("lab.toml")).unwrap();
                let listed = load_in(dir).unwrap().networks;
                assert_eq!(listed[0].name, "homelab");
                assert!(load_network_unlocked(dir, "homelab").unwrap().is_none());
            }
            "after the rewrite" => {
                finish_rename_unlocked(dir, &intent).unwrap();
            }
            _ => {}
        }

        let lab = finish_rename_in(dir, &intent).unwrap().unwrap();
        assert_eq!(lab.name, "lab", "{crash}");
        assert!(!ledger.exists(), "{crash}");
        assert_eq!(
            std::fs::read_to_string(crate::invite::ledger_path_in(dir, "lab")).unwrap(),
            "# homelab's invites\n",
            "{crash}"
        );
        let listed = load_in(dir).unwrap().networks;
        assert_eq!(listed.len(), 1, "{crash}");
        assert_eq!(listed[0].name, "lab", "{crash}");
        let expected = NetworkConfig {
            name: "lab".into(),
            ..home
        };
        assert_eq!(
            ::toml::to_string(&load_network_unlocked(dir, "lab").unwrap().unwrap()).unwrap(),
            ::toml::to_string(&expected).unwrap(),
            "{crash}"
        );
        // Finishing again changes nothing.
        assert_eq!(
            finish_rename_in(dir, &intent).unwrap().map(|net| net.name),
            Some("lab".into()),
            "{crash}"
        );
    }
}

/// Nothing is renamed over a network saved under the new name meanwhile, which
/// the daemon never does while the intent stands but a hand edit can, and a
/// network that is gone has nothing left to finish.
#[test]
fn an_interrupted_rename_never_replaces_another_network() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let intent = RenameIntent {
        from: "homelab".into(),
        to: "lab".into(),
    };
    let (homelab, lab) = (net("homelab"), net("lab"));
    save_network_unlocked(dir, &homelab).unwrap();
    save_network_unlocked(dir, &lab).unwrap();
    assert!(finish_rename_in(dir, &intent).unwrap().is_none());
    for kept in [&homelab, &lab] {
        let saved = load_network_unlocked(dir, &kept.name).unwrap().unwrap();
        assert_eq!(
            ::toml::to_string(&saved).unwrap(),
            ::toml::to_string(kept).unwrap()
        );
    }

    let tmp = tempfile::tempdir().unwrap();
    assert!(finish_rename_in(tmp.path(), &intent).unwrap().is_none());
}

/// A rename that has not finished blocks the next one: its intent is the only
/// record of what is left to do.
#[test]
fn a_rename_waits_for_an_unfinished_one() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    save_network_unlocked(dir, &net("homelab")).unwrap();
    save_network_unlocked(dir, &net("office")).unwrap();
    rename_network_in(dir, "homelab", "lab").unwrap().unwrap();

    let refused = rename_network_in(dir, "office", "work").unwrap_err();
    assert!(
        refused.to_string().contains("has not finished"),
        "{refused:#}"
    );
    assert!(load_network_unlocked(dir, "office").unwrap().is_some());
    assert!(load_network_unlocked(dir, "work").unwrap().is_none());
}

/// A rename never replaces the config of a network already saved under the
/// new name, whose secret key would go with it.
#[test]
fn rename_refuses_a_name_another_network_is_saved_under() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let (homelab, genesis) = (net("homelab"), net("genesis"));
    save_network_unlocked(dir, &homelab).unwrap();
    save_network_unlocked(dir, &genesis).unwrap();

    assert!(rename_network_in(dir, "homelab", "genesis").is_err());
    for kept in [&homelab, &genesis] {
        let saved = load_network_unlocked(dir, &kept.name).unwrap().unwrap();
        assert_eq!(
            ::toml::to_string(&saved).unwrap(),
            ::toml::to_string(kept).unwrap()
        );
    }
    // Refused before anything was committed.
    assert!(load_rename_intent(dir).unwrap().is_none());
}

#[test]
fn settings_download_fields_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let cfg = AppConfig {
        file_auto_accept_peers: vec![SecretKey::from([41; 32]).public()],
        download_dir: Some("/srv/incoming".to_string()),
        download_user: Some(1000),
        ..Default::default()
    };
    save_settings_in(dir, &cfg).unwrap();

    let loaded = load_in(dir).unwrap();
    assert_eq!(loaded.download_dir.as_deref(), Some("/srv/incoming"));
    assert_eq!(loaded.download_user, Some(1000));
    assert_eq!(loaded.file_auto_accept_peers, cfg.file_auto_accept_peers);
}

#[test]
fn settings_inbound_and_blocked_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = AppConfig {
        inbound: InboundPolicy::Known,
        blocked: vec![SecretKey::from([45; 32]).public()],
        ..Default::default()
    };
    save_settings_in(tmp.path(), &cfg).unwrap();
    let loaded = load_in(tmp.path()).unwrap();
    assert_eq!(loaded.inbound, InboundPolicy::Known);
    assert_eq!(loaded.blocked, cfg.blocked);
}

#[test]
fn ssh_port_defaults_to_22_and_persists() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(load_in(tmp.path()).unwrap().ssh_port, 22);
    let cfg = AppConfig {
        ssh_port: 2222,
        ..Default::default()
    };
    save_settings_in(tmp.path(), &cfg).unwrap();
    assert_eq!(load_in(tmp.path()).unwrap().ssh_port, 2222);
}

#[test]
fn v4_bridge_defaults_on_and_preserves_explicit_off() {
    let tmp = tempfile::tempdir().expect("create config directory");
    assert!(load_in(tmp.path()).expect("load fresh settings").v4_bridge);
    std::fs::write(tmp.path().join(SETTINGS_FILE), "mdns_enabled = false\n")
        .expect("write settings without the bridge key");
    assert!(load_in(tmp.path()).expect("load older settings").v4_bridge);

    let cfg = AppConfig {
        v4_bridge: false,
        ..Default::default()
    };
    save_settings_in(tmp.path(), &cfg).expect("save the disabled bridge");
    assert!(!load_in(tmp.path()).expect("reload settings").v4_bridge);
}

#[test]
fn management_state_roundtrips_with_typed_values() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let controller_key = SecretKey::generate();
    let controller = controller_key.public();
    let machine = test_id(32);
    let enrolled_at = UnixTimestampSecs::from_secs(100);
    let last_seen = UnixTimestampSecs::from_secs(200);
    let cfg = AppConfig {
        controllers: vec![ControllerGrant {
            identity: controller,
            enrolled_at,
            receipt: Some(EnrollmentReceipt::issue(
                &controller_key,
                machine,
                enrolled_at,
            )),
        }],
        managed_machines: vec![ManagedMachine {
            identity: machine,
            hostname: "build-box".parse().unwrap(),
            enrolled_at,
            last_seen: Some(last_seen),
        }],
        forgotten_machines: vec![test_id(33)],
        enrollment_credentials: vec![EnrollmentCredential {
            id: ray_proto::ipc::EnrollmentCredentialId::new("abc123".to_string()),
            secret_hash: blake3::hash(b"fabricated enrollment secret"),
            expires_at: UnixTimestampSecs::from_secs(300),
            reusable: true,
            enrolled_machines: vec![machine],
            revoked: false,
        }],
        ..Default::default()
    };
    save_settings_in(dir, &cfg).unwrap();

    let loaded = load_in(dir).unwrap();
    assert_eq!(loaded.controllers, cfg.controllers);
    assert_eq!(loaded.managed_machines, cfg.managed_machines);
    assert_eq!(loaded.forgotten_machines, cfg.forgotten_machines);
    assert_eq!(loaded.enrollment_credentials, cfg.enrollment_credentials);
}

#[test]
fn legacy_controller_grant_loads_without_a_receipt() {
    let settings: AppConfig = toml::from_str(&format!(
        "[[controllers]]\nidentity = '{}'\nenrolled_at = 100\n",
        test_id(31)
    ))
    .unwrap();
    assert!(settings.controllers[0].receipt.is_none());
    assert!(settings.forgotten_machines.is_empty());
}

#[test]
fn settings_endpoint_hints_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let hint = EndpointHint {
        peer: test_id(7),
        addr: TransportAddr::Ip("203.0.113.7:1234".parse().unwrap()),
        last_success: UnixTimestampSecs::from_secs(100),
    };
    let cfg = AppConfig {
        endpoint_hints: vec![hint.clone()],
        ..Default::default()
    };
    save_settings_in(dir, &cfg).unwrap();

    let loaded = load_in(dir).unwrap();
    assert_eq!(loaded.endpoint_hints, vec![hint]);
}

#[test]
fn legacy_endpoint_hints_are_removed_when_startup_prunes() {
    #[derive(Serialize)]
    struct LegacySettings {
        endpoint_hints: Vec<EndpointAddr>,
    }
    let tmp = tempfile::tempdir().unwrap();
    let legacy = LegacySettings {
        endpoint_hints: vec![
            EndpointAddr::new(test_id(7))
                .with_ip_addr("192.0.2.1:1234".parse().unwrap())
                .with_relay_url("https://relay.example.com".parse().unwrap()),
        ],
    };
    std::fs::write(
        tmp.path().join(SETTINGS_FILE),
        toml::to_string(&legacy).unwrap(),
    )
    .unwrap();
    let loaded = load_in(tmp.path()).unwrap();
    assert_eq!(loaded.endpoint_hints.len(), 2);
    assert!(
        loaded
            .endpoint_hints
            .iter()
            .all(|hint| hint.last_success.as_secs() == 0)
    );
    update_settings_in(tmp.path(), |cfg| {
        endpoint_hints::prune(&mut cfg.endpoint_hints, UnixTimestampSecs::from_secs(100));
        Ok(())
    })
    .unwrap();
    assert!(load_in(tmp.path()).unwrap().endpoint_hints.is_empty());
    assert!(
        !std::fs::read_to_string(tmp.path().join(SETTINGS_FILE))
            .unwrap()
            .contains("endpoint_hints")
    );
}

/// The IPv6-only cutover deleted the `ipv6-only` setting, and the release
/// notes promise a `settings.toml` still carrying it upgrades rather than
/// failing to parse. Nothing in `Settings` names the key any more, so what
/// keeps that promise is the absence of `deny_unknown_fields`, which is
/// exactly the kind of thing a later tidy-up adds without noticing.
#[test]
fn a_stale_ipv6_only_key_still_loads() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join(SETTINGS_FILE),
        "mdns_enabled = false\nipv6_only = true\n",
    )
    .unwrap();
    let loaded = load_in(tmp.path()).expect("a settings.toml from an older build still loads");
    assert!(!loaded.mdns_enabled, "the keys we do know are still read");
}

/// Contact keys are gone; a settings.toml that still has one loads, and the
/// key is not written back.
#[test]
fn a_stale_contact_key_still_loads() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join(SETTINGS_FILE),
        format!(
            "mdns_enabled = false\ncontact_secret_key = \"{}\"\n",
            "ab".repeat(32)
        ),
    )
    .unwrap();
    let loaded = load_in(tmp.path()).expect("a settings.toml with a contact key still loads");
    assert!(!loaded.mdns_enabled);
    assert!(
        !settings_toml(&loaded)
            .unwrap()
            .contains("contact_secret_key")
    );
}

#[test]
fn settings_download_fields_default_none() {
    let tmp = tempfile::tempdir().unwrap();
    // No settings.toml written: fields default to None.
    let loaded = load_in(tmp.path()).unwrap();
    assert_eq!(loaded.download_dir, None);
    assert_eq!(loaded.download_user, None);
}

#[test]
fn fresh_install_defaults_to_partial_dns() {
    let tmp = tempfile::tempdir().unwrap();
    let loaded = load_in(tmp.path()).unwrap();
    assert_eq!(loaded.dns_mode, DnsMode::Partial);
    assert!(loaded.dns_mode.enabled());
    assert!(!loaded.dns_mode.short_names());
}

#[test]
fn a_settings_file_without_a_dns_key_uses_partial() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join(SETTINGS_FILE), "mdns_enabled = true\n").unwrap();
    assert_eq!(load_in(tmp.path()).unwrap().dns_mode, DnsMode::Partial);
}

#[test]
fn fresh_install_matches_an_empty_settings_file() {
    let fresh = tempfile::tempdir().expect("create config directory");
    let empty = tempfile::tempdir().expect("create config directory");
    std::fs::write(empty.path().join(SETTINGS_FILE), "").expect("write empty settings");
    let fresh = load_in(fresh.path()).expect("load fresh install");
    let empty = load_in(empty.path()).expect("load empty settings");
    assert!(fresh.on_demand && empty.on_demand);
    assert!(fresh.pf_passthrough && empty.pf_passthrough);
}

#[test]
fn legacy_dns_bool_and_partial_mode_load() {
    let tmp = tempfile::tempdir().expect("create config directory");
    let path = tmp.path().join(SETTINGS_FILE);
    std::fs::write(&path, "dns_enabled = false\n").expect("write old setting");
    assert_eq!(
        load_in(tmp.path()).expect("load old setting").dns_mode,
        DnsMode::Off
    );
    std::fs::write(&path, "dns_mode = 'partial'\n").expect("write new setting");
    assert_eq!(
        load_in(tmp.path()).expect("load new setting").dns_mode,
        DnsMode::Partial
    );
}

#[test]
fn quic_engine_round_trips_and_tolerates_unknown_values() {
    use std::fs::write;

    let tmp = tempfile::tempdir().expect("create config directory");
    let path = tmp.path().join(SETTINGS_FILE);
    assert_eq!(
        load_in(tmp.path()).expect("fresh install").quic_engine,
        QuicEngine::Standalone
    );
    write(&path, "").expect("write settings without a controller");
    assert_eq!(
        load_in(tmp.path())
            .expect("load unset controller")
            .quic_engine,
        QuicEngine::Standalone
    );
    for controller in [QuicEngine::Standalone, QuicEngine::FqCodel] {
        let value = controller.as_ref();
        write(&path, format!("quic_engine = '{value}'\n")).expect("write setting");
        let loaded = load_in(tmp.path()).expect("load setting");
        assert_eq!(loaded.quic_engine, controller);
        assert!(
            settings_toml(&loaded)
                .expect("serialize")
                .contains(&format!("quic_engine = \"{value}\""))
        );
    }
    for (legacy, engine) in [
        ("cubic", QuicEngine::Standalone),
        ("loss-tolerant", QuicEngine::Standalone),
        ("fq-codel", QuicEngine::FqCodel),
    ] {
        write(&path, format!("quic_congestion = '{legacy}'\n")).expect("write legacy setting");
        let loaded = load_in(tmp.path()).expect("load legacy setting");
        assert_eq!(loaded.quic_engine, engine);
        let saved = settings_toml(&loaded).expect("serialize migrated setting");
        assert!(saved.contains(&format!("quic_engine = \"{}\"", engine.as_ref())));
        assert!(!saved.contains("quic_congestion"));
    }
    // A removed or hand-typed controller must not stop the daemon loading.
    write(&path, "quic_engine = 'bbr3'\n").expect("write unknown");
    assert_eq!(
        load_in(tmp.path()).expect("load unknown").quic_engine,
        QuicEngine::Standalone
    );
}

#[test]
fn dns_mode_accepts_only_named_values() {
    for (value, mode) in [
        ("on", DnsMode::On),
        ("partial", DnsMode::Partial),
        ("off", DnsMode::Off),
    ] {
        assert_eq!(value.parse::<DnsMode>().expect("named mode"), mode);
    }
    for value in [
        "1", "yes", "true", "0", "no", "false", "ON", "OFF", "PARTIAL",
    ] {
        assert!(
            value.parse::<DnsMode>().is_err(),
            "{value} must be rejected"
        );
    }
}

#[test]
fn network_aliases_roundtrip_and_default_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    // A network with aliases persists them across a save/load cycle.
    let mut n = net("homelab");
    n.aliases.insert("alice".into(), "id-alice".into());
    n.aliases.insert("bob".into(), "id-bob".into());
    save_network_unlocked(dir, &n).unwrap();
    let loaded = load_network_unlocked(dir, "homelab").unwrap().unwrap();
    assert_eq!(
        loaded.aliases.get("alice").map(String::as_str),
        Some("id-alice")
    );
    assert_eq!(
        loaded.aliases.get("bob").map(String::as_str),
        Some("id-bob")
    );

    // A network with no aliases omits the key; loading a toml without it
    // defaults to an empty map (backward compatible with pre-alias configs).
    let plain = net("genesis");
    assert!(plain.aliases.is_empty());
    let toml = ::toml::to_string(&plain).unwrap();
    assert!(
        !toml.contains("aliases"),
        "empty aliases must not be serialized"
    );
    let back: NetworkConfig = ::toml::from_str(&toml).unwrap();
    assert!(back.aliases.is_empty());
}

#[test]
fn settings_roundtrip_server_overrides() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    // A fresh dir (no settings.toml) loads all three overrides as unset.
    let fresh = load_in(dir).unwrap();
    assert!(fresh.relay.is_unset());
    assert!(fresh.discovery_dns.is_unset());
    assert!(fresh.dns_upstreams.is_unset());

    let cfg = AppConfig {
        relay: ServerOverride {
            servers: vec!["http://r:1".into()],
            replace: true,
        },
        dns_upstreams: ServerOverride {
            servers: vec!["1.1.1.1".into()],
            replace: false,
        },
        ..Default::default()
    };
    save_settings_in(dir, &cfg).unwrap();

    let loaded = load_in(dir).unwrap();
    assert_eq!(loaded.relay, cfg.relay);
    assert_eq!(loaded.dns_upstreams, cfg.dns_upstreams);
    assert!(loaded.discovery_dns.is_unset());
}

#[test]
fn relay_urls_expands_rayfish_preset() {
    let o = ServerOverride {
        servers: vec!["rayfish".into()],
        replace: false,
    };
    assert_eq!(
        relay_urls(&o).unwrap(),
        vec![RELAY_PRESET_RAYFISH.to_string()]
    );
    let d = ServerOverride {
        servers: vec!["rayfish".into()],
        replace: false,
    };
    assert_eq!(
        discovery_urls(&d).unwrap(),
        vec![DISCOVERY_PRESET_RAYFISH.to_string()]
    );
}

#[test]
fn url_entry_rejects_bad() {
    assert!(
        relay_urls(&ServerOverride {
            servers: vec!["ftp://x".into()],
            replace: false
        })
        .is_err()
    );
    assert!(
        relay_urls(&ServerOverride {
            servers: vec!["not a url".into()],
            replace: false
        })
        .is_err()
    );
    // A real http URL passes through unchanged.
    let ok = ServerOverride {
        servers: vec!["http://r:1".into()],
        replace: false,
    };
    assert_eq!(relay_urls(&ok).unwrap(), vec!["http://r:1".to_string()]);
}

#[test]
fn resolve_upstreams_augment_and_replace() {
    let captured = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))];
    let one = Ipv4Addr::new(1, 1, 1, 1);

    // Unset: captured unchanged.
    assert_eq!(
        resolve_upstreams(&ServerOverride::default(), captured.clone()),
        captured
    );

    // Augment: custom first, then captured.
    let aug = ServerOverride {
        servers: vec!["1.1.1.1".into()],
        replace: false,
    };
    assert_eq!(
        resolve_upstreams(&aug, captured.clone()),
        vec![IpAddr::V4(one), captured[0]]
    );

    // Replace: custom only.
    let rep = ServerOverride {
        servers: vec!["1.1.1.1".into()],
        replace: true,
    };
    assert_eq!(
        resolve_upstreams(&rep, captured.clone()),
        vec![IpAddr::V4(one)]
    );

    // Tailscale remains the preferred upstream even when the user added a
    // different resolver, while Rayfish itself still intercepts `.ray`.
    let tailscale = IpAddr::V4(Ipv4Addr::new(100, 100, 100, 100));
    assert_eq!(
        resolve_upstreams(&aug, vec![captured[0], tailscale]),
        vec![tailscale, IpAddr::V4(one), captured[0]]
    );
}

/// A host whose resolv.conf names an IPv6 server keeps forwarding to it,
/// under the same override rules as its IPv4 ones.
#[test]
fn captured_v6_upstreams_follow_the_override_rules() {
    let v4: IpAddr = "192.0.2.1".parse().unwrap();
    let v6: IpAddr = "2001:db8::1".parse().unwrap();
    assert_eq!(
        resolve_upstreams(&ServerOverride::default(), vec![v4, v6]),
        vec![v4, v6]
    );
    let replace = ServerOverride {
        servers: vec!["9.9.9.9".into()],
        replace: true,
    };
    assert_eq!(
        resolve_upstreams(&replace, vec![v4, v6]),
        vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]
    );
    // Already listed (the operator named it too): not twice.
    let augment = ServerOverride {
        servers: vec![v6.to_string()],
        replace: false,
    };
    assert_eq!(resolve_upstreams(&augment, vec![v6]), vec![v6]);
}

/// An IPv6 upstream can be a resolver on a mesh peer. `--replace` must leave
/// that address intact so it receives every non-`.ray` lookup.
#[test]
fn replace_with_only_ipv6_uses_the_configured_peer() {
    let captured = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))];
    let peer: Ipv6Addr = "200::1234".parse().unwrap();
    let v6_only = ServerOverride {
        servers: vec![peer.to_string()],
        replace: true,
    };
    assert_eq!(
        resolve_upstreams(&v6_only, captured.clone()),
        vec![IpAddr::V6(peer)]
    );

    // Both families retain their order under `--replace`.
    let mixed = ServerOverride {
        servers: vec![peer.to_string(), "1.1.1.1".into()],
        replace: true,
    };
    assert_eq!(
        resolve_upstreams(&mixed, captured),
        vec![IpAddr::V6(peer), IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]
    );
}

/// `has_usable_upstream` has to agree with what `resolve_upstreams` keeps.
///
/// It waives the refusal to take over `/etc/resolv.conf` with no verified
/// upstream of our own. Answering yes on a setting that then narrows to
/// nothing would take the file, install the re-assert watcher, and leave the
/// forwarder with an empty list: the host loses every name outside `.ray`,
/// and repairing the file by hand is undone by the watcher. That is worse
/// than the refusal it bypassed, so the two must not disagree.
#[test]
fn only_a_usable_upstream_waives_the_takeover_guard() {
    let captured: Vec<IpAddr> = Vec::new();
    for (servers, usable) in [
        (vec!["2606:4700:4700::1111"], true),
        (vec!["2606:4700:4700::1111", "2001:4860:4860::8888"], true),
        (vec!["1.1.1.1"], true),
        (vec!["2606:4700:4700::1111", "1.1.1.1"], true),
        (vec!["not-an-address"], false),
        (vec![], false),
    ] {
        for replace in [false, true] {
            let o = ServerOverride {
                servers: servers.iter().map(|s| s.to_string()).collect(),
                replace,
            };
            assert_eq!(has_usable_upstream(&o), usable, "{servers:?}");
            // The claim this guard makes, stated the other way round: saying
            // yes must mean the forwarder actually gets a server.
            assert_eq!(
                !resolve_upstreams(&o, captured.clone()).is_empty(),
                usable,
                "{servers:?} replace={replace}"
            );
        }
    }
}

#[test]
fn config_set_n0_resets() {
    let mut cfg = AppConfig::default();
    config_set(&mut cfg, settings::GlobalKey::Relay, "rayfish", true).unwrap();
    assert!(!cfg.relay.is_unset());
    config_set(&mut cfg, settings::GlobalKey::Relay, "n0", false).unwrap();
    assert!(cfg.relay.is_unset());
}

#[test]
fn config_set_dns_upstreams_rejects_non_ip() {
    let mut cfg = AppConfig::default();
    assert!(
        config_set(
            &mut cfg,
            settings::GlobalKey::DnsUpstreams,
            "1.1.1.1",
            false
        )
        .is_ok()
    );
    assert!(
        config_set(
            &mut cfg,
            settings::GlobalKey::DnsUpstreams,
            "not-an-ip",
            false
        )
        .is_err()
    );
    // rayfish is not a valid upstream keyword.
    assert!(
        config_set(
            &mut cfg,
            settings::GlobalKey::DnsUpstreams,
            "rayfish",
            false
        )
        .is_err()
    );
}

// Regression for the bug that prompted this change: concurrent saves of
// distinct networks used to clobber one another through a single
// non-atomic `networks.toml`. With one file per network they cannot.
#[test]
fn concurrent_saves_do_not_clobber() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    const N: usize = 24;

    std::thread::scope(|s| {
        for i in 0..N {
            let dir = dir.clone();
            s.spawn(move || {
                save_network_unlocked(&dir, &net(&format!("net-{i}"))).unwrap();
            });
        }
    });

    let loaded = load_in(&dir).unwrap();
    assert_eq!(
        loaded.networks.len(),
        N,
        "all concurrent saves must survive"
    );
}

/// The network shards got a transaction boundary but `settings.toml` did
/// not, so the ten `load()` -> mutate one global -> `save_settings()` sites
/// still raced: each wrote back the whole file, reverting whatever another
/// task had changed in between.
#[test]
fn concurrent_settings_updates_preserve_unrelated_globals() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    let barrier = std::sync::Barrier::new(3);

    std::thread::scope(|scope| {
        scope.spawn(|| {
            barrier.wait();
            update_settings_in(&dir, |cfg| {
                cfg.operator_uid = Some(1234);
                Ok(())
            })
            .unwrap();
        });
        scope.spawn(|| {
            barrier.wait();
            update_settings_in(&dir, |cfg| {
                cfg.default_hostname = Some("umbrel".into());
                Ok(())
            })
            .unwrap();
        });
        barrier.wait();
    });

    let loaded = load_in(&dir).unwrap();
    assert_eq!(loaded.operator_uid, Some(1234));
    assert_eq!(loaded.default_hostname.as_deref(), Some("umbrel"));
}

/// A failing callback must leave the file as it was, not write a
/// half-applied config.
#[test]
fn a_failed_settings_update_saves_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    update_settings_in(&dir, |cfg| {
        cfg.operator_uid = Some(7);
        Ok(())
    })
    .unwrap();

    let err = update_settings_in(&dir, |cfg| {
        cfg.operator_uid = Some(9);
        anyhow::bail!("callback failed")
    });

    assert!(err.is_err());
    assert_eq!(load_in(&dir).unwrap().operator_uid, Some(7));
}

#[test]
fn concurrent_same_network_updates_preserve_unrelated_fields() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    save_network_unlocked(&dir, &net("homelab")).unwrap();
    let barrier = std::sync::Barrier::new(3);

    std::thread::scope(|scope| {
        scope.spawn(|| {
            barrier.wait();
            update_network_in(&dir, "homelab", |net| {
                net.aliases.insert("alice".into(), "id-alice".into());
                Ok(())
            })
            .unwrap();
        });
        scope.spawn(|| {
            barrier.wait();
            update_network_in(&dir, "homelab", |net| {
                net.last_group_hash = Some(blake3::hash(b"latest group"));
                net.auto_accept_files = false;
                Ok(())
            })
            .unwrap();
        });
        barrier.wait();
    });

    let loaded = load_network_unlocked(&dir, "homelab").unwrap().unwrap();
    assert_eq!(
        loaded.aliases.get("alice").map(String::as_str),
        Some("id-alice")
    );
    assert_eq!(loaded.last_group_hash, Some(blake3::hash(b"latest group")));
    assert!(!loaded.auto_accept_files);
}

#[test]
fn update_or_insert_uses_initial_only_when_network_is_absent() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let mut initial = net("homelab");
    initial.aliases.insert("local".into(), "first".into());

    update_network_or_insert_in(dir, "homelab", initial, |net| {
        net.last_group_hash = Some(blake3::hash(b"first group"));
        net.auto_accept_firewall = true;
        Ok(())
    })
    .unwrap();

    let mut stale_initial = net("homelab");
    stale_initial.aliases.insert("local".into(), "stale".into());
    update_network_or_insert_in(dir, "homelab", stale_initial, |net| {
        net.my_hostname = Some("latest".into());
        Ok(())
    })
    .unwrap();

    let loaded = load_network_unlocked(dir, "homelab").unwrap().unwrap();
    assert_eq!(
        loaded.aliases.get("local").map(String::as_str),
        Some("first")
    );
    assert_eq!(loaded.last_group_hash, Some(blake3::hash(b"first group")));
    assert!(loaded.auto_accept_firewall);
    assert_eq!(loaded.my_hostname.as_deref(), Some("latest"));
}

#[test]
fn network_update_reentry_is_rejected_before_locking() {
    let _scope = NetworkUpdateScope::enter().unwrap();
    let error = ensure_not_in_network_update().unwrap_err();
    assert!(
        error
            .to_string()
            .contains("network config update callbacks must not call network config APIs")
    );
}

/// A no-op update still re-syncs the file, and that must succeed. It runs on
/// every retry of an already-durable write, so a re-sync that always fails
/// leaves the caller retrying a write that has nothing left to do: the
/// coordinator republished its pkarr record every five seconds instead of
/// every two and a half minutes, for as long as the daemon ran. Windows is
/// the case this guards, where `FlushFileBuffers` rejects a read-only handle.
#[test]
fn a_no_op_network_update_re_syncs_rather_than_failing() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    save_network_unlocked(dir, &net("homelab")).unwrap();

    let updated = update_network_in(dir, "homelab", |_| Ok(()))
        .expect("a no-op update re-syncs the file rather than reporting a disk error")
        .expect("the network exists");

    assert_eq!(updated.name, "homelab");
}

#[test]
fn failed_network_update_does_not_persist_partial_mutation() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    save_network_unlocked(dir, &net("homelab")).unwrap();

    let result = update_network_in(dir, "homelab", |net| {
        net.aliases.insert("alice".into(), "id-alice".into());
        anyhow::bail!("reject update")
    });

    assert!(result.is_err());
    assert!(
        load_network_unlocked(dir, "homelab")
            .unwrap()
            .unwrap()
            .aliases
            .is_empty()
    );
}

#[test]
fn migrate_legacy_splits_and_backs_up() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    // Write a legacy single-file config (the pre-shard format).
    let legacy = AppConfig {
        default_hostname: Some("laptop".into()),
        networks: vec![net("homelab"), net("genesis")],
        ..Default::default()
    };
    std::fs::write(
        dir.join(LEGACY_FILE),
        toml::to_string_pretty(&legacy).unwrap(),
    )
    .unwrap();

    migrate_legacy(dir).unwrap();

    // Legacy file preserved as a backup, original gone.
    assert!(!dir.join(LEGACY_FILE).exists());
    assert!(dir.join("networks.toml.bak").exists());

    // Both networks + globals are now in the sharded layout.
    let loaded = load_in(dir).unwrap();
    assert_eq!(loaded.networks.len(), 2);
    assert_eq!(loaded.default_hostname.as_deref(), Some("laptop"));

    // Idempotent: a second migrate (no legacy file) is a no-op.
    migrate_legacy(dir).unwrap();
    assert_eq!(load_in(dir).unwrap().networks.len(), 2);
}

#[test]
fn rejects_unsafe_network_names() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    assert!(save_network_unlocked(dir, &net("../escape")).is_err());
    assert!(load_network_unlocked(dir, "a/b").is_err());
}

#[test]
fn pending_join_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    // Start from an empty settings file.
    save_settings_in(dir, &AppConfig::default()).unwrap();

    add_pending_join_in(
        dir,
        PendingJoinEntry {
            network_key: "abc123".to_string(),
            name: Some("homelab".to_string()),
            transport: Some(TransportMode::Tor),
        },
    )
    .unwrap();

    let loaded = load_in(dir).unwrap();
    assert_eq!(loaded.pending_joins.len(), 1);
    assert_eq!(loaded.pending_joins[0].network_key, "abc123");
    assert_eq!(loaded.pending_joins[0].transport, Some(TransportMode::Tor));

    // Adding the same key again does not duplicate it.
    add_pending_join_in(
        dir,
        PendingJoinEntry {
            network_key: "abc123".to_string(),
            name: None,
            transport: None,
        },
    )
    .unwrap();
    assert_eq!(load_in(dir).unwrap().pending_joins.len(), 1);

    remove_pending_join_in(dir, "abc123").unwrap();
    assert!(load_in(dir).unwrap().pending_joins.is_empty());
}

/// A pending join saved before the transport was recorded still loads.
#[test]
fn a_pending_join_without_a_transport_loads() {
    let entry: PendingJoinEntry =
        toml::from_str("network_key = \"abc123\"\nname = \"homelab\"\n").unwrap();
    assert_eq!(entry.name.as_deref(), Some("homelab"));
    assert_eq!(entry.transport, None);
}

/// The temp file was named `.{fname}.tmp.{pid}`: one path per file per
/// process, so two threads writing the same config opened the same temp
/// file and one could rename a file the other was still filling. The
/// survivor's content was then whatever the two writers had interleaved.
#[test]
fn concurrent_writes_to_one_path_never_mix() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("settings.toml");
    let candidates = ["a".repeat(4096), "b".repeat(16384), "c".repeat(65536)];

    for _ in 0..25 {
        std::thread::scope(|s| {
            for c in &candidates {
                s.spawn(|| write_file(&path, c.as_bytes(), false).unwrap());
            }
        });
        let got = std::fs::read_to_string(&path).unwrap();
        assert!(
            candidates.contains(&got),
            "torn file: {} bytes, starts {:?}",
            got.len(),
            &got[..got.len().min(8)]
        );
    }

    let left: Vec<String> = std::fs::read_dir(tmp.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".tmp."))
        .collect();
    assert!(left.is_empty(), "temp files left behind: {left:?}");
}

#[test]
fn settings_file_leaves_the_networks_to_their_own_files() {
    let config = AppConfig {
        networks: vec![empty_network_config("lab")],
        ..Default::default()
    };
    let text = settings_toml(&config).expect("serialize settings");
    let parsed: AppConfig = toml::from_str(&text).expect("parse settings");
    assert!(parsed.networks.is_empty());
    assert_eq!(parsed.ssh_port, config.ssh_port);
}
