use super::*;

fn id(seed: u8) -> EndpointId {
    let mut bytes = [0; 32];
    bytes[0] = seed;
    SecretKey::from(bytes).public()
}

#[test]
fn resolves_exact_name_or_unambiguous_identity_prefix() {
    let alice = id(1);
    let bob = id(2);
    let candidates = || {
        vec![
            (alice, Some("alice".to_string())),
            (bob, Some("bob".to_string())),
        ]
    };

    assert_eq!(
        resolve_named_identity("alice", candidates()),
        Ok(Some(alice))
    );
    assert_eq!(
        resolve_named_identity(&bob.fmt_short().to_string(), candidates()),
        Ok(Some(bob))
    );
    assert_eq!(resolve_named_identity("missing", candidates()), Ok(None));
    assert_eq!(resolve_named_identity("", candidates()), Err(()));
}

#[test]
fn rejects_duplicate_names() {
    assert_eq!(
        resolve_named_identity(
            "same",
            [
                (id(1), Some("same".to_string())),
                (id(2), Some("same".to_string()))
            ],
        ),
        Err(())
    );
}
