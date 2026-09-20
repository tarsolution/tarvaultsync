use std::process::Command;

#[test]
fn informational_commands_do_not_open_or_create_a_workspace() {
    let temp = tempfile::tempdir().unwrap();
    let missing = temp.path().join("not-created");
    for option in ["--version", "--help"] {
        let result = Command::new(env!("CARGO_BIN_EXE_tar-vault-sync"))
            .arg(option)
            .env("TAR_VAULT_SYNC_DIR", &missing)
            .output()
            .unwrap();
        assert!(result.status.success());
        assert!(String::from_utf8(result.stdout)
            .unwrap()
            .contains("TAR Vault Sync"));
        assert!(!missing.exists());
    }
}
