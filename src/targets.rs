use crate::core::{
    DockerInputKind, ErrorCategory, LocalTarget, MissingTargetPolicy, SecretPayload, SecretType,
    StructuredFormat, TargetSpec,
};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    str::FromStr,
};
use yaml_edit::YamlFile;

#[cfg(windows)]
const GCM_STORE: &str = "wincredman";
#[cfg(target_os = "macos")]
const GCM_STORE: &str = "keychain";
#[cfg(all(unix, not(target_os = "macos")))]
const GCM_STORE: &str = "secretservice";

pub struct ProductionTarget {
    root: PathBuf,
}

impl ProductionTarget {
    pub fn new(root: PathBuf) -> Result<Self, ErrorCategory> {
        let root = root
            .canonicalize()
            .map_err(|_| ErrorCategory::InvalidConfig)?;
        Ok(Self { root })
    }

    fn checked_path<'a>(&self, spec: &'a TargetSpec) -> Result<Option<&'a Path>, ErrorCategory> {
        let path = match spec {
            TargetSpec::WholeFile { path }
            | TargetSpec::StructuredField { path, .. }
            | TargetSpec::DockerInput { path, .. } => path,
            TargetSpec::GitCredential { .. } => return Ok(None),
            TargetSpec::Fake { .. } => return Err(ErrorCategory::InvalidConfig),
        };
        let parent = path.parent().ok_or(ErrorCategory::InvalidConfig)?;
        let parent = parent.canonicalize().map_err(|_| ErrorCategory::Target)?;
        if !path.is_absolute() || !parent.starts_with(&self.root) {
            return Err(ErrorCategory::InvalidConfig);
        }
        if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(ErrorCategory::InvalidConfig);
        }
        Ok(Some(path))
    }

    fn apply_file(
        &self,
        spec: &TargetSpec,
        payload: &SecretPayload,
        policy: &MissingTargetPolicy,
    ) -> Result<(), ErrorCategory> {
        let path = self
            .checked_path(spec)?
            .ok_or(ErrorCategory::InvalidConfig)?;
        let existing = match fs::read(path) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err(ErrorCategory::Target),
        };
        if existing.is_none() && *policy != MissingTargetPolicy::Recreate {
            return Err(ErrorCategory::Target);
        }
        let rendered = match spec {
            TargetSpec::WholeFile { .. } => return atomic_write(path, payload.as_bytes()),
            TargetSpec::StructuredField { key, format, .. } => {
                let prior = existing.as_deref().unwrap_or_default();
                render_structured(prior, key, format, payload)?
            }
            TargetSpec::DockerInput { key, input, .. } => {
                let prior = existing.as_deref().unwrap_or_default();
                match input {
                    DockerInputKind::EnvFile { .. } => {
                        render_key_value(prior, key, payload, KeyValueStyle::SingleQuoted)?
                    }
                    DockerInputKind::ComposeEnvironment => render_compose(prior, key, payload)?,
                }
            }
            _ => return Err(ErrorCategory::InvalidConfig),
        };
        atomic_write(path, &rendered)
    }
}

impl LocalTarget for ProductionTarget {
    fn validate(&self, spec: &TargetSpec, kind: &SecretType) -> Result<(), ErrorCategory> {
        self.checked_path(spec)?;
        match spec {
            TargetSpec::WholeFile { .. } => Ok(()),
            TargetSpec::StructuredField { format, .. }
                if *kind == SecretType::Text
                    || (*kind == SecretType::Json && *format != StructuredFormat::Yaml) =>
            {
                Ok(())
            }
            TargetSpec::DockerInput { path, input, .. } if *kind == SecretType::Text => {
                if let DockerInputKind::EnvFile {
                    compose_path,
                    service,
                } = input
                {
                    validate_env_file_relation(&self.root, compose_path, service, path)?;
                }
                Ok(())
            }
            TargetSpec::GitCredential {
                protocol,
                host,
                path,
                username,
            } if *kind == SecretType::Text
                && protocol == "https"
                && !host.is_empty()
                && !username.is_empty()
                && (path.is_none() || git_uses_http_path(host, path.as_deref().unwrap())) =>
            {
                Ok(())
            }
            _ => Err(ErrorCategory::InvalidConfig),
        }
    }

    fn is_missing(&self, spec: &TargetSpec) -> bool {
        match spec {
            TargetSpec::WholeFile { path }
            | TargetSpec::StructuredField { path, .. }
            | TargetSpec::DockerInput { path, .. } => !path.exists(),
            _ => false,
        }
    }

    fn apply(&self, spec: &TargetSpec, payload: &SecretPayload) -> Result<(), ErrorCategory> {
        self.apply_with_policy(spec, payload, &MissingTargetPolicy::Alert)
    }

    fn apply_with_policy(
        &self,
        spec: &TargetSpec,
        payload: &SecretPayload,
        policy: &MissingTargetPolicy,
    ) -> Result<(), ErrorCategory> {
        self.validate(spec, &payload.kind)?;
        match spec {
            TargetSpec::GitCredential {
                protocol,
                host,
                path,
                username,
            } => store_git_credential(protocol, host, path.as_deref(), username, payload),
            _ => self.apply_file(spec, payload, policy),
        }
    }
}

fn render_structured(
    prior: &[u8],
    key: &str,
    format: &StructuredFormat,
    payload: &SecretPayload,
) -> Result<Vec<u8>, ErrorCategory> {
    match format {
        StructuredFormat::DotEnv => {
            render_key_value(prior, key, payload, KeyValueStyle::SingleQuoted)
        }
        StructuredFormat::Properties => {
            render_key_value(prior, key, payload, KeyValueStyle::Properties)
        }
        StructuredFormat::Json => {
            let mut value: serde_json::Value = if prior.is_empty() {
                serde_json::json!({})
            } else {
                serde_json::from_slice(prior).map_err(|_| ErrorCategory::Target)?
            };
            let text =
                std::str::from_utf8(payload.as_bytes()).map_err(|_| ErrorCategory::Target)?;
            let replacement = if payload.kind == SecretType::Json {
                serde_json::from_str(text).map_err(|_| ErrorCategory::Target)?
            } else {
                serde_json::Value::String(text.to_owned())
            };
            *value.pointer_mut(key).ok_or(ErrorCategory::Target)? = replacement;
            serde_json::to_vec_pretty(&value).map_err(|_| ErrorCategory::Target)
        }
        StructuredFormat::Yaml => render_yaml(prior, key, payload),
    }
}

#[derive(Clone, Copy)]
enum KeyValueStyle {
    SingleQuoted,
    Properties,
}

fn render_key_value(
    prior: &[u8],
    key: &str,
    payload: &SecretPayload,
    style: KeyValueStyle,
) -> Result<Vec<u8>, ErrorCategory> {
    let source = std::str::from_utf8(prior).map_err(|_| ErrorCategory::Target)?;
    let value = std::str::from_utf8(payload.as_bytes()).map_err(|_| ErrorCategory::Target)?;
    if value.contains(['\r', '\n', '\0']) {
        return Err(ErrorCategory::Target);
    }
    let encoded = match style {
        KeyValueStyle::SingleQuoted => {
            format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
        }
        KeyValueStyle::Properties => value
            .replace('\\', "\\\\")
            .replace('=', "\\=")
            .replace(':', "\\:"),
    };
    let newline = if source.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut found = false;
    let mut out = String::with_capacity(source.len() + encoded.len() + key.len() + 4);
    for line in source.split_inclusive('\n') {
        let body = line.trim_end_matches(['\r', '\n']);
        let trimmed = body.trim_start();
        let candidate = if matches!(style, KeyValueStyle::Properties) {
            if trimmed.starts_with(['#', '!']) {
                None
            } else {
                let end = trimmed.find(|c: char| c == '=' || c == ':' || c.is_ascii_whitespace());
                end.map(|index| &trimmed[..index])
            }
        } else {
            trimmed
                .strip_prefix("export ")
                .unwrap_or(trimmed)
                .split_once('=')
                .map(|(k, _)| k.trim())
        };
        if candidate == Some(key) {
            if found {
                return Err(ErrorCategory::Target);
            }
            found = true;
            if body.trim_start().starts_with("export ") {
                out.push_str("export ");
            }
            out.push_str(key);
            out.push('=');
            out.push_str(&encoded);
            if line.ends_with('\n') {
                out.push_str(newline);
            }
        } else {
            out.push_str(line);
        }
    }
    if !found {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push_str(newline);
        }
        out.push_str(key);
        out.push('=');
        out.push_str(&encoded);
        out.push_str(newline);
    }
    Ok(out.into_bytes())
}

fn render_yaml(
    prior: &[u8],
    pointer: &str,
    payload: &SecretPayload,
) -> Result<Vec<u8>, ErrorCategory> {
    let source = std::str::from_utf8(prior).map_err(|_| ErrorCategory::Target)?;
    let value = std::str::from_utf8(payload.as_bytes()).map_err(|_| ErrorCategory::Target)?;
    render_yaml_text(source, pointer, value)
}

fn render_yaml_text(source: &str, pointer: &str, value: &str) -> Result<Vec<u8>, ErrorCategory> {
    if value.contains(['\r', '\n', '\0']) {
        return Err(ErrorCategory::Target);
    }
    let file = YamlFile::from_str(source).map_err(|_| ErrorCategory::Target)?;
    if file.documents().count() != 1 {
        return Err(ErrorCategory::Target);
    }
    let doc = file.document().ok_or(ErrorCategory::Target)?;
    let parts: Vec<_> = pointer
        .trim_start_matches('/')
        .split('/')
        .map(unescape_pointer)
        .collect();
    if parts.is_empty() || parts.iter().any(|p| p.is_empty()) {
        return Err(ErrorCategory::InvalidConfig);
    }
    let mut mapping = doc.as_mapping().ok_or(ErrorCategory::Target)?.clone();
    for part in &parts[..parts.len() - 1] {
        mapping = mapping
            .get(part.as_str())
            .and_then(|n| n.as_mapping().cloned())
            .ok_or(ErrorCategory::Target)?;
    }
    if mapping.get(parts[parts.len() - 1].as_str()).is_none() {
        return Err(ErrorCategory::Target);
    }
    mapping.set(parts[parts.len() - 1].as_str(), value);
    Ok(file.to_string().into_bytes())
}

fn render_compose(
    prior: &[u8],
    key: &str,
    payload: &SecretPayload,
) -> Result<Vec<u8>, ErrorCategory> {
    // A binding selects one service with `service:VARIABLE`.
    let (service, variable) = key.split_once(':').ok_or(ErrorCategory::InvalidConfig)?;
    let pointer = format!("/services/{service}/environment/{variable}");
    let source = std::str::from_utf8(prior).map_err(|_| ErrorCategory::Target)?;
    let value = std::str::from_utf8(payload.as_bytes()).map_err(|_| ErrorCategory::Target)?;
    render_yaml_text(source, &pointer, &value.replace('$', "$$"))
}

fn validate_env_file_relation(
    root: &Path,
    compose_path: &Path,
    service: &str,
    target: &Path,
) -> Result<(), ErrorCategory> {
    let source = fs::read_to_string(compose_path).map_err(|_| ErrorCategory::Target)?;
    let file = YamlFile::from_str(&source).map_err(|_| ErrorCategory::Target)?;
    if file.documents().count() != 1 {
        return Err(ErrorCategory::Target);
    }
    let entry = file
        .document()
        .and_then(|d| d.get("services"))
        .and_then(|n| n.get(service))
        .and_then(|n| n.get("env_file"))
        .ok_or(ErrorCategory::Target)?;
    let candidates: Vec<String> = if let Some(scalar) = entry.as_scalar() {
        vec![scalar.as_string()]
    } else if let Some(sequence) = entry.as_sequence() {
        sequence
            .into_iter()
            .map(|item| {
                if let Some(scalar) = item.as_scalar() {
                    Ok(scalar.as_string())
                } else if let Some(path) = item
                    .get("path")
                    .and_then(|n| n.as_scalar().map(|s| s.as_string()))
                {
                    if item.get("format").is_some() {
                        Err(ErrorCategory::InvalidConfig)
                    } else {
                        Ok(path)
                    }
                } else {
                    Err(ErrorCategory::InvalidConfig)
                }
            })
            .collect::<Result<Vec<_>, _>>()?
    } else {
        return Err(ErrorCategory::InvalidConfig);
    };
    let target = scoped_file_path(root, target)?;
    let mut matches = 0;
    for candidate in candidates {
        if candidate.is_empty() || candidate.contains('$') {
            return Err(ErrorCategory::InvalidConfig);
        }
        let relative = Path::new(&candidate);
        if relative
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(ErrorCategory::InvalidConfig);
        }
        let listed = if relative.is_absolute() {
            relative.to_path_buf()
        } else {
            compose_path
                .parent()
                .ok_or(ErrorCategory::InvalidConfig)?
                .join(relative)
        };
        let listed = scoped_file_path(root, &listed)?;
        if listed == target {
            matches += 1;
        }
    }
    if matches != 1 {
        return Err(ErrorCategory::InvalidConfig);
    }
    Ok(())
}

fn scoped_file_path(root: &Path, path: &Path) -> Result<PathBuf, ErrorCategory> {
    let parent = path
        .parent()
        .ok_or(ErrorCategory::InvalidConfig)?
        .canonicalize()
        .map_err(|_| ErrorCategory::InvalidConfig)?;
    if !parent.starts_with(root)
        || fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
    {
        return Err(ErrorCategory::InvalidConfig);
    }
    Ok(parent.join(path.file_name().ok_or(ErrorCategory::InvalidConfig)?))
}

fn unescape_pointer(s: &str) -> String {
    s.replace("~1", "/").replace("~0", "~")
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), ErrorCategory> {
    let parent = path.parent().ok_or(ErrorCategory::Target)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent).map_err(|_| ErrorCategory::Target)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| ErrorCategory::Target)?;
    }
    temp.write_all(bytes)
        .and_then(|_| temp.as_file().sync_all())
        .map_err(|_| ErrorCategory::Target)?;
    temp.persist(path).map_err(|_| ErrorCategory::Target)?;
    Ok(())
}

fn store_git_credential(
    protocol: &str,
    host: &str,
    path: Option<&str>,
    username: &str,
    payload: &SecretPayload,
) -> Result<(), ErrorCategory> {
    let bytes = payload.as_bytes();
    if bytes.is_empty() || bytes.iter().any(|b| matches!(b, b'\n' | b'\r' | b'\0')) {
        return Err(ErrorCategory::Target);
    }
    let mut child = Command::new("git")
        .args(["credential-manager", "store"])
        .env("GCM_CREDENTIAL_STORE", GCM_STORE)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ErrorCategory::Target)?;
    let result = (|| {
        let stdin = child.stdin.as_mut().ok_or(ErrorCategory::Target)?;
        write!(stdin, "protocol={protocol}\nhost={host}\n").map_err(|_| ErrorCategory::Target)?;
        if let Some(path) = path {
            writeln!(stdin, "path={path}").map_err(|_| ErrorCategory::Target)?;
        }
        write!(stdin, "username={username}\npassword=").map_err(|_| ErrorCategory::Target)?;
        stdin
            .write_all(bytes)
            .and_then(|_| stdin.write_all(b"\n\n"))
            .map_err(|_| ErrorCategory::Target)
    })();
    drop(child.stdin.take());
    if result.is_err() {
        let _ = child.kill();
    }
    let status = child.wait().map_err(|_| ErrorCategory::Target)?;
    result?;
    if !status.success() {
        return Err(ErrorCategory::Target);
    }
    Ok(())
}

fn git_uses_http_path(host: &str, path: &str) -> bool {
    if host.eq_ignore_ascii_case("dev.azure.com") {
        return false;
    }
    let url = format!("https://{host}/{path}");
    Command::new("git")
        .args([
            "config",
            "--global",
            "--get-urlmatch",
            "credential.useHttpPath",
            &url,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .is_ok_and(|result| {
            result.status.success()
                && String::from_utf8(result.stdout)
                    .is_ok_and(|value| value.trim().eq_ignore_ascii_case("true"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe() -> SecretPayload {
        SecretPayload::new(b"probe-value".to_vec(), SecretType::Text)
    }

    #[test]
    fn file_renderers_preserve_unrelated_content_and_failure_preserves_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = ProductionTarget::new(dir.path().to_path_buf()).unwrap();
        let dotenv = dir.path().join("sample.env");
        fs::write(&dotenv, b"# kept\r\nTOKEN=old\r\nOTHER=1\r\n").unwrap();
        let spec = TargetSpec::StructuredField {
            path: dotenv.clone(),
            key: "TOKEN".into(),
            format: StructuredFormat::DotEnv,
        };
        target.apply(&spec, &probe()).unwrap();
        let data = fs::read_to_string(&dotenv).unwrap();
        assert!(data.contains("# kept\r\n"));
        assert!(data.contains("OTHER=1\r\n"));
        assert!(data.contains("TOKEN='probe-value'\r\n"));
        let before = fs::read(&dotenv).unwrap();
        let bad = SecretPayload::new(b"line\nbreak".to_vec(), SecretType::Text);
        assert_eq!(target.apply(&spec, &bad), Err(ErrorCategory::Target));
        assert_eq!(fs::read(&dotenv).unwrap(), before);

        let json = dir.path().join("sample.json");
        fs::write(&json, br#"{"nested":{"token":"old"},"other":7}"#).unwrap();
        let spec = TargetSpec::StructuredField {
            path: json.clone(),
            key: "/nested/token".into(),
            format: StructuredFormat::Json,
        };
        target.apply(&spec, &probe()).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&fs::read(&json).unwrap()).unwrap();
        assert_eq!(value["other"], 7);
        assert_eq!(value["nested"]["token"], "probe-value");

        let properties = dir.path().join("app.properties");
        fs::write(&properties, "# kept\nTOKEN: old\nOTHER=1\n").unwrap();
        let spec = TargetSpec::StructuredField {
            path: properties.clone(),
            key: "TOKEN".into(),
            format: StructuredFormat::Properties,
        };
        target.apply(&spec, &probe()).unwrap();
        let data = fs::read_to_string(&properties).unwrap();
        assert!(data.contains("# kept\n"));
        assert!(data.contains("TOKEN=probe-value\n"));
        assert!(data.contains("OTHER=1\n"));

        let raw = dir.path().join("binary.bin");
        let spec = TargetSpec::WholeFile { path: raw.clone() };
        let binary = SecretPayload::new(vec![0, 255, 1], SecretType::Binary);
        target
            .apply_with_policy(&spec, &binary, &MissingTargetPolicy::Recreate)
            .unwrap();
        assert_eq!(fs::read(&raw).unwrap(), binary.as_bytes());
    }

    #[test]
    fn yaml_and_docker_keep_other_fields() {
        let dir = tempfile::tempdir().unwrap();
        let target = ProductionTarget::new(dir.path().to_path_buf()).unwrap();
        let yaml = dir.path().join("sample.yaml");
        fs::write(&yaml, "# keep\nsettings:\n  token: old\n  other: yes\n").unwrap();
        let spec = TargetSpec::StructuredField {
            path: yaml.clone(),
            key: "/settings/token".into(),
            format: StructuredFormat::Yaml,
        };
        target.apply(&spec, &probe()).unwrap();
        let updated = fs::read_to_string(&yaml).unwrap();
        assert!(updated.contains("# keep"));
        assert!(updated.contains("other: yes"));
        assert!(updated.contains("probe-value"));

        let compose = dir.path().join("compose.yaml");
        fs::write(
            &compose,
            "services:\n  web:\n    environment:\n      TOKEN: old\n      OTHER: keep\n",
        )
        .unwrap();
        let spec = TargetSpec::DockerInput {
            path: compose.clone(),
            key: "web:TOKEN".into(),
            input: DockerInputKind::ComposeEnvironment,
        };
        let dollar = SecretPayload::new(b"$PROBE".to_vec(), SecretType::Text);
        target.apply(&spec, &dollar).unwrap();
        let updated = fs::read_to_string(&compose).unwrap();
        assert!(updated.contains("$$PROBE"));
        assert!(updated.contains("OTHER: keep"));

        let env = dir.path().join("web.env");
        fs::write(&env, "TOKEN=old\nOTHER=keep\n").unwrap();
        fs::write(
            &compose,
            "services:\n  web:\n    env_file:\n      - web.env\n      - other.env\n",
        )
        .unwrap();
        let spec = TargetSpec::DockerInput {
            path: env.clone(),
            key: "TOKEN".into(),
            input: DockerInputKind::EnvFile {
                compose_path: compose.clone(),
                service: "web".into(),
            },
        };
        target.apply(&spec, &dollar).unwrap();
        let updated = fs::read_to_string(&env).unwrap();
        assert!(updated.contains("TOKEN='$PROBE'"));
        assert!(updated.contains("OTHER=keep"));
        let unrelated = dir.path().join("not-listed.env");
        fs::write(&unrelated, "TOKEN=old\n").unwrap();
        let wrong = TargetSpec::DockerInput {
            path: unrelated.clone(),
            key: "TOKEN".into(),
            input: DockerInputKind::EnvFile {
                compose_path: compose.clone(),
                service: "web".into(),
            },
        };
        assert_eq!(
            target.apply(&wrong, &dollar),
            Err(ErrorCategory::InvalidConfig)
        );
        assert_eq!(fs::read_to_string(&unrelated).unwrap(), "TOKEN=old\n");
    }

    #[test]
    fn scope_and_git_type_are_checked_before_payload() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let target = ProductionTarget::new(dir.path().to_path_buf()).unwrap();
        let outside = TargetSpec::WholeFile {
            path: elsewhere.path().join("outside"),
        };
        assert_eq!(
            target.validate(&outside, &SecretType::Text),
            Err(ErrorCategory::InvalidConfig)
        );
        let git = TargetSpec::GitCredential {
            protocol: "https".into(),
            host: "example.test".into(),
            path: None,
            username: "user".into(),
        };
        assert_eq!(
            target.validate(&git, &SecretType::Binary),
            Err(ErrorCategory::InvalidConfig)
        );
        assert_eq!(target.validate(&git, &SecretType::Text), Ok(()));
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(elsewhere.path(), dir.path().join("outside-link")).unwrap();
            let linked = TargetSpec::WholeFile {
                path: dir.path().join("outside-link/escaped"),
            };
            assert_eq!(
                target.validate(&linked, &SecretType::Text),
                Err(ErrorCategory::InvalidConfig)
            );
        }
    }
}
