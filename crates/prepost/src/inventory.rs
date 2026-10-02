//! Device inventory loading.
//!
//! `inventory/devices.yml` groups devices by platform; each platform
//! carries the netmiko `device_type` and the command list captured for
//! it. An optional top-level `pairs:` list names redundant pairs
//! explicitly (otherwise they are inferred from hostnames).
//!
//! The file is the one the Python tool reads (`inventory/devices.yml`,
//! gitignored there because it names real hosts). Copy
//! `fixtures/devices.example.yml` and edit: adding a device or a
//! command never means touching code.

use std::io::{BufRead, Write};
use std::path::Path;

use serde_yaml::Value;

/// The bundled example, relative to the crate source tree.
pub const EXAMPLE_INVENTORY: &str = "fixtures/devices.example.yml";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Platform {
    pub name: String,
    pub device_type: String,
    pub hosts: Vec<String>,
    pub commands: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Inventory {
    pub platforms: Vec<Platform>,
    pub pairs: Vec<(String, String)>,
}

/// One device to reach, with credentials.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceSpec {
    pub device_type: String,
    pub host: String,
    pub username: String,
    pub password: String,
}

/// One collection job: a device and the commands to run on it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Job {
    pub device: DeviceSpec,
    pub commands: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct InventoryError(pub String);

/// Parse and validate the inventory.
pub fn load_inventory(path: &Path) -> Result<Inventory, InventoryError> {
    if !path.exists() {
        return Err(InventoryError(format!(
            "Inventory not found: {}\nCopy {EXAMPLE_INVENTORY} (bundled with the prepost source) to {} and fill in your devices.",
            path.display(),
            crate::layout::default_inventory().display()
        )));
    }

    let data = read_yaml(path)?;
    let shown = path.display();

    let Some(platforms) = data.get("platforms").and_then(Value::as_sequence) else {
        return Err(InventoryError(format!(
            "{shown}: expected a top-level 'platforms' list."
        )));
    };

    let pairs = pairs_from(&data, path)?;

    let mut parsed = Vec::with_capacity(platforms.len());

    for (index, platform) in platforms.iter().enumerate() {
        let label = match platform.get("name") {
            Some(name) => scalar_text(name),
            None => format!("platforms[{index}]"),
        };

        for key in ["name", "device_type", "hosts", "commands"] {
            if platform.get(key).is_none_or(is_falsy) {
                return Err(InventoryError(format!(
                    "{shown}: platform '{label}' is missing '{key}'."
                )));
            }
        }

        let (Some(hosts), Some(commands)) = (
            platform.get("hosts").and_then(Value::as_sequence),
            platform.get("commands").and_then(Value::as_sequence),
        ) else {
            return Err(InventoryError(format!(
                "{shown}: platform '{label}': 'hosts' and 'commands' must be lists."
            )));
        };

        parsed.push(Platform {
            name: label.clone(),
            device_type: scalar_text(platform.get("device_type").unwrap_or(&Value::Null)),
            hosts: scalar_list(hosts, path, &label, "hosts")?,
            commands: scalar_list(commands, path, &label, "commands")?,
        });
    }

    Ok(Inventory {
        platforms: parsed,
        pairs,
    })
}

/// The `pairs:` list of an inventory, or empty when the file is absent.
///
/// The HTML report can be built on a machine that has no inventory
/// (only the captured evidence), so a missing file is not an error here.
pub fn load_pairs(path: &Path) -> Result<Vec<(String, String)>, InventoryError> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let data = read_yaml(path)?;

    if !data.is_mapping() {
        return Err(InventoryError(format!("{}: expected a YAML mapping.", path.display())));
    }

    pairs_from(&data, path)
}

/// Validate and return the optional `pairs:` list of an inventory.
fn pairs_from(data: &Value, path: &Path) -> Result<Vec<(String, String)>, InventoryError> {
    let pairs = match data.get("pairs") {
        Some(value) if !is_falsy(value) => value,
        _ => return Ok(Vec::new()),
    };

    let Some(pairs) = pairs.as_sequence() else {
        return Err(InventoryError(format!(
            "{}: 'pairs' must be a list of two-hostname lists.",
            path.display()
        )));
    };

    pairs
        .iter()
        .map(|pair| {
            let hosts = pair.as_sequence().filter(|hosts| hosts.len() == 2);
            let names: Option<Vec<&str>> = hosts.map(|hosts| {
                hosts
                    .iter()
                    .filter_map(|host| host.as_str().filter(|host| !host.is_empty()))
                    .collect()
            });

            match names.as_deref() {
                Some([first, second]) => Ok((first.to_string(), second.to_string())),
                _ => Err(InventoryError(format!(
                    "{}: each entry in 'pairs' must be a list of exactly two hostnames, got {}.",
                    path.display(),
                    repr(pair)
                ))),
            }
        })
        .collect()
}

/// Flatten platforms into one job per device.
pub fn build_jobs(inventory: &Inventory, username: &str, password: &str) -> Vec<Job> {
    inventory
        .platforms
        .iter()
        .flat_map(|platform| {
            platform.hosts.iter().map(move |host| Job {
                device: DeviceSpec {
                    device_type: platform.device_type.clone(),
                    host: host.clone(),
                    username: username.to_string(),
                    password: password.to_string(),
                },
                commands: platform.commands.clone(),
            })
        })
        .collect()
}

/// Ask for SSH credentials; the password is never echoed or stored.
pub fn prompt_credentials(username: Option<&str>) -> anyhow::Result<(String, String)> {
    let username = match username {
        Some(name) if !name.is_empty() => name.to_string(),
        _ => {
            print!("Username: ");
            std::io::stdout().flush()?;
            let mut line = String::new();
            std::io::stdin().lock().read_line(&mut line)?;
            line.trim_end_matches(['\r', '\n']).to_string()
        }
    };

    let password = rpassword::prompt_password("Password: ")?;

    Ok((username, password))
}

fn read_yaml(path: &Path) -> Result<Value, InventoryError> {
    let text = std::fs::read_to_string(path).map_err(|error| InventoryError(format!("{}: {error}", path.display())))?;

    serde_yaml::from_str(&text).map_err(|error| InventoryError(format!("{}: {error}", path.display())))
}

/// Python truthiness of a YAML value: `None`, `False`, `0`, `""`, `[]`
/// and `{}` all count as "not given".
fn is_falsy(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Bool(flag) => !flag,
        Value::Number(number) => number.as_f64() == Some(0.0),
        Value::String(text) => text.is_empty(),
        Value::Sequence(items) => items.is_empty(),
        Value::Mapping(map) => map.is_empty(),
        Value::Tagged(tagged) => is_falsy(&tagged.value),
    }
}

/// A scalar as the string Python's `str()` would show.
fn scalar_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Null => "None".to_string(),
        Value::Number(number) => number.to_string(),
        Value::Tagged(tagged) => scalar_text(&tagged.value),
        other => repr(other),
    }
}

fn scalar_list(items: &[Value], path: &Path, label: &str, key: &str) -> Result<Vec<String>, InventoryError> {
    items
        .iter()
        .map(|item| match item {
            Value::Sequence(_) | Value::Mapping(_) => Err(InventoryError(format!(
                "{}: platform '{label}': every entry in '{key}' must be a plain value, got {}.",
                path.display(),
                repr(item)
            ))),
            scalar => Ok(scalar_text(scalar)),
        })
        .collect()
}

/// Python `repr()` of the value, for error messages.
fn repr(value: &Value) -> String {
    match value {
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Number(number) => number.to_string(),
        Value::String(text) => {
            if text.contains('\'') && !text.contains('"') {
                format!("\"{text}\"")
            } else {
                format!("'{}'", text.replace('\\', "\\\\").replace('\'', "\\'"))
            }
        }
        Value::Sequence(items) => format!("[{}]", items.iter().map(repr).collect::<Vec<_>>().join(", ")),
        Value::Mapping(map) => format!(
            "{{{}}}",
            map.iter()
                .map(|(key, value)| format!("{}: {}", repr(key), repr(value)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::Tagged(tagged) => repr(&tagged.value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_repr_shapes() {
        let value: Value = serde_yaml::from_str("[ONLY-ONE, 2, true, null, {a: b}]").unwrap();
        assert_eq!(repr(&value), "['ONLY-ONE', 2, True, None, {'a': 'b'}]");
        assert_eq!(repr(&Value::String("it's".into())), "\"it's\"");
    }

    #[test]
    fn falsy_values() {
        for text in ["null", "false", "0", "''", "[]", "{}"] {
            assert!(is_falsy(&serde_yaml::from_str(text).unwrap()), "{text}");
        }
        for text in ["true", "1", "x", "[a]", "{a: 1}"] {
            assert!(!is_falsy(&serde_yaml::from_str(text).unwrap()), "{text}");
        }
    }
}
