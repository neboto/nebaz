//! The read-only guard (ticket 07, `PERMISSIONS.md`): nebaz's core promise
//! is that it never changes anything in Azure. This test makes that
//! mechanical over the source tree, so `cargo test` fails the moment a
//! change could send a write, fetch a secret value, or copy a mutating `az`
//! command for the user to run:
//!
//! 1. `Method::` appears only in `src/azure/arm.rs`, and there only as
//!    `Method::Get`; the pipeline (`Pipeline::new`) and the bearer policy
//!    are built nowhere else; no HTTP client crate is a direct dependency.
//! 2. No data-plane host string exists in non-test code under `src/` — Key
//!    Vault values, blob bodies and model calls live behind those hosts,
//!    never behind ARM. (Test fixtures may carry a `vaultUri`, as real ARM rows do.)
//! 3. Every `az …` command string in `src/` uses a read verb, or is on a
//!    written allowlist; the Key Vault value-returning commands and the
//!    AI account key listing are named forbidden outright.
//! 4. Every ARM action `PERMISSIONS.md` grants ends in `/read`.
//!
//! There is deliberately no API-path allowlist here: the paths are
//! documentation in `PERMISSIONS.md`, kept in sync by the PR template.

use std::fs;
use std::path::{Path, PathBuf};

const ARM_FILE: &str = "src/azure/arm.rs";

/// The hosts every Azure data plane lives on (public + sovereign clouds).
/// ARM (`management.*`) is the only endpoint nebaz talks to.
const DATA_PLANE_HOSTS: &[&str] = &[
    "vault.azure.net",
    "vault.usgovcloudapi.net",
    "vault.azure.cn",
    "blob.core.windows.net",
    "dfs.core.windows.net",
    "file.core.windows.net",
    "queue.core.windows.net",
    "table.core.windows.net",
    "blob.core.usgovcloudapi.net",
    "blob.core.chinacloudapi.cn",
    // Foundry / AI Services / Azure OpenAI: model calls and agent APIs.
    "cognitiveservices.azure.com",
    "openai.azure.com",
    "services.ai.azure.com",
    // App Service: the apps themselves and their Kudu (SCM) sites.
    "azurewebsites.net",
    // Azure SQL: the servers' own endpoints (a TDS connection, not ARM).
    "database.windows.net",
    // Container Registry: repositories, tags and manifests (the registry's
    // login server).
    "azurecr.io",
    // Cosmos DB: the accounts' document endpoints.
    "documents.azure.com",
];

/// Crates that could open an HTTP connection behind the pipeline's back.
const HTTP_CLIENT_CRATES: &[&str] = &["reqwest", "hyper", "ureq", "curl", "isahc", "attohttpc", "minreq"];

/// `az <group…> <verb>` verbs that read. `get-access-token` is what
/// azure_identity runs; nebaz itself runs `az account list`.
const AZ_READ_VERBS: &[&str] = &["show", "list", "get-access-token"];

/// Command chains that read nothing but must never appear: they return
/// secret material to the terminal. `cognitiveservices account keys list`
/// carries a read verb, so it has to be named here.
const AZ_FORBIDDEN: &[&str] = &[
    "keyvault secret show",
    "keyvault key show",
    "keyvault certificate",
    "cognitiveservices account keys",
    // App settings, connection strings and function keys: each lists
    // secrets under a read verb.
    "webapp config appsettings",
    "webapp config connection-string",
    "functionapp config appsettings",
    "functionapp keys",
    "functionapp function keys",
    "logicapp config appsettings",
    // Cosmos DB account keys, read-only keys and connection strings.
    "cosmosdb keys",
];

/// `az` mentions that are not commands. Each needs a reason.
const AZ_ALLOW: &[(&str, &str)] = &[
    ("login", "advice text in the auth error; the user runs it, nebaz never does"),
    ("not", "\"az not found on PATH\" — an error message"),
    ("command", "\"Copied az command\" — the clipboard toast"),
    ("cli", "prose in a doc comment or message naming the Azure CLI"),
    ("upgrade", "advice text in the too-old-CLI error; the user runs it"),
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rust_sources() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(&root().join("src"), &mut out);
    out.sort();
    out
}

/// Drop `//` comments so prose never trips the scan; keep line count.
fn without_line_comments(text: &str) -> String {
    text.lines()
        .map(|l| match l.find("//") {
            Some(i) if !l[..i].contains('"') => &l[..i],
            _ => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The part of a file before its `#[cfg(test)]` module.
fn non_test_part(text: &str) -> &str {
    text.split("#[cfg(test)]").next().unwrap_or(text)
}

fn line_of(text: &str, offset: usize) -> usize {
    text[..offset].matches('\n').count() + 1
}

fn rel(path: &Path) -> String {
    path.strip_prefix(root()).unwrap().display().to_string()
}

/// Every `"…"` string literal in the text with its byte offset.
fn string_literals(text: &str) -> Vec<(usize, String)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            let start = i;
            i += 1;
            let mut s = String::new();
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    s.push(bytes[i + 1] as char);
                    i += 2;
                } else {
                    s.push(bytes[i] as char);
                    i += 1;
                }
            }
            out.push((start, s));
        }
        i += 1;
    }
    out
}

#[test]
fn only_the_arm_client_builds_requests_and_only_gets() {
    let mut problems = Vec::new();
    for path in rust_sources() {
        let text = without_line_comments(&fs::read_to_string(&path).unwrap());
        let is_arm = rel(&path) == ARM_FILE;
        let scan = if is_arm { non_test_part(&text) } else { text.as_str() };
        for needle in ["Method::", "Pipeline::new", "BearerTokenAuthorizationPolicy"] {
            for (offset, _) in scan.match_indices(needle) {
                if !is_arm {
                    problems.push(format!("{}:{}: `{}` outside {}", rel(&path), line_of(scan, offset), needle, ARM_FILE));
                } else if needle == "Method::" && !scan[offset..].starts_with("Method::Get") {
                    problems.push(format!("{}:{}: a method other than Method::Get", rel(&path), line_of(scan, offset)));
                }
            }
        }
    }
    let arm = fs::read_to_string(root().join(ARM_FILE)).unwrap();
    assert!(arm.contains("Method::Get"), "{} no longer builds GET requests?", ARM_FILE);
    assert!(arm.contains("ReadOnlyPolicy"), "{} lost the ReadOnlyPolicy", ARM_FILE);

    let manifest = fs::read_to_string(root().join("Cargo.toml")).unwrap();
    let deps = manifest.split("[dependencies]").nth(1).unwrap_or("");
    for line in deps.lines().take_while(|l| !l.starts_with("[profile")) {
        let name = line.split(['=', ' ']).next().unwrap_or("").trim();
        if HTTP_CLIENT_CRATES.contains(&name) {
            problems.push(format!("Cargo.toml: `{}` is a direct dependency; all HTTP goes through the azure_core pipeline", name));
        }
    }
    assert!(problems.is_empty(), "read-only guard (HTTP layer):\n  {}", problems.join("\n  "));
}

#[test]
fn no_data_plane_host_is_named_anywhere() {
    let mut problems = Vec::new();
    for path in rust_sources() {
        let file = fs::read_to_string(&path).unwrap();
        let text = non_test_part(&file);
        for host in DATA_PLANE_HOSTS {
            for (offset, _) in text.match_indices(host) {
                problems.push(format!("{}:{}: data-plane host `{}`", rel(&path), line_of(text, offset), host));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "read-only guard (data plane): nebaz talks to ARM only, never to a vault or storage endpoint\n  {}",
        problems.join("\n  ")
    );
}

#[test]
fn every_az_command_reads() {
    let mut problems = Vec::new();
    let mut seen = 0usize;
    for path in rust_sources() {
        let text = without_line_comments(&fs::read_to_string(&path).unwrap());
        for (offset, literal) in string_literals(&text) {
            let mut rest = literal.as_str();
            while let Some(i) = rest.find("az ") {
                let at_word_start = i == 0 || !rest.as_bytes()[i - 1].is_ascii_alphanumeric();
                rest = &rest[i + 3..];
                if !at_word_start {
                    continue;
                }
                seen += 1;
                // `az login`, 'az login', "az upgrade," — strip the quoting
                // and punctuation around each word before judging it.
                let words: Vec<String> = rest
                    .split_whitespace()
                    .map(|w| w.trim_matches(|c: char| !c.is_ascii_alphanumeric()).to_ascii_lowercase())
                    .take_while(|w| !w.is_empty() && w.chars().all(|c| c.is_ascii_lowercase() || c == '-'))
                    // Four command groups plus the verb: the deepest chain in
                    // use is `network private-dns link vnet list`.
                    .take(5)
                    .collect();
                let words: Vec<&str> = words.iter().map(String::as_str).collect();
                let chain = words.join(" ");
                let where_ = format!("{}:{}: `az {}`", rel(&path), line_of(&text, offset), chain);
                if AZ_FORBIDDEN.iter().any(|f| chain.starts_with(f)) {
                    problems.push(format!("{} returns secret material", where_));
                } else if words.iter().any(|w| AZ_READ_VERBS.contains(w)) {
                    // a read command
                } else if words.first().is_some_and(|w| AZ_ALLOW.iter().any(|(a, _)| a == w)) {
                    // allowlisted prose
                } else {
                    problems.push(format!("{} has no read verb (add a reason to AZ_ALLOW if it is not a command)", where_));
                }
            }
        }
    }
    assert!(seen >= 20, "only {} `az` mentions found — did the scan break?", seen);
    assert!(problems.is_empty(), "read-only guard (az commands):\n  {}", problems.join("\n  "));
}

#[test]
fn permissions_doc_grants_only_read_actions() {
    let doc = fs::read_to_string(root().join("PERMISSIONS.md")).expect("PERMISSIONS.md at the repo root");
    let mut actions = Vec::new();
    for (_, literal) in string_literals(&doc.replace('`', "\"")) {
        if literal.starts_with("Microsoft.") && literal.contains('/') && !literal.contains(' ') {
            actions.push(literal);
        }
    }
    actions.sort();
    actions.dedup();
    assert!(actions.len() >= 10, "PERMISSIONS.md lists only {} ARM actions — did the format change?", actions.len());
    let bad: Vec<_> = actions.iter().filter(|a| !a.ends_with("/read")).collect();
    assert!(bad.is_empty(), "read-only guard (PERMISSIONS.md): non-read actions {:?}", bad);
    assert!(doc.contains("`Reader`"), "PERMISSIONS.md must name the built-in Reader role");
}
