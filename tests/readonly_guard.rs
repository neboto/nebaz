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
//!    Microsoft Graph (ADR 0004) is allowed in `src/azure/graph.rs` only;
//!    `getByIds` (a `POST`) and the secret-returning calls are forbidden
//!    everywhere, and the Graph module never names a certificate's `key`.
//! 3. Every `az …` command string in `src/` uses a read verb, or is on a
//!    written allowlist; the Key Vault value-returning commands and the
//!    AI account key listing are named forbidden outright. The one
//!    exception is the `C` catalogue (ADR 0005): `src/azure/cli_actions.rs`
//!    may also hold the Connect and Change verbs listed here, for commands
//!    the user copies and runs; it spawns nothing, and only the picker
//!    (which hands a command to the clipboard) uses it. A destructive verb
//!    or a secret-revealing command or flag is refused there too.
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
    // Container Apps: the apps themselves (the environment's default
    // domain).
    "azurecontainerapps.io",
    // Monitor: log queries and App Insights data.
    "api.loganalytics.io",
    "api.applicationinsights.io",
    // Power Platform (#77): environments and their policy links live in
    // the admin APIs (BAP, public and US government; the Power Platform
    // API), Dataverse data in the environment's own host. Enterprise
    // policies are ARM; the rest is not.
    "api.bap.microsoft.com",
    "api.bap.microsoft.us",
    "api.powerplatform.com",
    "crm.dynamics.com",
    // Azure AD Graph, retired: never, not even in the Graph module.
    "graph.windows.net",
];

/// The one file allowed to name a Microsoft Graph host (ADR 0004): every
/// Graph path and query lives there, sent through the Graph flavour of the
/// ARM client's one GET constructor.
const GRAPH_FILE: &str = "src/azure/graph.rs";

/// Microsoft Graph, public and sovereign clouds. Allowed in [`GRAPH_FILE`]
/// only; anywhere else they are a data-plane host like the rest.
const GRAPH_HOSTS: &[&str] = &[
    "graph.microsoft.com",
    "graph.microsoft.us",
    "dod-graph.microsoft.us",
    "microsoftgraph.chinacloudapi.cn",
];

/// Graph calls that write or return secret material, forbidden as a
/// literal anywhere in `src/`: `getByIds` is a `POST`; `addPassword` and
/// `addKey` are the only calls that return a secret value.
const GRAPH_FORBIDDEN: &[&str] = &["getByIds", "addPassword", "addKey", "secretText"];

/// Fields the Graph module must never name in a literal: a certificate's
/// `key` is only returned when selected.
const GRAPH_FORBIDDEN_FIELDS: &[&str] = &["key"];

/// Query options the Graph module must never use. Graph returns a
/// certificate's `key` whenever `keyCredentials` is `$select`ed, so nebaz
/// selects nothing: the default projection leaves `key` null.
const GRAPH_FORBIDDEN_OPTIONS: &[&str] = &["$select", "select="];

/// Crates that could open an HTTP connection behind the pipeline's back.
const HTTP_CLIENT_CRATES: &[&str] = &["reqwest", "hyper", "ureq", "curl", "isahc", "attohttpc", "minreq"];

/// `az <group…> <verb>` verbs that read, matched as whole words.
/// `get-access-token` is what azure_identity runs; nebaz itself runs
/// `az account list`. The rest are reads the `C` catalogue offers.
const AZ_READ_VERBS: &[&str] = &[
    "show",
    "list",
    "get-access-token",
    "get-instance-view",
    "get-boot-log",
    "get-upgrades",
    "list-effective-nsg",
    "show-effective-route-table",
    "list-instances",
];

/// The `C` command catalogue (ADR 0005, #47): the one file that may hold
/// an `az` command whose verb is on [`AZ_CONNECT_VERBS`] or
/// [`AZ_CHANGE_VERBS`]. The user copies those and runs them; nebaz never
/// does.
const CLI_CATALOGUE_FILE: &str = "src/azure/cli_actions.rs";

/// The only files that may name the catalogue: the catalogue, the picker
/// glue on `App` (which hands the chosen command to the clipboard) and the
/// picker widget (which draws it).
const CLI_CATALOGUE_USERS: &[&str] = &[CLI_CATALOGUE_FILE, "src/app/command_picker.rs", "src/ui/widgets/command_picker.rs"];

/// Verbs that open a session or configure a local tool and change nothing
/// in Azure (`ssh vm`, `aks get-credentials`, `acr login`, `webapp log
/// tail`). Catalogue only.
const AZ_CONNECT_VERBS: &[&str] = &["ssh", "rdp", "connect", "get-credentials", "exec", "login", "tail"];

/// Reversible operational changes. Catalogue only, shown under a warning.
const AZ_CHANGE_VERBS: &[&str] = &["start", "stop", "restart", "deallocate", "scale"];

/// Verbs refused in every `az` literal, the catalogue included: they
/// destroy, overwrite, run code on the target, or mint and print a
/// credential (`ad sp credential reset`).
const AZ_DESTRUCTIVE: &[&str] = &[
    "delete",
    "purge",
    "remove",
    "reset",
    "regenerate",
    "rotate",
    "renew",
    "revoke",
    "invoke",
    "run-command",
    "reimage",
    "redeploy",
    "set",
    "create",
    "update",
    "import",
    "restore",
];

/// Flags refused in every `az` literal: each makes a command print a
/// credential (`aks get-credentials --admin`, `acr login --expose-token`,
/// `containerapp secret list --show-values`).
const AZ_FORBIDDEN_FLAGS: &[&str] = &["--admin", "--expose-token", "--show-values", "--show-secrets"];

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
    // Container Apps secrets: `secret list --show-values` and `secret
    // show` print values (the ARM side is the `listSecrets` POST).
    "containerapp secret",
    "containerapp job secret",
    // Registry admin password, storage account keys, SAS tokens and
    // connection strings, publishing profiles (deployment passwords).
    "acr credential",
    "storage account keys",
    "storage account show-connection-string",
    "storage account generate-sas",
    "sql db show-connection-string",
    "webapp deployment list-publishing",
    "functionapp deployment list-publishing",
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

/// The host problems in one file's non-test text: every data-plane host,
/// and a Graph host outside [`GRAPH_FILE`].
fn host_problems(rel_path: &str, file: &str) -> Vec<String> {
    let text = non_test_part(file);
    let mut problems = Vec::new();
    for host in DATA_PLANE_HOSTS {
        for (offset, _) in text.match_indices(host) {
            problems.push(format!("{}:{}: data-plane host `{}`", rel_path, line_of(text, offset), host));
        }
    }
    if rel_path != GRAPH_FILE {
        for host in GRAPH_HOSTS {
            for (offset, _) in text.match_indices(host) {
                problems.push(format!(
                    "{}:{}: Graph host `{}` outside {}",
                    rel_path,
                    line_of(text, offset),
                    host,
                    GRAPH_FILE
                ));
            }
        }
    }
    problems
}

/// The Graph problems in one file's non-test, comment-free text: a
/// forbidden call anywhere, and a forbidden field in a Graph-module
/// literal (a `$select` list, a path, a query value).
fn graph_problems(rel_path: &str, file: &str) -> Vec<String> {
    let stripped = without_line_comments(file);
    let text = non_test_part(&stripped);
    let mut problems = Vec::new();
    for (offset, literal) in string_literals(text) {
        for call in GRAPH_FORBIDDEN {
            if literal.contains(call) {
                problems.push(format!("{}:{}: Graph `{}` (a write or a secret)", rel_path, line_of(text, offset), call));
            }
        }
        if rel_path == GRAPH_FILE {
            if let Some(option) = GRAPH_FORBIDDEN_OPTIONS.iter().find(|o| literal.contains(*o)) {
                problems.push(format!(
                    "{}:{}: Graph `{}` in {:?} (selecting keyCredentials returns the key)",
                    rel_path,
                    line_of(text, offset),
                    option,
                    literal
                ));
            }
            let tokens = literal.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '@'));
            for token in tokens {
                if GRAPH_FORBIDDEN_FIELDS.contains(&token) {
                    problems.push(format!(
                        "{}:{}: Graph field `{}` in {:?} (a certificate's key is never selected)",
                        rel_path,
                        line_of(text, offset),
                        token,
                        literal
                    ));
                }
            }
        }
    }
    problems
}

#[test]
fn no_data_plane_host_is_named_anywhere() {
    let mut problems = Vec::new();
    for path in rust_sources() {
        let file = fs::read_to_string(&path).unwrap();
        problems.extend(host_problems(&rel(&path), &file));
    }
    assert!(
        problems.is_empty(),
        "read-only guard (data plane): nebaz talks to ARM, and to Graph from {} only, never to a vault or storage endpoint\n  {}",
        GRAPH_FILE,
        problems.join("\n  ")
    );
    let graph = fs::read_to_string(root().join(GRAPH_FILE)).expect("the Graph module");
    assert!(
        GRAPH_HOSTS.iter().any(|h| non_test_part(&graph).contains(h)),
        "{} names no Graph host: did the module move? Update GRAPH_FILE",
        GRAPH_FILE
    );
}

#[test]
fn graph_is_get_only_and_never_selects_a_key() {
    let mut problems = Vec::new();
    for path in rust_sources() {
        let file = fs::read_to_string(&path).unwrap();
        problems.extend(graph_problems(&rel(&path), &file));
    }
    assert!(problems.is_empty(), "read-only guard (Graph):\n  {}", problems.join("\n  "));
}

/// The guard's own rules, on synthetic files: a regression here means a
/// real violation could pass unnoticed.
#[test]
fn the_graph_rules_catch_what_they_should() {
    let graph_host = "let g = \"https://graph.microsoft.com\";\n";
    assert!(host_problems(GRAPH_FILE, graph_host).is_empty(), "the Graph module may name its host");
    let elsewhere = host_problems("src/azure/services/access.rs", graph_host);
    assert_eq!(elsewhere.len(), 1, "{:?}", elsewhere);
    assert!(elsewhere[0].contains("outside src/azure/graph.rs"), "{:?}", elsewhere);
    assert_eq!(host_problems(GRAPH_FILE, "let v = \"vault.azure.net\";\n").len(), 1, "data-plane hosts stay forbidden in the Graph module");
    assert_eq!(host_problems(GRAPH_FILE, "let a = \"https://graph.windows.net\";\n").len(), 1, "AAD Graph is retired");
    assert!(
        host_problems("src/x.rs", "fn f() {}\n#[cfg(test)]\nmod t { const H: &str = \"graph.microsoft.com\"; }\n").is_empty(),
        "test fixtures are exempt, as for every host"
    );

    let post = graph_problems("src/azure/client.rs", "let p = \"/v1.0/directoryObjects/getByIds\";\n");
    assert_eq!(post.len(), 1, "{:?}", post);
    assert_eq!(graph_problems(GRAPH_FILE, "let s = \"/v1.0/applications/{}/addPassword\";\n").len(), 1);
    let select_key = graph_problems(GRAPH_FILE, "let q = (\"$select\", \"id,displayName,key\");\n");
    assert_eq!(select_key.len(), 2, "the option and the field: {:?}", select_key);
    assert_eq!(graph_problems(GRAPH_FILE, "let q = \"$select=key\";\n").len(), 2);
    assert_eq!(
        graph_problems(GRAPH_FILE, "let q = (\"$select\", \"id,keyCredentials\");\n").len(),
        1,
        "selecting keyCredentials returns the key: no $select at all"
    );
    assert!(
        graph_problems(GRAPH_FILE, "let p = \"/keyCredentials\";\n").is_empty(),
        "reading the default projection's keyCredentials (key null) is fine"
    );
    assert_eq!(graph_problems("src/azure/services/x.rs", "let q = \"$select=id\";\n").len(), 0, "ARM selects fields freely");
    assert!(graph_problems(GRAPH_FILE, "// a doc comment may say $select=key\n").is_empty());
}

/// The `az` problems in one file's comment-free text, and how many `az`
/// mentions it holds. Words are judged whole; the chain is the words
/// before the first flag, at most four groups plus the verb (the deepest
/// in use is `network private-dns link vnet list`).
fn az_problems(rel_path: &str, text: &str) -> (usize, Vec<String>) {
    let in_catalogue = rel_path == CLI_CATALOGUE_FILE;
    let mut problems = Vec::new();
    let mut seen = 0usize;
    for (offset, literal) in string_literals(text) {
        if literal == "az" && rel_path != "src/azure/auth.rs" && !in_catalogue {
            problems.push(format!(
                "{}:{}: a bare \"az\" (only auth.rs runs az; only the catalogue builds commands)",
                rel_path,
                line_of(text, offset)
            ));
        }
        let mut rest = literal.as_str();
        while let Some(i) = rest.find("az ") {
            let at_word_start = i == 0 || !rest.as_bytes()[i - 1].is_ascii_alphanumeric();
            rest = &rest[i + 3..];
            if !at_word_start {
                continue;
            }
            seen += 1;
            // `az login`, 'az login', "az upgrade," — strip the quoting and
            // punctuation around each word before judging it.
            let words: Vec<String> = rest
                .split_whitespace()
                .take_while(|w| !w.starts_with('-'))
                .map(|w| w.trim_matches(|c: char| !c.is_ascii_alphanumeric()).to_ascii_lowercase())
                .take_while(|w| !w.is_empty() && w.chars().all(|c| c.is_ascii_lowercase() || c == '-'))
                .take(5)
                .collect();
            let words: Vec<&str> = words.iter().map(String::as_str).collect();
            let chain = words.join(" ");
            let flags: Vec<&str> = rest.split_whitespace().filter(|w| w.starts_with("--")).collect();
            let where_ = format!("{}:{}: `az {}`", rel_path, line_of(text, offset), chain);
            if AZ_FORBIDDEN.iter().any(|f| chain.starts_with(f)) {
                problems.push(format!("{} returns secret material", where_));
            } else if let Some(f) = flags.iter().find(|f| AZ_FORBIDDEN_FLAGS.contains(f)) {
                problems.push(format!("{} with `{}` prints a credential", where_, f));
            } else if let Some(v) = words.iter().find(|w| AZ_DESTRUCTIVE.contains(w)) {
                problems.push(format!("{} uses `{}`: never offered, not even to copy", where_, v));
            } else if words.iter().any(|w| AZ_READ_VERBS.contains(w)) {
                // a read command
            } else if in_catalogue && words.iter().any(|w| AZ_CONNECT_VERBS.contains(w) || AZ_CHANGE_VERBS.contains(w)) {
                // a copied Connect / Change command (ADR 0005)
            } else if words.first().is_some_and(|w| AZ_ALLOW.iter().any(|(a, _)| a == w)) {
                // allowlisted prose
            } else if in_catalogue {
                problems.push(format!("{} has no read, Connect or Change verb", where_));
            } else {
                problems.push(format!("{} has no read verb (add a reason to AZ_ALLOW if it is not a command)", where_));
            }
        }
    }
    (seen, problems)
}

#[test]
fn every_az_command_reads() {
    let mut problems = Vec::new();
    let mut seen = 0usize;
    for path in rust_sources() {
        let text = without_line_comments(&fs::read_to_string(&path).unwrap());
        let (n, p) = az_problems(&rel(&path), &text);
        seen += n;
        problems.extend(p);
    }
    assert!(seen >= 20, "only {} `az` mentions found — did the scan break?", seen);
    assert!(problems.is_empty(), "read-only guard (az commands):\n  {}", problems.join("\n  "));
}

/// The catalogue only produces text: it spawns nothing, nothing that
/// spawns names it, and its only users are the picker's glue and widget.
#[test]
fn the_cli_catalogue_is_only_copied() {
    let catalogue = without_line_comments(&fs::read_to_string(root().join(CLI_CATALOGUE_FILE)).expect("the catalogue"));
    for needle in ["process::", "Command::new", "spawn", "std::process"] {
        assert!(!catalogue.contains(needle), "{} must never run anything: found `{}`", CLI_CATALOGUE_FILE, needle);
    }
    let mut problems = Vec::new();
    for path in rust_sources() {
        let r = rel(&path);
        // Tests may call it (they assert on what it builds); the module
        // tree declares it.
        if r.starts_with("src/harness_tests/") {
            continue;
        }
        let file = without_line_comments(&fs::read_to_string(&path).unwrap());
        let text = non_test_part(&file).replace("pub mod cli_actions;", "");
        if text.contains("cli_actions") && !CLI_CATALOGUE_USERS.contains(&r.as_str()) {
            problems.push(format!("{}: names the C catalogue (only {:?} may)", r, CLI_CATALOGUE_USERS));
        }
        if CLI_CATALOGUE_USERS.contains(&r.as_str()) && (text.contains("process::") || text.contains("Command::new")) {
            problems.push(format!("{}: a catalogue user spawns a process", r));
        }
    }
    assert!(problems.is_empty(), "read-only guard (C catalogue):\n  {}", problems.join("\n  "));
}

/// The `az` rules on synthetic files: a regression here means a real
/// violation could pass unnoticed.
#[test]
fn the_az_rules_catch_what_they_should() {
    let count = |path: &str, line: &str| az_problems(path, line).1.len();
    let elsewhere = "src/app.rs";
    // Reads pass everywhere.
    assert_eq!(count(elsewhere, "let c = \"az vm show --ids {}\";"), 0);
    assert_eq!(count(elsewhere, "let c = \"az vm get-instance-view --ids {}\";"), 0);
    // Connect and Change verbs: the catalogue only.
    for cmd in ["az vm start --ids {}", "az aks get-credentials -n {}", "az ssh vm -n {}", "az aks nodepool scale --node-count 3"] {
        let line = format!("let c = \"{}\";", cmd);
        assert_eq!(count(elsewhere, &line), 1, "{cmd} outside the catalogue");
        assert_eq!(count(CLI_CATALOGUE_FILE, &line), 0, "{cmd} in the catalogue");
    }
    // Refused in the catalogue too.
    for cmd in [
        "az vm delete --ids {}",
        "az ad sp credential reset --id {}",
        "az keyvault secret show --id {}",
        "az storage account keys list -n {}",
        "az acr credential show -n {}",
        "az aks get-credentials -n {} --admin",
        "az acr login -n {} --expose-token",
        "az vm run-command invoke --ids {}",
        "az webapp update --ids {}",
    ] {
        let line = format!("let c = \"{}\";", cmd);
        assert_eq!(count(CLI_CATALOGUE_FILE, &line), 1, "{cmd} must be refused in the catalogue");
    }
    // A verb hidden behind a placeholder reads as no verb at all.
    assert_eq!(count(CLI_CATALOGUE_FILE, "let c = format!(\"az vm {} --ids {}\", v, id);"), 1);
    // A bare "az" outside auth.rs and the catalogue.
    assert_eq!(count(elsewhere, "let a = \"az\";"), 1);
    assert_eq!(count("src/azure/auth.rs", "let a = \"az\";"), 0);
    // Prose stays allowed.
    assert_eq!(count(elsewhere, "let m = \"run `az login`\";"), 0);
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

/// ARM reads that are POSTs (a NIC's effective NSG rules and routes):
/// `ReadOnlyPolicy` would refuse them at runtime anyway; the guard keeps
/// them out of `src/`. The network lens (#50) computes NSG access
/// client-side from GETs instead.
const POST_ONLY_READS: &[&str] = &["effectivenetworksecuritygroups", "effectiveroutetable"];

#[test]
fn no_post_only_read_is_requested() {
    let mut problems = Vec::new();
    for path in rust_sources() {
        let file = without_line_comments(&fs::read_to_string(&path).unwrap());
        let text = non_test_part(&file);
        for (offset, literal) in string_literals(text) {
            let lower = literal.to_lowercase();
            for action in POST_ONLY_READS {
                if lower.contains(action) {
                    problems.push(format!("{}:{}: `{}` is a POST action", rel(&path), line_of(text, offset), action));
                }
            }
        }
    }
    assert!(problems.is_empty(), "read-only guard (POST-only reads):\n  {}", problems.join("\n  "));
}
