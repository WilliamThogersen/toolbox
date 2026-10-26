use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

use super::{Listing, Request, git, list};
use crate::command::manifest::is_valid_name;
use crate::command::registry::Problem;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Markets {
    #[serde(default)]
    pub markets: BTreeMap<String, Market>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Market {
    pub url: String,
    #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
    pub git_ref: Option<String>,
}

impl Markets {
    fn with(&self, name: &str, market: Market) -> Self {
        let mut markets = self.markets.clone();
        markets.insert(name.to_string(), market);
        Self { markets }
    }

    fn without(&self, name: &str) -> Self {
        let markets = self.markets.iter().filter(|(n, _)| *n != name).map(|(n, m)| (n.clone(), m.clone()));
        Self {
            markets: markets.collect(),
        }
    }
}

pub fn load(path: &Path) -> Result<Markets> {
    match fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str(&raw).with_context(|| format!("invalid {}", path.display())),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(Markets::default()),
        Err(err) => Err(err).with_context(|| format!("could not read {}", path.display())),
    }
}

fn save(path: &Path, markets: &Markets) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("could not create {}", parent.display()))?;
    }
    fs::write(path, serde_json::to_string_pretty(markets)? + "\n")
        .with_context(|| format!("could not write {}", path.display()))
}

#[derive(Debug, Serialize)]
pub struct Entry {
    pub name: String,
    pub url: String,
    #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
    pub git_ref: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Added {
    pub name: String,
    pub url: String,
    #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
    pub git_ref: Option<String>,
    pub commands: Vec<String>,
}

pub fn add(path: &Path, commands_dir: &Path, name: &str, url: &str, git_ref: Option<&str>) -> Result<Added> {
    ensure!(is_valid_name(name), "{name:?} is not a valid marketplace name (a-z, 0-9, '-', '_')");
    let markets = load(path)?;
    if let Some(existing) = markets.markets.get(name) {
        bail!(
            "a marketplace named {name:?} already exists ({}). Remove it first: tb self market rm {name}",
            existing.url
        );
    }
    let url = git::resolve_url(url)?;
    let offered = list(commands_dir, &url, git_ref)?;
    let market = Market {
        url: url.clone(),
        git_ref: git_ref.map(str::to_string),
    };
    save(path, &markets.with(name, market))?;
    Ok(Added {
        name: name.to_string(),
        url,
        git_ref: git_ref.map(str::to_string),
        commands: offered.commands.into_iter().map(|l| l.name).collect(),
    })
}

pub fn entries(path: &Path) -> Result<Vec<Entry>> {
    Ok(load(path)?
        .markets
        .into_iter()
        .map(|(name, m)| Entry {
            name,
            url: m.url,
            git_ref: m.git_ref,
        })
        .collect())
}

pub fn remove(path: &Path, name: &str) -> Result<()> {
    let markets = load(path)?;
    ensure!(markets.markets.contains_key(name), "no marketplace named {name:?}");
    save(path, &markets.without(name))
}

pub fn resolve(markets: &Markets, source: &str, git_ref: Option<&str>, names: &[String]) -> Result<Request> {
    let (market_name, picked) = match source.split_once('/') {
        Some((market, command)) if is_valid_name(market) && is_valid_name(command) => (market, Some(command)),
        _ => (source, None),
    };
    let plain = || Request {
        url: source.to_string(),
        git_ref: git_ref.map(str::to_string),
        names: names.to_vec(),
    };
    if !is_valid_name(market_name) {
        return Ok(plain());
    }
    match markets.markets.get(market_name) {
        Some(market) => Ok(Request {
            url: market.url.clone(),
            git_ref: git_ref.map(str::to_string).or_else(|| market.git_ref.clone()),
            names: picked.map(str::to_string).into_iter().chain(names.iter().cloned()).collect(),
        }),
        None if Path::new(source).exists() => Ok(plain()),
        None => bail!(
            "no marketplace named {market_name:?}. Add it with `tb self market add {market_name} <git-url>`, give a full git URL, or write a local folder as ./{source}"
        ),
    }
}

#[derive(Debug, Serialize)]
pub struct SearchReport {
    pub results: Vec<Listing>,
    pub problems: Vec<Problem>,
}

pub fn search(path: &Path, commands_dir: &Path, text: Option<&str>) -> Result<SearchReport> {
    let markets = load(path)?;
    ensure!(
        !markets.markets.is_empty(),
        "no marketplaces yet. Add one: tb self market add <name> <git-url>"
    );
    let needle = text.map(str::to_lowercase);
    let found: Vec<std::result::Result<Vec<Listing>, Problem>> = markets
        .markets
        .iter()
        .map(|(name, market)| {
            list(commands_dir, &market.url, market.git_ref.as_deref())
                .map(|offered| {
                    offered
                        .commands
                        .into_iter()
                        .filter(|l| matches(l, needle.as_deref()))
                        .map(|l| Listing {
                            market: Some(name.clone()),
                            ..l
                        })
                        .collect()
                })
                .map_err(|err| Problem {
                    command: name.clone(),
                    problem: format!("{err:#}"),
                })
        })
        .collect();
    let (results, problems): (Vec<_>, Vec<_>) = found.into_iter().partition(Result::is_ok);
    Ok(SearchReport {
        results: results.into_iter().flat_map(Result::unwrap).collect(),
        problems: problems.into_iter().filter_map(Result::err).collect(),
    })
}

fn matches(listing: &Listing, needle: Option<&str>) -> bool {
    needle.is_none_or(|needle| {
        listing.name.contains(needle) || listing.description.to_lowercase().contains(needle)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::manifest::Permissions;

    fn acme() -> Markets {
        Markets::default().with(
            "acme",
            Market {
                url: "https://github.com/acme/tb-market.git".into(),
                git_ref: Some("stable".into()),
            },
        )
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(std::string::ToString::to_string).collect()
    }

    #[test]
    fn store_round_trips_and_missing_file_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("markets.json");
        assert_eq!(load(&path).unwrap(), Markets::default());
        save(&path, &acme()).unwrap();
        assert_eq!(load(&path).unwrap(), acme());
        assert!(acme().without("acme").markets.is_empty());
    }

    #[test]
    fn market_shorthand_and_name_both_pick_commands() {
        let one = resolve(&acme(), "acme/stars", None, &[]).unwrap();
        assert_eq!(one.url, "https://github.com/acme/tb-market.git");
        assert_eq!(one.git_ref.as_deref(), Some("stable"));
        assert_eq!(one.names, strings(&["stars"]));

        let many = resolve(&acme(), "acme", Some("v2"), &strings(&["a", "b"])).unwrap();
        assert_eq!(many.git_ref.as_deref(), Some("v2"), "--ref overrides the saved ref");
        assert_eq!(many.names, strings(&["a", "b"]));
    }

    #[test]
    fn urls_and_paths_pass_through() {
        for source in ["https://gitlab.com/a/b.git", "git@github.com:a/b.git", "./acme", "/abs/path"] {
            let request = resolve(&acme(), source, None, &strings(&["x"])).unwrap();
            assert_eq!(request.url, source);
            assert_eq!(request.names, strings(&["x"]));
        }
    }

    #[test]
    fn unknown_market_names_explain_themselves() {
        let err = resolve(&acme(), "nope/stars", None, &[]).unwrap_err().to_string();
        assert!(err.contains("no marketplace named \"nope\""), "{err}");
        assert!(err.contains("tb self market add nope"), "{err}");
    }

    #[test]
    fn search_matches_name_or_description_ignoring_case() {
        let listing = Listing {
            market: None,
            name: "pr-status".into(),
            version: None,
            description: "Show a GitHub pull request".into(),
            permissions: Permissions::default(),
            installed: false,
        };
        assert!(matches(&listing, None));
        assert!(matches(&listing, Some("pr")));
        assert!(matches(&listing, Some("github")));
        assert!(!matches(&listing, Some("gitlab")));
    }
}
