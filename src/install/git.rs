use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};

pub fn resolve_url(url: &str) -> Result<String> {
    let path = Path::new(url);
    if !path.exists() {
        return Ok(url.to_string());
    }
    let absolute = path.canonicalize().with_context(|| format!("could not resolve {url}"))?;
    Ok(absolute.to_str().context("the repo path is not UTF-8")?.to_string())
}

pub fn fetch(url: &str, git_ref: Option<&str>, dest: &Path) -> Result<String> {
    ensure!(!url.trim().is_empty(), "the git URL is empty");
    ensure!(!url.starts_with('-'), "{url:?} is not a git URL");
    if let Some(r) = git_ref {
        ensure!(
            !r.is_empty() && !r.starts_with('-') && !r.contains(char::is_whitespace),
            "{r:?} is not a branch, tag or commit"
        );
    }
    let dest_str = dest.to_str().context("the staging folder path is not UTF-8")?;
    git(None, &["init", "--quiet", dest_str])?;
    git(
        Some(dest),
        &["fetch", "--quiet", "--depth", "1", "--no-tags", "--", url, git_ref.unwrap_or("HEAD")],
    )
    .with_context(|| format!("could not fetch {url}"))?;
    git(Some(dest), &["checkout", "--quiet", "FETCH_HEAD"])?;
    Ok(git(Some(dest), &["rev-parse", "HEAD"])?.trim().to_string())
}

fn git(dir: Option<&Path>, args: &[&str]) -> Result<String> {
    let mut cmd = Command::new("git");
    cmd.args(["-c", "protocol.ext.allow=never"]);
    if let Some(dir) = dir {
        cmd.arg("-C").arg(dir);
    }
    let out = cmd
        .args(args)
        .output()
        .context("could not run git. Install git, then try again")?;
    if !out.status.success() {
        let action = args.first().copied().unwrap_or_default();
        bail!("git {action} failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_paths_become_absolute_and_urls_stay() {
        let url = "https://gitlab.com/a/tools.git";
        assert_eq!(resolve_url(url).unwrap(), url);
        assert_eq!(resolve_url("git@github.com:a/tools.git").unwrap(), "git@github.com:a/tools.git");
        let here = std::env::current_dir().unwrap().canonicalize().unwrap();
        assert_eq!(resolve_url(".").unwrap(), here.to_str().unwrap());
    }

    #[test]
    fn rejects_option_like_input() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("repo");
        assert!(fetch("--upload-pack=touch /tmp/x", None, &dest).is_err());
        assert!(fetch("", None, &dest).is_err());
        assert!(fetch("https://example.com/r.git", Some("--orphan"), &dest).is_err());
        assert!(!dest.exists());
    }
}
