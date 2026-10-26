use anyhow::{Result, anyhow};
use clap::ArgMatches;

pub fn required<'a>(matches: &'a ArgMatches, id: &str) -> Result<&'a str> {
    optional(matches, id)?.ok_or_else(|| anyhow!("missing argument {id}"))
}

pub fn optional<'a>(matches: &'a ArgMatches, id: &str) -> Result<Option<&'a str>> {
    Ok(matches.try_get_one::<String>(id)?.map(String::as_str))
}

pub fn values(matches: &ArgMatches, id: &str) -> Result<Vec<String>> {
    Ok(matches.try_get_many::<String>(id)?.into_iter().flatten().cloned().collect())
}

pub fn flag(matches: &ArgMatches, id: &str) -> Result<bool> {
    Ok(matches.try_get_one::<bool>(id)?.copied().unwrap_or(false))
}

pub fn typed<T: Clone + Send + Sync + 'static>(matches: &ArgMatches, id: &str) -> Result<T> {
    matches.try_get_one::<T>(id)?.cloned().ok_or_else(|| anyhow!("missing argument {id}"))
}

#[cfg(test)]
mod tests {
    use clap::{Arg, ArgAction, Command};

    use super::*;

    fn parse(args: &[&str]) -> ArgMatches {
        Command::new("t")
            .arg(Arg::new("name").required(true))
            .arg(Arg::new("tag").long("tag").action(ArgAction::Append))
            .arg(Arg::new("yes").long("yes").action(ArgAction::SetTrue))
            .arg(Arg::new("n").long("n").value_parser(clap::value_parser!(usize)))
            .get_matches_from(args)
    }

    #[test]
    fn lookups_read_what_clap_parsed() {
        let m = parse(&["t", "hi", "--tag", "a", "--tag", "b", "--yes", "--n", "3"]);
        assert_eq!(required(&m, "name").unwrap(), "hi");
        assert_eq!(values(&m, "tag").unwrap(), ["a", "b"]);
        assert!(flag(&m, "yes").unwrap());
        assert_eq!(typed::<usize>(&m, "n").unwrap(), 3);
        let bare = parse(&["t", "hi"]);
        assert!(values(&bare, "tag").unwrap().is_empty());
        assert!(!flag(&bare, "yes").unwrap());
        assert!(typed::<usize>(&bare, "n").is_err());
    }

    #[test]
    fn unknown_ids_and_wrong_types_are_errors_not_panics() {
        let m = parse(&["t", "hi", "--n", "3"]);
        assert!(required(&m, "nope").is_err());
        assert!(optional(&m, "n").is_err());
        assert!(flag(&m, "name").is_err());
    }
}
