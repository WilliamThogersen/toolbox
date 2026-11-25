use super::NewKey;
use crate::cli::screen::{one_line, printable};
use crate::command::registry::{CommandDef, Registry};
use crate::command::sources::Sources;
use crate::vault::approval::{self, Access};
use crate::vault::commands::{Key, destination};
use crate::vault::{SecretEntry, VaultData};

const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const INVERSE: &str = "\x1b[7m";
const RESET: &str = "\x1b[0m";
const HELP: &str = "up/down move  enter choose  v read script  tab current access  s save  q quit";

pub struct KeyRow {
    pub key: NewKey,
    pub users: Vec<String>,
    pub entry: Option<SecretEntry>,
}

pub struct Script<'a> {
    pub def: &'a CommandDef,
    pub sources: Sources,
    pub fingerprint: String,
}

pub struct UseRow {
    pub script: usize,
    pub key: String,
    pub changed: bool,
    pub allowed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum View {
    List,
    Access,
    Confirm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Stay,
    AskKey(usize),
    Read(usize),
    Save,
    Quit,
}

pub struct Menu<'a> {
    pub keys: Vec<KeyRow>,
    pub uses: Vec<UseRow>,
    pub scripts: Vec<Script<'a>>,
    vault: &'a VaultData,
    registry: &'a Registry,
    cursor: usize,
    view: View,
    status: String,
    quit_armed: bool,
}

pub struct Plan<'a> {
    pub added: Vec<(&'a str, &'a SecretEntry)>,
    pub allowed: Vec<&'a UseRow>,
    pub declined: Vec<&'a UseRow>,
    pub skipped: Vec<&'a str>,
}

impl<'a> Menu<'a> {
    pub fn new(
        keys: Vec<KeyRow>,
        uses: Vec<UseRow>,
        scripts: Vec<Script<'a>>,
        vault: &'a VaultData,
        registry: &'a Registry,
    ) -> Self {
        Self { keys, uses, scripts, vault, registry, cursor: 0, view: View::List, status: String::new(), quit_armed: false }
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty() && self.uses.is_empty()
    }

    pub fn set_status(&mut self, text: &str) {
        self.status = printable(&one_line(text));
    }

    pub fn set_entry(&mut self, index: usize, entry: Option<SecretEntry>) {
        let Some(row) = self.keys.get_mut(index) else { return };
        row.entry = entry;
        let name = row.key.request.name.clone();
        let ready = row.entry.is_some();
        self.set_status(&if ready { format!("{name} is ready. Allow the commands below that should use it.") } else { format!("{name} was skipped.") });
        if !ready {
            self.uses.iter_mut().filter(|u| u.key == name).for_each(|u| u.allowed = false);
        }
    }

    pub fn entry(&self, key: &str) -> Option<&SecretEntry> {
        self.vault.get(key).or_else(|| {
            self.keys.iter().find(|row| row.key.request.name == key).and_then(|row| row.entry.as_ref())
        })
    }

    pub fn plan(&self) -> Plan<'_> {
        let (ready, waiting): (Vec<&KeyRow>, Vec<&KeyRow>) = self.keys.iter().partition(|row| row.entry.is_some());
        let available: Vec<&UseRow> = self.uses.iter().filter(|u| self.entry(&u.key).is_some()).collect();
        let (allowed, declined) = available.into_iter().partition(|u| u.allowed);
        Plan {
            added: ready
                .into_iter()
                .filter_map(|row| row.entry.as_ref().map(|entry| (row.key.request.name.as_str(), entry)))
                .collect(),
            allowed,
            declined,
            skipped: waiting.into_iter().map(|row| row.key.request.name.as_str()).collect(),
        }
    }

    pub fn command(&self, row: &UseRow) -> &str {
        self.scripts.get(row.script).map_or("", |s| s.def.manifest.name.as_str())
    }

    pub fn full_script(&self, script: usize) -> String {
        self.scripts.get(script).map(|s| printable(&approval::full_text(s.def, &s.sources))).unwrap_or_default()
    }

    fn rows(&self) -> usize {
        self.keys.len().saturating_add(self.uses.len())
    }

    fn use_at(&self, cursor: usize) -> Option<(usize, &UseRow)> {
        let index = cursor.checked_sub(self.keys.len())?;
        self.uses.get(index).map(|row| (index, row))
    }

    pub fn press(&mut self, key: Key) -> Action {
        let armed = std::mem::take(&mut self.quit_armed);
        match self.view {
            View::Access => {
                self.view = View::List;
                Action::Stay
            }
            View::Confirm => {
                self.view = View::List;
                if matches!(key, Key::Enter | Key::Char('y' | 'Y')) { Action::Save } else { Action::Stay }
            }
            View::List => self.press_in_list(key, armed),
        }
    }

    fn press_in_list(&mut self, key: Key, armed: bool) -> Action {
        self.status.clear();
        match key {
            Key::Up | Key::Char('k') => self.cursor = self.cursor.saturating_sub(1),
            Key::Down | Key::Char('j') => {
                self.cursor = self.cursor.saturating_add(1).min(self.rows().saturating_sub(1));
            }
            Key::Enter | Key::Space => return self.choose(),
            Key::Char('v') => match self.use_at(self.cursor) {
                Some((_, row)) => return Action::Read(row.script),
                None => self.set_status("v reads the script of the command under the cursor"),
            },
            Key::Tab | Key::Char('a') => self.view = View::Access,
            Key::Char('s') => self.view = View::Confirm,
            Key::Quit | Key::Char('q') => return self.quit(armed),
            Key::Char(_) | Key::Other => self.set_status(HELP),
        }
        Action::Stay
    }

    fn choose(&mut self) -> Action {
        if self.cursor < self.keys.len() {
            return Action::AskKey(self.cursor);
        }
        let Some((index, row)) = self.use_at(self.cursor) else { return Action::Stay };
        if self.entry(&row.key).is_none() {
            let text = format!("Add the key {} first: it is in the list above.", row.key);
            self.set_status(&text);
            return Action::Stay;
        }
        if let Some(row) = self.uses.get_mut(index) {
            row.allowed = !row.allowed;
        }
        Action::Stay
    }

    fn quit(&mut self, armed: bool) -> Action {
        let plan = self.plan();
        if armed || (plan.added.is_empty() && plan.allowed.is_empty()) {
            return Action::Quit;
        }
        self.quit_armed = true;
        self.set_status("Press q again to quit without saving anything.");
        Action::Stay
    }

    pub fn render(&self, width: usize, height: usize) -> String {
        let lines = match self.view {
            View::List => self.render_list(height),
            View::Access => self.render_access(),
            View::Confirm => self.render_confirm(),
        };
        let fitted: Vec<String> = lines.iter().take(height.saturating_sub(1)).map(|line| fit(line, width)).collect();
        fitted.join("\r\n")
    }

    fn render_list(&self, height: usize) -> Vec<String> {
        let mut lines = vec![format!("{BOLD}tb self vault setup{RESET}  {DIM}what is waiting for you{RESET}"), String::new()];
        let list = self.list_lines();
        let room = (height / 2).max(4);
        let start = self.list_start(&list, room);
        lines.extend(list.into_iter().skip(start).take(room).map(|(_, line)| line));
        lines.push(format!("{DIM}{}{RESET}", "-".repeat(60)));
        let details_room = height.saturating_sub(lines.len()).saturating_sub(4);
        let details = self.details();
        let more = details.len() > details_room;
        lines.extend(details.into_iter().take(details_room));
        if more {
            lines.push(format!("{DIM}  ... (v reads the whole script){RESET}"));
        }
        lines.push(String::new());
        lines.push(self.status.clone());
        lines.push(format!("{DIM}{HELP}{RESET}"));
        lines
    }

    fn list_start(&self, list: &[(Option<usize>, String)], room: usize) -> usize {
        let at = list.iter().position(|(row, _)| *row == Some(self.cursor)).unwrap_or(0);
        at.saturating_add(2).saturating_sub(room)
    }

    fn list_lines(&self) -> Vec<(Option<usize>, String)> {
        let mut lines = Vec::new();
        if !self.keys.is_empty() {
            lines.push((None, format!("{BOLD}Keys to add{RESET}")));
            lines.extend(self.keys.iter().enumerate().map(|(i, row)| (Some(i), self.key_line(i, row))));
            lines.push((None, String::new()));
        }
        if !self.uses.is_empty() {
            lines.push((None, format!("{BOLD}Commands that want a key{RESET}")));
            let first = self.keys.len();
            lines.extend(self.uses.iter().enumerate().map(|(i, row)| {
                let at = first.saturating_add(i);
                (Some(at), self.use_line(at, row))
            }));
        }
        lines
    }

    fn key_line(&self, at: usize, row: &KeyRow) -> String {
        let name = &row.key.request.name;
        let text = match &row.entry {
            Some(entry) => format!("[x] {name:<24} ready, goes to {}", printable(&destination(entry))),
            None => format!("[ ] {name:<24} waiting for you, enter to paste it"),
        };
        self.mark(at, &text)
    }

    fn use_line(&self, at: usize, row: &UseRow) -> String {
        let check = if row.allowed { "[x]" } else { "[ ]" };
        let what = format!("{} may use {}", self.command(row), row.key);
        let note = if self.entry(&row.key).is_none() {
            "add the key first"
        } else if row.changed {
            "changed since you allowed it"
        } else {
            "new"
        };
        self.mark(at, &format!("{check} {what:<40} {DIM}{note}{RESET}"))
    }

    fn mark(&self, at: usize, text: &str) -> String {
        if at == self.cursor { format!("{INVERSE}> {text}{RESET}") } else { format!("  {text}") }
    }

    fn details(&self) -> Vec<String> {
        if let Some(row) = self.keys.get(self.cursor) {
            return key_details(row);
        }
        let Some((_, row)) = self.use_at(self.cursor) else { return Vec::new() };
        let Some(script) = self.scripts.get(row.script) else { return Vec::new() };
        let Some(entry) = self.entry(&row.key) else {
            return vec![format!("Add the key {} first (it is in the list above), then allow this command.", row.key)];
        };
        let review = approval::review(script.def, &script.sources, &[(row.key.as_str(), entry)]);
        review.summary.lines().map(str::to_string).collect()
    }

    fn render_access(&self) -> Vec<String> {
        let mut lines = vec![format!("{BOLD}Keys in your vault and the commands allowed to use them{RESET}"), String::new()];
        for (name, entry) in &self.vault.secrets {
            lines.push(format!("{BOLD}{name}{RESET}  goes to {}", printable(&destination(entry))));
            let users = approval::access(name, entry, self.registry);
            if users.is_empty() {
                lines.push(format!("    {DIM}no command uses it{RESET}"));
            }
            lines.extend(users.into_iter().map(|user| format!("    {:<28} {}", user.name, access_text(user.access))));
        }
        if self.vault.secrets.is_empty() {
            lines.push("The vault is empty.".to_string());
        }
        lines.extend([String::new(), format!("{DIM}any key goes back{RESET}")]);
        lines
    }

    fn render_confirm(&self) -> Vec<String> {
        let plan = self.plan();
        let mut lines = vec![format!("{BOLD}This is what will be saved{RESET}"), String::new()];
        let added = plan.added.iter().map(|(name, entry)| format!("  add the key {name}, sent only to {}", printable(&destination(entry))));
        let allowed = plan.allowed.iter().map(|u| format!("  let {} use {}", self.command(u), u.key));
        let changes: Vec<String> = added.chain(allowed).collect();
        if changes.is_empty() {
            lines.push("  nothing".to_string());
        }
        lines.extend(changes);
        let declined: Vec<String> = plan.declined.iter().map(|u| format!("  {} may not use {}", self.command(u), u.key)).collect();
        if !declined.is_empty() {
            lines.extend([String::new(), format!("{BOLD}Not allowed{RESET} {DIM}(logged as declined){RESET}")]);
            lines.extend(declined);
        }
        if !plan.skipped.is_empty() {
            lines.extend([String::new(), format!("{BOLD}Still waiting{RESET} {DIM}(the requests stay){RESET}")]);
            lines.push(format!("  {}", plan.skipped.join(", ")));
        }
        lines.extend([String::new(), "Enter or y saves (macOS asks for Touch ID). Any other key goes back.".to_string()]);
        lines
    }
}

fn key_details(row: &KeyRow) -> Vec<String> {
    let req = &row.key.request;
    let list = |items: &[String]| items.join(", ");
    let lines = [
        Some(format!("Key {} {}", req.name, if row.key.requested { "was requested" } else { "is missing" })),
        (!req.why.is_empty()).then(|| format!("  why: {}", one_line(&req.why))),
        req.note.as_ref().map(|note| format!("  note: {}", one_line(note))),
        Some(match row.users.as_slice() {
            [] => "  no command uses it yet".to_string(),
            users => format!("  used by {}", users.join(", ")),
        }),
        (!req.hosts.is_empty()).then(|| format!("  hosts asked for: {}", list(&req.hosts))),
        (req.hosts.is_empty() && !row.key.calls.is_empty()).then(|| format!("  the command calls {}", list(&row.key.calls))),
        (!req.query_params.is_empty()).then(|| format!("  query parameters: {}", list(&req.query_params))),
        (!req.methods.is_empty()).then(|| format!("  methods: {}", list(&req.methods))),
        (!req.paths.is_empty()).then(|| format!("  paths: {}", list(&req.paths))),
        Some(String::new()),
        Some(match &row.entry {
            Some(_) => "Enter asks again, an empty answer takes it back out.".to_string(),
            None => "Enter lets you check where it may go and paste it. Nothing is saved before s.".to_string(),
        }),
    ];
    lines.into_iter().flatten().map(|line| printable(&line)).collect()
}

fn access_text(access: Access) -> &'static str {
    match access {
        Access::Allowed => "allowed",
        Access::Changed => "changed since allowed, run setup to review",
        Access::NotAllowed => "not allowed",
        Access::Missing => "allowed, but the command is gone or unreadable",
    }
}

fn fit(line: &str, width: usize) -> String {
    let mut visible = 0usize;
    let mut out = String::with_capacity(line.len());
    let mut in_escape = false;
    for c in line.chars() {
        if c == '\x1b' {
            in_escape = true;
        } else if in_escape {
            in_escape = !c.is_ascii_alphabetic();
        } else if visible >= width.saturating_sub(1) {
            continue;
        } else {
            visible = visible.saturating_add(1);
        }
        out.push(c);
    }
    out
}
