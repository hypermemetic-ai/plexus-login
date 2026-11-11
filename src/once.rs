//! DIST-14: one-time sign-in links — `GET /login?once=<token>`.
//!
//! An app that runs on loopback with no login provider (menger's first run)
//! still never opens without a sign-in: it prints a link carrying a token,
//! and the login page trades the token, once, for a session as the app's
//! local admin. What a token is, where it is kept and who it signs in is the
//! app's ([`OnceLinks`]); the page only asks.
//!
//! The page asks only when the app gave it [`OnceLinks`] (`LoginOptions::once`)
//! and only for a caller on loopback; anywhere else `?once=` is an unknown
//! query and the plain page is served.
//!
//! GAMMA-15: [`LinkDir`] is where an app may keep its tokens — menger's
//! way (DIST-14, `menger login`), lifted: a directory of files, one per
//! token, so the running server and a command run beside it (`menger
//! login`, `plexus-ui login`) share them with no method on the wire. A
//! fresh link for a running server is a file written into its directory.

use plexus_rpc::core::plexus::AuthContext;
use sha2::Digest;
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// The app's one-time links.
pub trait OnceLinks: Send + Sync {
    /// The identity `token` signs in, taking the token: it answers once,
    /// and never after its expiry.
    fn redeem(&self, token: &str) -> Option<AuthContext>;

    /// What the page says to a link that was used, expired or never was —
    /// with the command that prints another.
    fn spent(&self) -> String;

    /// What the page says to anyone who reaches it without a link — how
    /// to get one.
    fn hint(&self) -> String;
}

/// How long a link lasts: ten minutes.
pub const ONCE_SECS: i64 = 10 * 60;

/// GAMMA-15: one-time tokens kept as files — `<dir>/<sha256 of the
/// token>`, each holding its expiry (unix seconds), 0600, in a directory
/// that is 0700, the caller's own and never a symlink. Taking a token is
/// removing its file, which succeeds once: of two at once, one signs in.
/// The token itself is never written; a file names only its hash.
///
/// Who may mint is whoever may write the directory: the operator, the OS
/// user the server runs as.
#[derive(Debug, Clone)]
pub struct LinkDir {
    dir: PathBuf,
}

impl LinkDir {
    /// The links in `dir`, made (0700) when missing. Refused when `dir` is
    /// a symlink, not a directory, or another user's; one that is open to
    /// others is closed to 0700.
    pub fn open(dir: impl AsRef<Path>) -> io::Result<Self> {
        let dir = dir.as_ref();
        let ctx = |e: io::Error| io::Error::new(e.kind(), format!("{}: {e}", dir.display()));
        if dir.symlink_metadata().is_err() {
            std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir).map_err(ctx)?;
        }
        let meta = dir.symlink_metadata().map_err(ctx)?;
        let refuse = |why: &str| io::Error::new(io::ErrorKind::PermissionDenied, format!("{}: {why}; the one-time links are kept only in a directory of the server's own", dir.display()));
        if meta.file_type().is_symlink() {
            return Err(refuse("a symlink"));
        }
        if !meta.is_dir() {
            return Err(refuse("not a directory"));
        }
        // SAFETY: geteuid has no preconditions and cannot fail.
        if meta.uid() != unsafe { libc::geteuid() } {
            return Err(refuse("another user's"));
        }
        if meta.mode() & 0o077 != 0 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(ctx)?;
        }
        Ok(Self { dir: dir.to_path_buf() })
    }

    /// The directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// A fresh token, good once for [`ONCE_SECS`]: 32 random bytes, hex.
    /// The expired ones are cleared on the way.
    pub fn mint(&self) -> io::Result<String> {
        self.mint_at(crate::sessions::now())
    }

    /// [`Self::mint`] as if the time were `at` (unix seconds).
    pub fn mint_at(&self, at: i64) -> io::Result<String> {
        self.clear_expired(at);
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.dir.join(hash(&token)))?;
        write!(f, "{}", at + ONCE_SECS)?;
        f.sync_all()?;
        Ok(token)
    }

    /// Whether `token` is a link of this directory that has not expired —
    /// taking it either way: a token answers `true` once.
    pub fn take(&self, token: &str) -> bool {
        self.take_at(token, crate::sessions::now())
    }

    /// [`Self::take`] as if the time were `at` (unix seconds).
    pub fn take_at(&self, token: &str, at: i64) -> bool {
        if token.is_empty() || token.len() > 128 {
            return false;
        }
        let file = self.dir.join(hash(token));
        let Ok(f) = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(&file) else { return false };
        let mut text = String::new();
        if f.take(32).read_to_string(&mut text).is_err() {
            return false;
        }
        // Taking it is removing it: of two at once, one succeeds.
        if std::fs::remove_file(&file).is_err() {
            return false;
        }
        text.trim().parse::<i64>().is_ok_and(|expires| expires > at)
    }

    /// Removes every file whose expiry has passed (or does not read).
    fn clear_expired(&self, at: i64) {
        let Ok(entries) = std::fs::read_dir(&self.dir) else { return };
        for e in entries.flatten() {
            let stale = std::fs::read_to_string(e.path()).ok().and_then(|s| s.trim().parse::<i64>().ok()).is_none_or(|exp| exp <= at);
            if stale {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

fn hash(token: &str) -> String {
    sha2::Sha256::digest(token.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> PathBuf {
        let d = std::env::temp_dir().join(format!("plexus-login-once-{}-{}", std::process::id(), crate::sessions::random_token()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// GAMMA-15: a link minted into the directory is taken once, within
    /// ten minutes of its making, and never after; another token is none.
    #[test]
    fn a_link_is_good_once_within_ten_minutes() {
        let links = LinkDir::open(scratch().join("once")).unwrap();
        let t = links.mint_at(1_000).unwrap();
        assert!(t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()), "32 bytes, hex: {t}");
        assert!(!links.take_at(&"ab".repeat(32), 1_001), "another token is no link");
        assert!(links.take_at(&t, 1_000 + ONCE_SECS - 1), "within ten minutes: taken");
        assert!(!links.take_at(&t, 1_001), "used: spent");
        let late = links.mint_at(1_000).unwrap();
        assert!(!links.take_at(&late, 1_000 + ONCE_SECS), "ten minutes on: spent, unused");
        let gone = links.mint_at(1_000).unwrap();
        assert!(links.mint_at(1_000 + ONCE_SECS).is_ok() && !links.take_at(&gone, 1_001), "a mint clears the expired");
    }

    /// GAMMA-15: the token is a credential — never written; a file names
    /// its hash, 0600, in a directory of 0700.
    #[test]
    fn a_link_is_kept_as_its_hash_0600_in_0700() {
        let root = scratch();
        let open = root.join("open");
        std::fs::DirBuilder::new().mode(0o755).create(&open).unwrap();
        let links = LinkDir::open(&open).unwrap();
        assert_eq!(std::fs::metadata(&open).unwrap().mode() & 0o777, 0o700, "a directory open to others is closed");
        let t = links.mint().unwrap();
        let files: Vec<_> = std::fs::read_dir(&open).unwrap().flatten().collect();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].file_name().to_string_lossy(), hash(&t), "the file names the token's hash");
        assert!(!std::fs::read_to_string(files[0].path()).unwrap().contains(&t), "never the token");
        assert_eq!(files[0].metadata().unwrap().mode() & 0o777, 0o600);
        let made = LinkDir::open(root.join("a/b")).unwrap();
        assert_eq!(std::fs::metadata(made.dir()).unwrap().mode() & 0o777, 0o700, "made 0700");
    }

    /// GAMMA-15: never through a symlink — not the directory, not a file
    /// in it.
    #[test]
    fn a_link_is_never_kept_or_taken_through_a_symlink() {
        let root = scratch();
        let elsewhere = root.join("elsewhere");
        std::fs::DirBuilder::new().mode(0o700).create(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, root.join("once")).unwrap();
        let e = LinkDir::open(root.join("once")).unwrap_err();
        assert!(e.to_string().contains("symlink"), "{e}");
        std::fs::write(root.join("file"), b"").unwrap();
        assert!(LinkDir::open(root.join("file")).unwrap_err().to_string().contains("not a directory"));

        let links = LinkDir::open(&elsewhere).unwrap();
        let target = root.join("target");
        std::fs::write(&target, (crate::sessions::now() + 600).to_string()).unwrap();
        let token = "cd".repeat(32);
        std::os::unix::fs::symlink(&target, elsewhere.join(hash(&token))).unwrap();
        assert!(!links.take(&token), "a token whose file is a symlink signs no one in");
    }
}
