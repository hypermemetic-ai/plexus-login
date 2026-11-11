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
/// The directory is verified once, on the handle [`LinkDir::open`] keeps,
/// and every file is reached through that handle (`openat`, `unlinkat`,
/// no-follow): a directory renamed away and replaced afterwards is never
/// read.
///
/// Who may mint is whoever may write the directory: the operator, the OS
/// user the server runs as.
#[derive(Debug, Clone)]
pub struct LinkDir {
    dir: PathBuf,
    fd: std::sync::Arc<std::fs::File>,
}

/// The effective user.
fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

fn refusal(dir: &Path, why: &str, what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, format!("{}: {why}; {what}", dir.display()))
}

/// `dir` opened as a directory, never through a symlink, made (0700, with
/// any missing parents) when missing; its metadata read from the handle.
fn open_dir(dir: &Path) -> io::Result<(std::fs::File, std::fs::Metadata)> {
    let ctx = |e: io::Error| io::Error::new(e.kind(), format!("{}: {e}", dir.display()));
    match dir.symlink_metadata() {
        Ok(m) if m.file_type().is_symlink() => return Err(refusal(dir, "a symlink", "give the directory itself")),
        Ok(m) if !m.is_dir() => return Err(refusal(dir, "not a directory", "give a directory")),
        Ok(_) => {}
        Err(_) => std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir).map_err(ctx)?,
    }
    let f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC).open(dir).map_err(|e| {
        if e.raw_os_error() == Some(libc::ELOOP) || e.raw_os_error() == Some(libc::ENOTDIR) {
            refusal(dir, "a symlink or not a directory", "give the directory itself")
        } else {
            ctx(e)
        }
    })?;
    let meta = f.metadata().map_err(ctx)?;
    Ok((f, meta))
}

/// GAMMA-15 (review F1): `dir` as a server's private data directory —
/// made 0700 when missing; refused when it is a symlink, not a directory,
/// another user's, or writable by its group or others (naming the fix: it
/// is never changed silently). Whatever is kept inside is only as safe as
/// this: whoever may write it may plant a session, a link, or a file the
/// server reads.
pub fn private_dir(dir: impl AsRef<Path>) -> io::Result<()> {
    let dir = dir.as_ref();
    let (_, meta) = open_dir(dir)?;
    if meta.uid() != euid() {
        return Err(refusal(dir, "another user's", "a data directory must be the server's own"));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(refusal(dir, &format!("writable by its group or others (mode {:o})", meta.mode() & 0o777), &format!("whoever may write it may sign in; `chmod go-w {}` (or 0700) and start again", dir.display())));
    }
    Ok(())
}

/// GAMMA-15 (review F1): the bytes of `path` (at most `max`), read only
/// when it is a regular file of the effective user's that its group and
/// others cannot write — never through a symlink, never blocking on a FIFO.
pub fn read_private(path: impl AsRef<Path>, max: u64) -> io::Result<Vec<u8>> {
    let path = path.as_ref();
    let f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC).open(path)?;
    let meta = f.metadata()?;
    if !meta.is_file() || meta.uid() != euid() || meta.mode() & 0o022 != 0 {
        return Err(refusal(path, "not a private file of this user's", "it is not read"));
    }
    let mut bytes = Vec::new();
    f.take(max).read_to_end(&mut bytes)?;
    Ok(bytes)
}

impl LinkDir {
    /// The links in `dir`, made (0700) when missing. Refused when `dir` is
    /// a symlink, not a directory, another user's, or writable by its group
    /// or others; one others may only read is closed to 0700.
    pub fn open(dir: impl AsRef<Path>) -> io::Result<Self> {
        let dir = dir.as_ref();
        let what = "the one-time links are kept only in a directory of the server's own";
        let (fd, meta) = open_dir(dir).map_err(|e| io::Error::new(e.kind(), format!("{e}; {what}")))?;
        if meta.uid() != euid() {
            return Err(refusal(dir, "another user's", what));
        }
        if meta.mode() & 0o022 != 0 {
            return Err(refusal(dir, "writable by its group or others", &format!("{what}: `chmod 700 {}`", dir.display())));
        }
        if meta.mode() & 0o077 != 0 {
            fd.set_permissions(std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self { dir: dir.to_path_buf(), fd: std::sync::Arc::new(fd) })
    }

    /// The directory (as it was named when opened).
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// `name` in the verified directory, opened with `flags`, never through
    /// a symlink.
    fn open_at(&self, name: &str, flags: libc::c_int) -> io::Result<std::fs::File> {
        use std::os::fd::{AsRawFd, FromRawFd};
        let c = std::ffi::CString::new(name).map_err(io::Error::other)?;
        // SAFETY: a valid directory fd, a NUL-terminated name; the fd
        // returned is owned by the File.
        let fd = unsafe { libc::openat(self.fd.as_raw_fd(), c.as_ptr(), flags | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0o600 as libc::c_uint) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }

    /// Removes `name` from the verified directory.
    fn unlink_at(&self, name: &str) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        let c = std::ffi::CString::new(name).map_err(io::Error::other)?;
        // SAFETY: a valid directory fd and a NUL-terminated name.
        if unsafe { libc::unlinkat(self.fd.as_raw_fd(), c.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// The names in the verified directory.
    fn names(&self) -> Vec<String> {
        use std::os::fd::AsRawFd;
        let mut out = Vec::new();
        // SAFETY: a dup of a valid directory fd, handed to fdopendir, which
        // owns it until closedir; each entry read before the next readdir.
        unsafe {
            let fd = libc::dup(self.fd.as_raw_fd());
            if fd < 0 {
                return out;
            }
            let d = libc::fdopendir(fd);
            if d.is_null() {
                libc::close(fd);
                return out;
            }
            libc::rewinddir(d);
            loop {
                let e = libc::readdir(d);
                if e.is_null() {
                    break;
                }
                if let Ok(n) = std::ffi::CStr::from_ptr((*e).d_name.as_ptr()).to_str() {
                    out.push(n.to_string());
                }
            }
            libc::closedir(d);
        }
        out
    }

    /// The expiry `name` holds, read only from a regular file.
    fn expiry(&self, name: &str) -> Option<i64> {
        let f = self.open_at(name, libc::O_RDONLY | libc::O_NONBLOCK).ok()?;
        if !f.metadata().ok()?.is_file() {
            return None;
        }
        let mut text = String::new();
        f.take(32).read_to_string(&mut text).ok()?;
        text.trim().parse().ok()
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
        let mut f = self.open_at(&hash(&token), libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL)?;
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
        let name = hash(token);
        let expires = self.expiry(&name);
        // Taking it is removing it: of two at once, one succeeds.
        if self.unlink_at(&name).is_err() {
            return false;
        }
        expires.is_some_and(|e| e > at)
    }

    /// Removes every file whose expiry has passed (or does not read).
    fn clear_expired(&self, at: i64) {
        for name in self.names().into_iter().filter(|n| n != "." && n != "..") {
            if self.expiry(&name).is_none_or(|exp| exp <= at) {
                let _ = self.unlink_at(&name);
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

    /// GAMMA-15 review F1: the directory is verified once, on the handle
    /// kept — a `once/` renamed away and replaced by another, with a
    /// planted hash in it, signs no one in; nor is a token planted in a
    /// `once/` its group or others may write ever taken.
    #[test]
    fn a_swapped_once_dir_with_a_planted_hash_signs_no_one_in() {
        let root = scratch();
        let links = LinkDir::open(root.join("once")).unwrap();
        let real = links.mint().unwrap();
        std::fs::rename(root.join("once"), root.join("once.old")).unwrap();
        std::fs::DirBuilder::new().mode(0o700).create(root.join("once")).unwrap();
        let planted = "ef".repeat(32);
        std::fs::write(root.join("once").join(hash(&planted)), (crate::sessions::now() + 3600).to_string()).unwrap();
        assert!(!links.take(&planted), "the replaced directory is never read");
        assert!(root.join("once").join(hash(&planted)).exists(), "nor touched");
        assert!(links.take(&real), "the verified one still is");

        let open = root.join("open");
        std::fs::DirBuilder::new().mode(0o777).create(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        let e = LinkDir::open(&open).unwrap_err().to_string();
        assert!(e.contains("writable by its group or others"), "{e}");
        assert_eq!(std::fs::metadata(&open).unwrap().mode() & 0o777, 0o777, "refused, never changed silently");
    }

    /// GAMMA-15 review F1: a data directory is the server's own — made
    /// 0700; a symlink, a file, or one its group or others may write is
    /// refused, naming the fix, and left as it was.
    #[test]
    fn a_data_dir_others_can_write_is_refused() {
        let root = scratch();
        private_dir(root.join("new/data")).unwrap();
        assert_eq!(std::fs::metadata(root.join("new/data")).unwrap().mode() & 0o777, 0o700, "made 0700");
        let world = root.join("world");
        std::fs::create_dir(&world).unwrap();
        std::fs::set_permissions(&world, std::fs::Permissions::from_mode(0o777)).unwrap();
        let e = private_dir(&world).unwrap_err().to_string();
        assert!(e.contains("writable by its group or others") && e.contains("chmod go-w"), "{e}");
        assert_eq!(std::fs::metadata(&world).unwrap().mode() & 0o777, 0o777, "never chmodded silently");
        std::fs::set_permissions(&world, std::fs::Permissions::from_mode(0o755)).unwrap();
        private_dir(&world).expect("0755, the user's own: taken");
        std::os::unix::fs::symlink(&world, root.join("link")).unwrap();
        assert!(private_dir(root.join("link")).unwrap_err().to_string().contains("symlink"));
        std::fs::write(root.join("file"), b"").unwrap();
        assert!(private_dir(root.join("file")).unwrap_err().to_string().contains("not a directory"));
    }

    /// GAMMA-15 review F1: a private file is read only when it is a regular
    /// file of this user's that no one else may write — never a symlink's
    /// target, never a FIFO (which would block).
    #[test]
    fn a_private_file_is_read_only_when_private() {
        let root = scratch();
        let ok = root.join("ok");
        std::fs::write(&ok, b"yes").unwrap();
        std::fs::set_permissions(&ok, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_private(&ok, 64).unwrap(), b"yes");
        std::os::unix::fs::symlink(&ok, root.join("link")).unwrap();
        assert!(read_private(root.join("link"), 64).is_err(), "not through a symlink");
        std::fs::set_permissions(&ok, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read_private(&ok, 64).is_err(), "not one others may write");
        let fifo = std::ffi::CString::new(root.join("fifo").to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(read_private(root.join("fifo"), 64).is_err(), "not a FIFO, and without blocking");
    }
}
