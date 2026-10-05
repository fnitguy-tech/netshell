//! A password that doesn't leak by accident.

use std::fmt;

use zeroize::Zeroizing;

/// A password or enable secret.
///
/// Two things make it safer than a plain `String`. Printing it with
/// `{:?}` gives `<redacted>`, so a debug log of [`crate::ConnectOptions`]
/// can't show the password. And its memory is overwritten with zeros
/// when it's dropped.
///
/// You rarely build one by hand: anything that takes a secret accepts
/// `&str`, `String`, or `&String`.
///
/// ```
/// let secret = netshell::Secret::from("hunter2");
/// assert_eq!(format!("{secret:?}"), "<redacted>");
/// assert_eq!(secret.expose(), "hunter2");
/// ```
///
/// One limit to know about: russh copies the password into its own
/// buffer to send it, and that copy isn't wiped.
#[derive(Clone, Default)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    /// The secret itself. The name is loud on purpose, so a reviewer
    /// can find every place a password is read.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Secret {
        // Moves the String in, so there's no second copy to wipe.
        Secret(Zeroizing::new(value))
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Secret {
        Secret(Zeroizing::new(value.to_string()))
    }
}

impl From<&String> for Secret {
    fn from(value: &String) -> Secret {
        Secret(Zeroizing::new(value.clone()))
    }
}
