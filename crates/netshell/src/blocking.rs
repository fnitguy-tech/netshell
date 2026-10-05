//! A synchronous wrapper for callers that run devices from plain
//! threads (one thread per device is the classic collector shape).
//!
//! Each [`Device`] owns a small single-threaded tokio runtime, so it
//! must not be created from inside another tokio runtime; use the
//! async [`crate::Device`] there.

use std::time::Duration;

use tokio::runtime::{Builder, Runtime};

use crate::{ConnectOptions, Error, Result};

/// Blocking counterpart of [`crate::Device`].
pub struct Device {
    runtime: Runtime,
    // `None` only once `disconnect` or `drop` has taken the session.
    inner: Option<crate::Device>,
}

impl Device {
    pub fn connect(options: ConnectOptions) -> Result<Device> {
        // Building a runtime can fail, for example when the process is
        // out of file descriptors. That's an error to report, not a
        // reason to take the whole collector down.
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(Error::Runtime)?;
        let inner = runtime.block_on(crate::Device::connect(options))?;
        Ok(Device {
            runtime,
            inner: Some(inner),
        })
    }

    fn session(&mut self) -> Result<(&Runtime, &mut crate::Device)> {
        match self.inner.as_mut() {
            Some(inner) => Ok((&self.runtime, inner)),
            None => Err(Error::Disconnected),
        }
    }

    /// The prompt minus its terminator and mode suffix, e.g. `SW-1`.
    pub fn base_prompt(&self) -> &str {
        self.inner.as_ref().map_or("", crate::Device::base_prompt)
    }

    /// See [`crate::Device::warnings`].
    pub fn warnings(&self) -> &[String] {
        self.inner.as_ref().map_or(&[], crate::Device::warnings)
    }

    /// See [`crate::Device::is_poisoned`].
    pub fn is_poisoned(&self) -> bool {
        self.inner.as_ref().is_some_and(crate::Device::is_poisoned)
    }

    pub fn find_prompt(&mut self) -> Result<String> {
        let (runtime, inner) = self.session()?;
        runtime.block_on(inner.find_prompt())
    }

    pub fn send_command(&mut self, command: &str) -> Result<String> {
        let (runtime, inner) = self.session()?;
        runtime.block_on(inner.send_command(command))
    }

    pub fn send_command_timeout(&mut self, command: &str, timeout: Duration) -> Result<String> {
        let (runtime, inner) = self.session()?;
        runtime.block_on(inner.send_command_timeout(command, timeout))
    }

    pub fn send_command_expect(&mut self, command: &str, pattern: &str, timeout: Duration) -> Result<String> {
        let (runtime, inner) = self.session()?;
        runtime.block_on(inner.send_command_expect(command, pattern, timeout))
    }

    pub fn write(&mut self, text: &str) -> Result<()> {
        let (runtime, inner) = self.session()?;
        runtime.block_on(inner.write(text))
    }

    pub fn disconnect(mut self) -> Result<()> {
        match self.inner.take() {
            Some(inner) => self.runtime.block_on(inner.disconnect()),
            None => Ok(()),
        }
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            let _ = self.runtime.block_on(inner.disconnect());
        }
    }
}
