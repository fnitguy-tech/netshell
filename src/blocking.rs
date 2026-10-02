//! A synchronous wrapper for callers that run devices from plain
//! threads (one thread per device is the classic collector shape).
//!
//! Each [`Device`] owns a small single-threaded tokio runtime, so it
//! must not be created from inside another tokio runtime; use the
//! async [`crate::Device`] there.

use std::time::Duration;

use tokio::runtime::{Builder, Runtime};

use crate::{ConnectOptions, Result};

/// Blocking counterpart of [`crate::Device`].
pub struct Device {
    runtime: Runtime,
    inner: Option<crate::Device>,
}

impl Device {
    pub fn connect(options: ConnectOptions) -> Result<Device> {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let inner = runtime.block_on(crate::Device::connect(options))?;
        Ok(Device {
            runtime,
            inner: Some(inner),
        })
    }

    pub fn base_prompt(&self) -> &str {
        self.inner.as_ref().expect("device already disconnected").base_prompt()
    }

    pub fn find_prompt(&mut self) -> Result<String> {
        let inner = self.inner.as_mut().expect("device already disconnected");
        self.runtime.block_on(inner.find_prompt())
    }

    pub fn send_command(&mut self, command: &str) -> Result<String> {
        let inner = self.inner.as_mut().expect("device already disconnected");
        self.runtime.block_on(inner.send_command(command))
    }

    pub fn send_command_timeout(&mut self, command: &str, timeout: Duration) -> Result<String> {
        let inner = self.inner.as_mut().expect("device already disconnected");
        self.runtime.block_on(inner.send_command_timeout(command, timeout))
    }

    pub fn send_command_expect(&mut self, command: &str, pattern: &str, timeout: Duration) -> Result<String> {
        let inner = self.inner.as_mut().expect("device already disconnected");
        self.runtime
            .block_on(inner.send_command_expect(command, pattern, timeout))
    }

    pub fn write(&mut self, text: &str) -> Result<()> {
        let inner = self.inner.as_mut().expect("device already disconnected");
        self.runtime.block_on(inner.write(text))
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
