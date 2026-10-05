//! Embeds the icon and version resource into the Windows executable.
//! On every other platform this does nothing; the resource compiler
//! (rc.exe) ships with the MSVC toolchain the Windows builds use.
//! FileVersion and ProductVersion come from the crate version.
//!
//! The resource belongs to the `netshell` binary, so it's only built
//! with the `cli` feature. A library-only build skips it and doesn't
//! need the `winresource` crate at all.

fn main() {
    println!("cargo:rerun-if-changed=assets/netshell.ico");

    #[cfg(all(windows, feature = "cli"))]
    {
        let mut resource = winresource::WindowsResource::new();
        resource.set_icon("assets/netshell.ico");
        resource.set("ProductName", "netshell");
        resource.set("FileDescription", "SSH shell driver for network devices");
        resource.set("CompanyName", "fnitguy-tech");
        resource.set("LegalCopyright", "Copyright (c) 2026 fnitguy-tech. MIT License.");
        resource.set("OriginalFilename", "netshell.exe");
        resource.compile().expect("compile the Windows resource");
    }
}
