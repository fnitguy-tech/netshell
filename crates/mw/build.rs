//! Embeds the icon and version resource into the Windows executable.
//! On every other platform this does nothing; the resource compiler
//! (rc.exe) ships with the MSVC toolchain the Windows builds use.

fn main() {
    println!("cargo:rerun-if-changed=assets/mw.ico");

    #[cfg(windows)]
    {
        let mut resource = winresource::WindowsResource::new();
        resource.set_icon("assets/mw.ico");
        resource.set("ProductName", "mw");
        resource.set("FileDescription", "Maintenance window check: capture device state before and after a change, report what changed");
        resource.compile().expect("compile the Windows resource");
    }
}
