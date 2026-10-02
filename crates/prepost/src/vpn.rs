//! PAN-OS IPsec / IKE / LSVPN churn rule, shared by both compare views
//! so the text diff and the HTML report agree on what a tunnel change
//! looks like.
//!
//! The status rows carry tunnel identity (gateway name, peer address,
//! tunnel interface, state) next to values that move on every rekey or
//! capture: SPIs, lifetimes, message IDs, established/expiry
//! timestamps, satellite login times, byte and packet counters.

use std::sync::LazyLock;

use regex::Regex;

pub const VPN_SA_COMMANDS: &[&str] = &["show vpn ike-sa", "show vpn ipsec-sa"];

pub const VPN_SATELLITE_COMMANDS: &[&str] = &[
    "show global-protect-gateway current-satellite",
    "show global-protect-satellite current-gateway",
];

/// Hub gateway list. The built state (tunnel, pool, access routes,
/// certificate) is what a maintenance changes; the per-gateway
/// satellite counter moves whenever a satellite powers up or leaves,
/// which is normal operation, not a change we made.
pub const VPN_GATEWAY_COMMANDS: &[&str] = &["show global-protect-gateway gateway"];

pub const VPN_GATEWAY_COUNT_FIELDS: &[&str] = &[
    "number of satellites",
    "current satellites",
    "satellites connected",
    "active satellites",
];

/// LSVPN per-tunnel flow table on a hub: each row names the tunnel and
/// the satellite, then carries byte/packet counters that move every
/// second. Same shape as an SA row, so the SA rule handles it.
pub const VPN_FLOW_COMMANDS: &[&str] = &[
    "show global-protect-gateway flow-site-to-site",
    "show global-protect-gateway flow",
];

/// Tokens in an SA table row that change without the tunnel changing.
static VPN_CHURN_TOKENS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"^(0x)?[0-9a-fA-F]{8,}$",                    // SPI (hex, with or without 0x)
        r"^[A-Z][a-z]{2}\.\d{1,2}$",                  // date: Aug.31
        r"^\d{1,2}:\d{2}(:\d{2})?$",                  // time: 10:11:12
        r"^\d+(\.\d+)?(/\d+(\.\d+)?)?[A-Za-z]{0,2}$", // counters, 3450/28800, 1.2GB
        r"^\d+[hms](\d+[ms])*$",                      // 1h10m rekey countdown
    ]
    .iter()
    .map(|p| Regex::new(p).unwrap())
    .collect()
});

/// key: value lines in the LSVPN satellite/gateway output that only
/// record when the session started, not whether it is up.
pub const VPN_SATELLITE_NOISE: &[&str] = &[
    "login time",
    "logout time",
    "connect time",
    "uptime",
    "established",
    "expiration",
];

/// Every command the VPN rule knows about (for category counting).
pub fn vpn_commands() -> Vec<&'static str> {
    [
        VPN_SA_COMMANDS,
        VPN_SATELLITE_COMMANDS,
        VPN_FLOW_COMMANDS,
        VPN_GATEWAY_COMMANDS,
    ]
    .concat()
}

/// Apply the churn rule. `None` drops the line; for every command the
/// rule does not know, the line comes back unchanged, so callers can
/// apply it unconditionally.
pub fn normalize_vpn_line(command: &str, line: &str) -> Option<String> {
    if VPN_SA_COMMANDS.contains(&command) || VPN_FLOW_COMMANDS.contains(&command) {
        // "Total 1 gateways found. 1 ike sa found." is the SA count;
        // keep it whole so an SA vanishing is a visible diff.
        if line.contains("found") {
            return Some(line.to_string());
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            return Some(line.to_string());
        }

        // Never drop the first token: it is the gateway ID / gateway
        // name that identifies the row. IPv4 addresses never match the
        // counter pattern (three dots) so peers survive.
        let mut kept = vec![parts[0]];
        kept.extend(
            parts[1..]
                .iter()
                .copied()
                .filter(|part| !VPN_CHURN_TOKENS.iter().any(|re| re.is_match(part))),
        );
        return Some(kept.join(" "));
    }

    let lowered = line.trim().to_lowercase();

    if VPN_SATELLITE_COMMANDS.contains(&command) {
        if VPN_SATELLITE_NOISE.iter().any(|noise| lowered.starts_with(noise)) {
            return None;
        }
        return Some(line.to_string());
    }

    if VPN_GATEWAY_COMMANDS.contains(&command) {
        if VPN_GATEWAY_COUNT_FIELDS.iter().any(|field| lowered.starts_with(field)) {
            return None;
        }
        return Some(line.to_string());
    }

    Some(line.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sa_rows_keep_identity_and_drop_churn() {
        let line = "GW-SITE-B    198.51.100.7   0x1A2B3C4D   Aug.31   10:11:12   3450/28800   1h10m   active";
        assert_eq!(
            normalize_vpn_line("show vpn ike-sa", line).unwrap(),
            "GW-SITE-B 198.51.100.7 active"
        );
        assert_eq!(
            normalize_vpn_line("show vpn ipsec-sa", "Total 1 gateways found. 1 ike sa found.").unwrap(),
            "Total 1 gateways found. 1 ike sa found."
        );
    }

    #[test]
    fn satellite_and_gateway_noise_is_dropped() {
        assert!(
            normalize_vpn_line(
                "show global-protect-gateway current-satellite",
                "  Login Time: Aug.31 10:11"
            )
            .is_none()
        );
        assert_eq!(
            normalize_vpn_line("show global-protect-gateway current-satellite", "  Tunnel: tunnel.10").unwrap(),
            "  Tunnel: tunnel.10"
        );
        assert!(normalize_vpn_line("show global-protect-gateway gateway", "Number of satellites: 3").is_none());
    }

    #[test]
    fn other_commands_pass_through() {
        assert_eq!(
            normalize_vpn_line("show version", "Uptime: 3 days").unwrap(),
            "Uptime: 3 days"
        );
    }
}
