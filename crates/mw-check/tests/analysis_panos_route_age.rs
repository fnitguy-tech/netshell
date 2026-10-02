//! PAN-OS routing-table age.
//!
//! `show routing route` prints a fixed-width table whose age column ticks
//! every second. Two captures taken two minutes apart therefore disagree on
//! every BGP route while the route set is identical - 224 of 224 lines on one
//! firewall in a real window, which is enough evidence noise to hide a route
//! that actually moved.
//!
//! The rows below are real PAN-OS output: 138 columns, `age` starting at 102
//! and `interface` at 108, so the age column is six wide.

use mw_check::analysis::normalize::{blank_panos_route_age, normalized_section};

#[rustfmt::skip]
const HEADER: &str = "destination                                 nexthop                                 metric flags      age   interface          next-AS    ";

/// A connected route: no age, no next-AS.
#[rustfmt::skip]
const CONNECTED: &str = "10.11.16.0/24                               10.11.16.1                              0      A C              tunnel.511                    ";

/// A BGP route with no age but a next-AS, which is also numeric.
#[rustfmt::skip]
const NO_AGE: &str = "10.0.0.0/8                                  10.2.1.1                                       A?B                                 4280000001 ";

/// A BGP route whose age fits the six-column span.
#[rustfmt::skip]
fn bgp_narrow(age: &str) -> String {
    format!("10.61.82.7/32                               10.2.1.1                                       A?B        {age}                     4280000001 ")
}

/// A BGP route whose seven-digit age overruns the span.
#[rustfmt::skip]
fn bgp_wide(age: &str) -> String {
    format!("10.100.2.251/32                             10.2.1.1                                       A?B        {age}                  4280000001 ")
}

fn section(age_narrow: &str, age_wide: &str) -> Vec<String> {
    vec![
        "VIRTUAL ROUTER: default (id 1)".to_string(),
        "  ==========".to_string(),
        HEADER.to_string(),
        CONNECTED.to_string(),
        bgp_narrow(age_narrow),
        bgp_wide(age_wide),
        "total routes shown: 3".to_string(),
    ]
}

#[test]
fn age_column_is_blanked_so_a_static_table_compares_equal() {
    let pre = normalized_section("show routing route", &section("2724", "2666471"));
    let post = normalized_section("show routing route", &section("2849", "2666596"));

    assert_eq!(pre, post);
}

#[test]
fn a_wide_age_does_not_leave_its_last_digits_behind() {
    // A 7-digit age overruns the header's 6-column "age" span, so slicing a
    // fixed width leaves a digit behind and the line still differs.
    let blanked = blank_panos_route_age(&section("2724", "2666471")).join("\n");

    assert!(!blanked.contains("2666471"));
    assert!(!blanked.contains("2724"));
}

#[test]
fn next_as_survives_a_blank_age() {
    // next-AS is numeric too. On a route with no age, the blanker must not
    // reach past the age column and erase it.
    let blanked = blank_panos_route_age(&[
        "VIRTUAL ROUTER: default (id 1)".to_string(),
        HEADER.to_string(),
        NO_AGE.to_string(),
    ]);

    assert!(blanked.last().unwrap().contains("4280000001"));
}

#[test]
fn a_route_that_really_moved_still_shows() {
    let mut moved = section("2724", "2666471");
    moved[4] = moved[4].replace("10.2.1.1", "10.2.1.5");

    let pre = normalized_section("show routing route", &section("2724", "2666471"));
    let post = normalized_section("show routing route", &moved);

    assert_ne!(pre, post);
    assert!(post.iter().any(|line| line.contains("10.2.1.5")));
}

#[test]
fn lines_before_any_header_are_untouched() {
    let lines: Vec<String> = [
        "flags: A:active, ?:loose, C:connect",
        "  ",
        "VIRTUAL ROUTER: management (id 4)",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    assert_eq!(blank_panos_route_age(&lines), lines);
}
