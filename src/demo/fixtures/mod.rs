//! The demo dataset's stored responses, one module per area (each owns its
//! services' paths; `docs/DEMO.md` has the table, the story and the ids).
//! Bodies are real ARM / Graph JSON with `{{prod}}` / `{{dev}}` /
//! `{{tenant}}` and `{{iso:now-15m}}` placeholders (`demo::render`).
//!
//! Order matters: the first fixture whose path matches and whose `when`
//! substrings all appear in the decoded query wins, so a narrow match goes
//! before its catch-all, and the areas are searched in [`AREAS`] order.

mod compute;
mod core;
mod data;
mod identity;
mod network;

pub struct Fixture {
    /// The request path: `*` matches any one segment; `{{prod}}` etc.
    pub path: &'static str,
    /// Substrings the decoded query must all contain (empty = any).
    pub when: &'static [&'static str],
    /// The HTTP status to answer with (200 unless the fixture says).
    pub status: u16,
    /// The file name, for the trace and the tests.
    pub file: &'static str,
    pub body: &'static str,
}

/// `fx!("area", "/path", "file.json")`, optionally with `when [..]` before
/// the file and `status N` first, from inside `fixtures/<area>.rs`: the
/// body is `fixtures/<area>/file.json`, embedded at build time.
#[allow(unused_macros)]
macro_rules! fx {
    ($area:literal, $path:literal, $file:literal) => {
        $crate::demo::fixtures::Fixture {
            path: $path,
            when: &[],
            status: 200,
            file: concat!($area, "/", $file),
            body: include_str!(concat!($area, "/", $file)),
        }
    };
    ($area:literal, $path:literal, when [$($w:literal),+ $(,)?], $file:literal) => {
        $crate::demo::fixtures::Fixture {
            path: $path,
            when: &[$($w),+],
            status: 200,
            file: concat!($area, "/", $file),
            body: include_str!(concat!($area, "/", $file)),
        }
    };
    (status $status:literal, $area:literal, $path:literal, $file:literal) => {
        $crate::demo::fixtures::Fixture {
            path: $path,
            when: &[],
            status: $status,
            file: concat!($area, "/", $file),
            body: include_str!(concat!($area, "/", $file)),
        }
    };
}
#[allow(unused_imports)]
pub(crate) use fx;

/// Every area, in lookup order.
pub static AREAS: &[&[Fixture]] = &[
    core::FIXTURES,
    network::FIXTURES,
    compute::FIXTURES,
    data::FIXTURES,
    identity::FIXTURES,
];
