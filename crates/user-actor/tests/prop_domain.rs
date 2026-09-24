//! Property tests for the user-actor domain: named-key virtual-key mapping
//! stays in the Win32 ranges the adapters rely on, and the focus dedup
//! contract holds for arbitrary snapshots.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use proptest::prelude::*;
use user_actor::{
    domain::FocusDedup,
    ports::driven::Key,
};

fn focus_snapshot(pid: u32, title: &str) -> user_actor::domain::FocusInfo {
    user_actor::domain::FocusInfo { pid, title: title.to_owned(), process: None }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Letter/digit keys map into the Win32 VK ranges (A–Z = 0x41..=0x5A,
    /// 0–9 = 0x30..=0x39); modifiers hit their documented codes.
    #[test]
    fn letter_and_digit_keys_map_into_vk_ranges(
        letter in any::<char>().prop_filter("ascii letter", char::is_ascii_alphabetic),
        digit in 0_u8..10,
    ) {
        let letter_vk = Key::Letter(letter).virtual_key();
        prop_assert!((0x41..=0x5A).contains(&letter_vk), "letter {letter} -> {letter_vk:#x}");
        let digit_vk = Key::Digit(digit).virtual_key();
        prop_assert!((0x30..=0x39).contains(&digit_vk), "digit {digit} -> {digit_vk:#x}");
    }

    /// Named modifiers are stable — chords depend on these exact codes.
    #[test]
    fn modifier_keys_map_exactly(win_is_left in any::<bool>()) {
        prop_assert_eq!(Key::Win.virtual_key(), 0x5B);
        prop_assert_eq!(Key::Ctrl.virtual_key(), 0x11);
        prop_assert_eq!(Key::Shift.virtual_key(), 0x10);
        prop_assert_eq!(Key::Alt.virtual_key(), 0x12);
        prop_assert_eq!(Key::Enter.virtual_key(), 0x0D);
        prop_assert_eq!(Key::Escape.virtual_key(), 0x1B);
        prop_assert_eq!(Key::Tab.virtual_key(), 0x09);
        prop_assert_eq!(Key::Space.virtual_key(), 0x20);
        prop_assert_eq!(Key::Backspace.virtual_key(), 0x08);
        prop_assert_eq!(Key::Add.virtual_key(), 0x6B);
        prop_assert_eq!(Key::Subtract.virtual_key(), 0x6D);
        prop_assert_eq!(Key::Multiply.virtual_key(), 0x6A);
        prop_assert_eq!(Key::Divide.virtual_key(), 0x6F);
        prop_assert_eq!(Key::Decimal.virtual_key(), 0x6E);
        prop_assert_eq!(Key::Raw(0xFF).virtual_key(), 0xFF);
        let _ = win_is_left;
    }

    /// Dedup: the first sight of a snapshot reports it; immediate repeats
    /// are suppressed; any field change reports again.
    #[test]
    fn focus_dedup_contract(
        pid in any::<u32>(),
        title in "[a-zA-Z0-9 ]{0,30}",
        other_pid in any::<u32>(),
        other_title in "[a-zA-Z0-9 ]{0,30}",
    ) {
        let first = focus_snapshot(pid, &title);
        let second = focus_snapshot(other_pid, &other_title);
        let mut dedup = FocusDedup::default();

        prop_assert_eq!(dedup.changed(first.clone()), Some(first.clone()));
        prop_assert_eq!(dedup.changed(first.clone()), None, "repeat must be suppressed");

        let changed = second != first;
        prop_assert_eq!(
            dedup.changed(second.clone()).is_some(),
            changed,
            "a distinct snapshot always reports"
        );
        // And the dedup now tracks the second snapshot.
        prop_assert_eq!(dedup.changed(second.clone()), None);
    }
}
