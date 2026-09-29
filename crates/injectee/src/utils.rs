use windows::{Win32::UI::WindowsAndMessaging::MessageBoxA, core::PCSTR};

use crate::TITLE;

pub(crate) fn message_box(message: &str) {
    unsafe {
        MessageBoxA(None, PCSTR(message.as_ptr()), TITLE, Default::default());
    };
}
