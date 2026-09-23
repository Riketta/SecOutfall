//! `WinEvent` focus source: `SetWinEventHook` for
//! `EVENT_SYSTEM_FOREGROUND`/`EVENT_OBJECT_FOCUS` served by a dedicated
//! message-pump thread (out-of-context hooks require their own pump).
//!
//! The pump thread resolves windows and forwards snapshots over a
//! [`std::sync::mpsc`] channel; a tokio task bridges them into the kernel
//! inlet with deduplication.

use std::{
    cell::RefCell,
    sync::{
        Arc,
        mpsc::Sender,
    },
    time::Duration,
};

use kernel::app::api_ports::EventInletPort;
use tokio_util::sync::CancellationToken;
use windows::Win32::{
    Foundation::{
        HWND,
        LPARAM,
        WPARAM,
    },
    System::Threading::GetCurrentThreadId,
    UI::{
        Accessibility::{
            HWINEVENTHOOK,
            SetWinEventHook,
            UnhookWinEvent,
        },
        WindowsAndMessaging::{
            DispatchMessageW,
            EVENT_OBJECT_FOCUS,
            EVENT_SYSTEM_FOREGROUND,
            GetMessageW,
            MSG,
            OBJID_WINDOW,
            PostThreadMessageW,
            WINEVENT_OUTOFCONTEXT,
            WM_QUIT,
        },
    },
};

use crate::{
    adapters::focus_shared::resolve_window,
    domain::{
        ActorEvent,
        FocusDedup,
        FocusInfo,
    },
};

/// How long the stop path waits for the pump thread to drain (it returns from
/// `GetMessageW` on `WM_QUIT`).
const PUMP_JOIN_TIMEOUT: Duration = Duration::from_secs(2);

thread_local! {
    /// Out-of-context hooks carry no user context; the callback reads the
    /// sink from the hook's own thread. Set before the hook is installed.
    static PUMP_SINK: RefCell<Option<Sender<FocusInfo>>> = const { RefCell::new(None) };
}

/// WinEvent-hook focus adapter.
#[derive(Debug, Default)]
pub struct WinEventFocusAdapter {
    cancel: CancellationToken,
    /// Pump thread id, published by the thread itself at startup.
    pump_thread_id: Arc<std::sync::atomic::AtomicU32>,
}

impl WinEventFocusAdapter {
    /// Assemble the adapter.
    #[must_use]
    pub fn new(cancel: CancellationToken) -> Self {
        Self { cancel, pump_thread_id: Arc::new(std::sync::atomic::AtomicU32::new(0)) }
    }

    /// Ask the pump thread to quit (`WM_QUIT`); idempotent, safe before start.
    pub fn stop(&self) {
        self.cancel.cancel();
        let thread_id = self.pump_thread_id.load(std::sync::atomic::Ordering::SeqCst);
        if thread_id != 0 {
            // SAFETY: posting to the thread id we captured from the pump.
            let _ = unsafe { PostThreadMessageW(thread_id, WM_QUIT, WPARAM(0), LPARAM(0)) };
        }
    }

    /// Run the pump and forward deduplicated focus changes until
    /// [`stop`](Self::stop).
    ///
    /// # Errors
    /// [`FocusHookError::Hook`] when the hooks cannot be installed.
    pub async fn run(
        &self,
        inlet: Arc<dyn EventInletPort<ActorEvent>>,
    ) -> Result<(), FocusHookError> {
        let (wire_tx, wire_rx) = std::sync::mpsc::channel::<FocusInfo>();
        let thread_id = Arc::clone(&self.pump_thread_id);
        let pump = tokio::task::spawn_blocking(move || pump_thread(wire_tx, &thread_id));

        // std → tokio bridge: the std Receiver is !Send and must never be
        // held across an await; a blocking task pumps it into a tokio channel.
        let (tokio_tx, mut tokio_rx) = tokio::sync::mpsc::channel::<FocusInfo>(64);
        let bridge = tokio::task::spawn_blocking(move || {
            for focus in &wire_rx {
                if tokio_tx.blocking_send(focus).is_err() {
                    break;
                }
            }
        });

        let mut dedup = FocusDedup::default();
        while !pump.is_finished() {
            tokio::select! {
                biased;
                () = self.cancel.cancelled() => {
                    self.stop();
                    break;
                }
                focus = tokio_rx.recv() => match focus {
                    Some(focus) => {
                        if let Some(focus) = dedup.changed(focus) {
                            inlet.accept(ActorEvent::FocusChanged(focus)).await;
                        }
                    }
                    None => break,
                },
            }
        }

        self.stop();
        match tokio::time::timeout(PUMP_JOIN_TIMEOUT, pump).await {
            Ok(joined) => joined.map_err(|error| FocusHookError::Join(error.to_string()))??,
            // The pump is best-effort on shutdown; the process exits anyway.
            Err(_elapsed) => {
                tracing::warn!("win-event pump did not quit in time; abandoning it");
            }
        }
        bridge.await.map_err(|error| FocusHookError::Bridge(error.to_string()))?;
        Ok(())
    }
}

/// Pump failures.
#[derive(Debug, thiserror::Error)]
pub enum FocusHookError {
    /// `SetWinEventHook` refused (interactive desktop required).
    #[error("SetWinEventHook failed for event {0:#x}")]
    Hook(u32),
    /// The pump thread could not be joined.
    #[error("pump join failed: {0}")]
    Join(String),
    /// The std→tokio bridge task could not be joined.
    #[error("bridge join failed: {0}")]
    Bridge(String),
}

/// The dedicated message-pump thread: installs both hooks, publishes its
/// thread id, and dispatches messages until `WM_QUIT`.
fn pump_thread(
    sink: Sender<FocusInfo>,
    thread_id: &Arc<std::sync::atomic::AtomicU32>,
) -> Result<(), FocusHookError> {
    PUMP_SINK.with(|cell| *cell.borrow_mut() = Some(sink));

    // SAFETY: installing out-of-context hooks with our callback; both are
    // unhooked before this thread exits.
    let foreground_hook = unsafe {
        SetWinEventHook(
            EVENT_SYSTEM_FOREGROUND,
            EVENT_SYSTEM_FOREGROUND,
            None,
            Some(winevent_proc),
            0,
            0,
            WINEVENT_OUTOFCONTEXT,
        )
    };
    // SAFETY: as above, for keyboard focus within the foreground window.
    let focus_hook = unsafe {
        SetWinEventHook(
            EVENT_OBJECT_FOCUS,
            EVENT_OBJECT_FOCUS,
            None,
            Some(winevent_proc),
            0,
            0,
            WINEVENT_OUTOFCONTEXT,
        )
    };
    if foreground_hook.is_invalid() || focus_hook.is_invalid() {
        unhook(foreground_hook, focus_hook);
        return Err(FocusHookError::Hook(EVENT_SYSTEM_FOREGROUND));
    }

    thread_id.store(
        // SAFETY: no preconditions; returns the current thread id.
        unsafe { GetCurrentThreadId() },
        std::sync::atomic::Ordering::SeqCst,
    );

    let mut message = MSG::default();
    loop {
        // SAFETY: `message` is an initialized out-param; `None` hwnd pumps
        // this thread's whole queue. Returns 0 on WM_QUIT and -1 on error.
        let received = unsafe { GetMessageW(std::ptr::from_mut(&mut message), None, 0, 0) }.0;
        if received == 0 || received == -1 {
            break;
        }
        // SAFETY: paired with a successful GetMessageW above.
        unsafe { DispatchMessageW(std::ptr::from_ref(&message)) };
    }

    unhook(foreground_hook, focus_hook);
    PUMP_SINK.with(|cell| *cell.borrow_mut() = None);
    Ok(())
}

fn unhook(foreground_hook: HWINEVENTHOOK, focus_hook: HWINEVENTHOOK) {
    // SAFETY: both handles come from SetWinEventHook and are unhooked exactly
    // once (invalid handles are ignored by the API).
    unsafe {
        if !foreground_hook.is_invalid() {
            let _ = UnhookWinEvent(foreground_hook);
        }
        if !focus_hook.is_invalid() {
            let _ = UnhookWinEvent(focus_hook);
        }
    }
}

/// The out-of-context hook callback: resolves the window on the hook thread
/// and forwards the snapshot.
unsafe extern "system" fn winevent_proc(
    _hook: HWINEVENTHOOK,
    _event: u32,
    hwnd: HWND,
    id_object: i32,
    _id_child: i32,
    _thread: u32,
    _time_ms: u32,
) {
    // Only window-level events (OBJID_WINDOW); element focus is noise.
    if id_object != OBJID_WINDOW.0 || hwnd == HWND::default() {
        return;
    }
    let focus = resolve_window(hwnd);
    PUMP_SINK.with(|cell| {
        if let Some(sink) = cell.borrow().as_ref() {
            let _ = sink.send(focus);
        }
    });
}
