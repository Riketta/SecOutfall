//! Scheduler adapter tests: deadline emission and keepalive heartbeat, both on
//! tokio's pausable clock so they run in microseconds.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    sync::{
        Arc,
        atomic::AtomicU64,
    },
    time::Duration,
};

use agent::{
    adapters::{
        driven::{
            broker::fake::FakeBroker,
            clock::fake::FakeClock,
        },
        driving::scheduler::SchedulerAdapter,
    },
    app::event::SandboxEvent,
    domain::scope::{
        ScopeState,
        SessionRecord,
        SharedScopeState,
    },
    ports::{
        driven::{
            broker::Channel,
            clock::SystemClockPort,
        },
        driving::event_source::EventSourcePort,
    },
};
use kernel::app::api_ports::EventInletPort;
use protocol::events::EventType;

/// Records every event the scheduler injects.
#[derive(Default)]
struct RecordingInlet {
    events: parking_lot::Mutex<Vec<SandboxEvent>>,
}

impl RecordingInlet {
    fn snapshot(&self) -> Vec<SandboxEvent> {
        self.events.lock().clone()
    }
}

#[async_trait::async_trait]
impl EventInletPort<SandboxEvent> for RecordingInlet {
    async fn accept(&self, event: SandboxEvent) {
        self.events.lock().push(event);
    }
}

fn open_session_state(scheduled: Option<u64>) -> SharedScopeState {
    Arc::new(parking_lot::Mutex::new(ScopeState {
        study_id: uuid::Uuid::from_u128(7),
        sessions: vec![SessionRecord {
            id: 0,
            scheduled_duration_secs: scheduled,
            started_at_ms: 0,
            ended_at_ms: None,
            abandoned: false,
            scoped_processes: Vec::new(),
            observed_drops: std::collections::BTreeSet::default(),
        }],
    }))
}

fn adapter(
    state: SharedScopeState,
    seq: &Arc<AtomicU64>,
    broker: &Arc<FakeBroker>,
    clock: &Arc<FakeClock>,
) -> Arc<SchedulerAdapter> {
    Arc::new(SchedulerAdapter::new(
        state,
        Arc::clone(clock) as Arc<dyn SystemClockPort>,
        Arc::clone(broker) as Arc<dyn agent::ports::driven::broker::BrokerPort>,
        Arc::clone(seq),
    ))
}

#[tokio::test(start_paused = true)]
async fn deadline_fires_after_scheduled_uptime() {
    let state = open_session_state(Some(2));
    let clock = Arc::new(FakeClock::new(0));
    let broker = Arc::new(FakeBroker::default());
    let seq = Arc::new(AtomicU64::new(0));
    let inlet = Arc::new(RecordingInlet::default());
    let sched = Arc::new(adapter(Arc::clone(&state), &seq, &broker, &clock));

    let task_sched = Arc::clone(&sched);
    let run_inlet: Arc<dyn EventInletPort<SandboxEvent>> = inlet.clone();
    let handle = tokio::spawn(async move { task_sched.run(run_inlet).await });

    // Let the spawned task enter its sleep BEFORE advancing paused time.
    tokio::task::yield_now().await;
    // Deadline is 2 simulated seconds out.
    tokio::time::advance(Duration::from_secs(2)).await;
    tokio::time::sleep(Duration::from_millis(1)).await;
    let deadlines = inlet
        .snapshot()
        .into_iter()
        .filter(|event| matches!(event, SandboxEvent::SessionDeadline))
        .count();
    assert_eq!(deadlines, 1, "deadline fires exactly once");
    sched.stop();
    let _ = tokio::time::timeout(Duration::from_millis(1), handle).await;
}

#[tokio::test(start_paused = true)]
async fn keepalive_published_every_15s_on_control_channel() {
    let state = open_session_state(None); // dynamic: no deadline, keepalive only
    let clock = Arc::new(FakeClock::new(0));
    let broker = Arc::new(FakeBroker::default());
    let seq = Arc::new(AtomicU64::new(0));
    let sched = Arc::new(adapter(state, &seq, &broker, &clock));
    let inlet: Arc<dyn EventInletPort<SandboxEvent>> = Arc::new(RecordingInlet::default());
    let run_inlet = inlet.clone();
    let task_sched = Arc::clone(&sched);
    let handle = tokio::spawn(async move { task_sched.run(run_inlet).await });

    for _ in 0..3 {
        tokio::time::advance(Duration::from_secs(15)).await;
        tokio::task::yield_now().await;
    }
    sched.stop();
    let _ = tokio::time::timeout(Duration::from_millis(1), handle).await;

    let keepalives = broker
        .of_channel(Channel::Control)
        .into_iter()
        .filter(|envelope| envelope.event_type == EventType::ControlKeepalive)
        .count();
    assert_eq!(keepalives, 3, "one keepalive per 15s tick");
}

#[tokio::test(start_paused = true)]
async fn dynamic_session_never_fires_a_deadline() {
    let state = open_session_state(None);
    let clock = Arc::new(FakeClock::new(0));
    let broker = Arc::new(FakeBroker::default());
    let seq = Arc::new(AtomicU64::new(0));
    let inlet = Arc::new(RecordingInlet::default());
    let sched = Arc::new(adapter(state, &seq, &broker, &clock));
    let run_inlet: Arc<dyn EventInletPort<SandboxEvent>> = inlet.clone();
    let task_sched = Arc::clone(&sched);
    let handle = tokio::spawn(async move { task_sched.run(run_inlet).await });

    tokio::time::advance(Duration::from_secs(24 * 3600)).await;
    tokio::time::sleep(Duration::from_millis(1)).await;
    let deadlines = inlet
        .snapshot()
        .into_iter()
        .filter(|event| matches!(event, SandboxEvent::SessionDeadline))
        .count();
    assert_eq!(deadlines, 0, "dynamic mode has no scheduled deadline");
    sched.stop();
    let _ = tokio::time::timeout(Duration::from_millis(1), handle).await;
}

#[tokio::test(start_paused = true)]
async fn zero_scheduled_duration_deadlines_immediately_once() {
    // A malformed/hostile `uptimes = [0]` entry degrades to "deadline on the
    // first tick" — never a panic, never a busy loop of deadlines.
    let state = open_session_state(Some(0));
    let clock = Arc::new(FakeClock::new(0));
    let broker = Arc::new(FakeBroker::default());
    let seq = Arc::new(AtomicU64::new(0));
    let inlet = Arc::new(RecordingInlet::default());
    let sched = Arc::new(adapter(state, &seq, &broker, &clock));
    let run_inlet: Arc<dyn EventInletPort<SandboxEvent>> = inlet.clone();
    let task_sched = Arc::clone(&sched);
    let handle = tokio::spawn(async move { task_sched.run(run_inlet).await });

    tokio::time::advance(Duration::from_secs(5)).await;
    tokio::time::sleep(Duration::from_millis(1)).await;
    let deadlines = inlet
        .snapshot()
        .into_iter()
        .filter(|event| matches!(event, SandboxEvent::SessionDeadline))
        .count();
    assert_eq!(deadlines, 1, "zero duration fires once, not in a loop");
    sched.stop();
    let _ = tokio::time::timeout(Duration::from_millis(1), handle).await;
}
