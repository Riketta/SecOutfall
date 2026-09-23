//! Walking skeleton: a plugin registers, the bus routes one event, the pipeline
//! delivers, and hooks run in the documented order (see root `AGENTS.md`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{
    Arc,
    Mutex,
};

use async_trait::async_trait;
use kernel::{
    app::{
        api_ports::EventInletPort,
        plugin_ports::{
            event_bus_port::EventBusPort,
            middleware_plugin_port::MiddlewarePluginPort,
            plugin_port::PluginPort,
        },
        services::kernel_service::KernelService,
    },
    bus::InMemoryEventBus,
    models::{
        KernelError,
        Next,
        PluginError,
    },
};

type Log = Arc<Mutex<Vec<String>>>;

#[derive(Debug, Clone, PartialEq, Eq)]
struct TestEvent(u8);

fn record(log: &Log, entry: String) {
    log.lock().unwrap().push(entry);
}

fn logged(log: &Log) -> Vec<String> {
    log.lock().unwrap().clone()
}

struct LifecyclePlugin {
    name: &'static str,
    fail_init: bool,
    fail_start: bool,
    log: Log,
}

impl LifecyclePlugin {
    fn new(name: &'static str, log: &Log) -> Self {
        Self { name, fail_init: false, fail_start: false, log: Arc::clone(log) }
    }
}

#[async_trait]
impl PluginPort for LifecyclePlugin {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn init(&self) -> Result<(), PluginError> {
        record(&self.log, format!("{}:init", self.name));
        if self.fail_init {
            return Err(PluginError::new(self.name, "init forced failure"));
        }
        Ok(())
    }

    async fn start(&self) -> Result<(), PluginError> {
        record(&self.log, format!("{}:start", self.name));
        if self.fail_start {
            return Err(PluginError::new(self.name, "start forced failure"));
        }
        Ok(())
    }

    async fn stop(&self) -> Result<(), PluginError> {
        record(&self.log, format!("{}:stop", self.name));
        Ok(())
    }
}

struct PipelinePlugin {
    name: &'static str,
    stop: bool,
    abort: bool,
    log: Log,
}

impl PipelinePlugin {
    fn continuing(name: &'static str, log: &Log) -> Self {
        Self { name, stop: false, abort: false, log: Arc::clone(log) }
    }

    fn stopping(name: &'static str, log: &Log) -> Self {
        Self { name, stop: true, abort: false, log: Arc::clone(log) }
    }

    fn aborting(name: &'static str, log: &Log) -> Self {
        Self { name, stop: false, abort: true, log: Arc::clone(log) }
    }
}

#[async_trait]
impl PluginPort for PipelinePlugin {
    fn name(&self) -> &'static str {
        self.name
    }
}

#[async_trait]
impl<E: Send, S: Sync> MiddlewarePluginPort<E, S> for PipelinePlugin {
    async fn pre(&self, _event: &mut E, _services: &S) -> Next {
        record(&self.log, format!("{}:pre", self.name));
        if self.abort {
            Next::Abort
        } else if self.stop {
            Next::Stop
        } else {
            Next::Continue
        }
    }

    async fn post(&self, _event: &mut E, _services: &S) {
        record(&self.log, format!("{}:post", self.name));
    }
}

fn pipeline(log: &Log) -> KernelService<TestEvent, (), InMemoryEventBus<TestEvent>> {
    KernelService::new(
        Vec::new(),
        vec![
            Arc::new(PipelinePlugin::continuing("m1", log)),
            Arc::new(PipelinePlugin::continuing("m2", log)),
            Arc::new(PipelinePlugin::continuing("m3", log)),
        ],
        InMemoryEventBus::new(8),
        (),
    )
}

#[tokio::test]
async fn lifecycle_runs_init_all_then_start_all_and_stops_reversed() {
    let log: Log = Arc::default();
    let kernel = KernelService::<TestEvent, (), InMemoryEventBus<TestEvent>, TestEvent>::new(
        vec![Arc::new(LifecyclePlugin::new("a", &log)), Arc::new(LifecyclePlugin::new("b", &log))],
        Vec::new(),
        InMemoryEventBus::<TestEvent>::new(8),
        (),
    );

    kernel.boot().await.unwrap();
    kernel.shutdown().await;

    assert_eq!(logged(&log), vec!["a:init", "b:init", "a:start", "b:start", "b:stop", "a:stop"]);
}

#[tokio::test]
async fn boot_fails_on_first_init_error() {
    let log: Log = Arc::default();
    let mut failing = LifecyclePlugin::new("bad", &log);
    failing.fail_init = true;
    let kernel = KernelService::<TestEvent, (), InMemoryEventBus<TestEvent>, TestEvent>::new(
        vec![Arc::new(LifecyclePlugin::new("ok", &log)), Arc::new(failing)],
        Vec::new(),
        InMemoryEventBus::<TestEvent>::new(8),
        (),
    );

    let result = kernel.boot().await;

    assert!(matches!(result, Err(KernelError::Lifecycle { plugin: "bad", .. })));
    // The already-initialized plugin is rolled back in reverse.
    assert_eq!(logged(&log), vec!["ok:init", "bad:init", "ok:stop"]);
}

#[tokio::test]
async fn boot_failure_mid_start_rolls_back_everything_processed() {
    let log: Log = Arc::default();
    let mut failing = LifecyclePlugin::new("bad", &log);
    failing.fail_start = true;
    let kernel = KernelService::<TestEvent, (), InMemoryEventBus<TestEvent>, TestEvent>::new(
        vec![Arc::new(LifecyclePlugin::new("first", &log)), Arc::new(failing)],
        Vec::new(),
        InMemoryEventBus::<TestEvent>::new(8),
        (),
    );

    let result = kernel.boot().await;

    assert!(matches!(result, Err(KernelError::Lifecycle { plugin: "bad", .. })));
    // The started plugin AND the failing one (partial start may hold
    // resources only `stop` can release) are rolled back in reverse.
    assert_eq!(
        logged(&log),
        vec!["first:init", "bad:init", "first:start", "bad:start", "bad:stop", "first:stop"]
    );
}

#[tokio::test]
async fn full_chain_runs_all_pre_then_post_reversed() {
    let log: Log = Arc::default();
    pipeline(&log).accept(TestEvent(1)).await;

    assert_eq!(logged(&log), vec!["m1:pre", "m2:pre", "m3:pre", "m3:post", "m2:post", "m1:post"]);
}

#[tokio::test]
async fn stop_skips_remaining_pre_but_runs_post_of_ran_plugins() {
    let log: Log = Arc::default();
    let kernel = KernelService::<TestEvent, (), InMemoryEventBus<TestEvent>, TestEvent>::new(
        Vec::new(),
        vec![
            Arc::new(PipelinePlugin::continuing("m1", &log)),
            Arc::new(PipelinePlugin::stopping("m2", &log)),
            Arc::new(PipelinePlugin::continuing("m3", &log)),
        ],
        InMemoryEventBus::new(8),
        (),
    );

    kernel.accept(TestEvent(1)).await;

    assert_eq!(logged(&log), vec!["m1:pre", "m2:pre", "m2:post", "m1:post"]);
}

#[tokio::test]
async fn abort_skips_remaining_pre_and_all_post() {
    let log: Log = Arc::default();
    let kernel = KernelService::<TestEvent, (), InMemoryEventBus<TestEvent>, TestEvent>::new(
        Vec::new(),
        vec![
            Arc::new(PipelinePlugin::continuing("m1", &log)),
            Arc::new(PipelinePlugin::aborting("m2", &log)),
            Arc::new(PipelinePlugin::continuing("m3", &log)),
        ],
        InMemoryEventBus::new(8),
        (),
    );

    kernel.accept(TestEvent(1)).await;

    // m2's own pre ran (it returned Abort); m3's pre and every post are skipped.
    assert_eq!(logged(&log), vec!["m1:pre", "m2:pre"]);
}

#[tokio::test]
async fn bus_routes_one_event_to_all_subscribers() {
    let bus = InMemoryEventBus::<TestEvent>::new(8);
    let mut rx1 = bus.subscribe();
    let mut rx2 = bus.subscribe();

    let delivered = bus.publish(TestEvent(7));

    assert_eq!(delivered, 2);
    assert_eq!(rx1.try_recv().unwrap(), TestEvent(7));
    assert_eq!(rx2.try_recv().unwrap(), TestEvent(7));
}

#[tokio::test]
async fn publish_without_subscribers_reports_zero() {
    let bus = InMemoryEventBus::<TestEvent>::new(8);

    assert_eq!(bus.publish(TestEvent(1)), 0);
}

#[tokio::test]
async fn slow_subscriber_sees_lagged_not_a_panic() {
    // Capacity 1: two publishes without a recv lag the subscriber by one.
    // The overflow policy is explicit: the subscriber observes
    // `RecvError::Lagged` (counted loss), the publisher never blocks.
    let bus = InMemoryEventBus::<TestEvent>::new(1);
    let mut rx = bus.subscribe();

    bus.publish(TestEvent(1));
    bus.publish(TestEvent(2));

    let verdict = rx.recv().await;
    assert!(
        matches!(&verdict, Err(tokio::sync::broadcast::error::RecvError::Lagged(1))),
        "expected Lagged(1), got {verdict:?}"
    );
    // After the lag report the stream resumes with the newest event.
    assert_eq!(rx.recv().await.unwrap(), TestEvent(2));
}

#[tokio::test]
async fn zero_capacity_bus_clamps_to_one_instead_of_panicking() {
    let bus = InMemoryEventBus::<TestEvent>::new(0);
    let mut rx = bus.subscribe();

    assert_eq!(bus.publish(TestEvent(1)), 1);
    assert_eq!(rx.recv().await.unwrap(), TestEvent(1));
}

#[tokio::test]
async fn double_shutdown_stops_every_plugin_twice_idempotently() {
    // `stop` is contractually idempotent; the kernel passes every shutdown
    // through so plugins can rely on their own guards.
    let log: Log = Arc::default();
    let kernel = KernelService::<TestEvent, (), InMemoryEventBus<TestEvent>, TestEvent>::new(
        vec![Arc::new(LifecyclePlugin::new("a", &log))],
        Vec::new(),
        InMemoryEventBus::<TestEvent>::new(8),
        (),
    );
    kernel.boot().await.unwrap();

    kernel.shutdown().await;
    kernel.shutdown().await;

    assert_eq!(logged(&log), vec!["a:init", "a:start", "a:stop", "a:stop"]);
}

#[tokio::test]
async fn pipeline_without_middleware_is_a_no_op() {
    let kernel = KernelService::<TestEvent, (), InMemoryEventBus<TestEvent>, TestEvent>::new(
        Vec::new(),
        Vec::new(),
        InMemoryEventBus::<TestEvent>::new(8),
        (),
    );
    kernel.boot().await.unwrap();

    kernel.accept(TestEvent(1)).await; // must not panic
    kernel.shutdown().await;
}
