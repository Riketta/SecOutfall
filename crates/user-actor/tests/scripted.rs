//! Scripted-activities framework tests: config gating, step execution order,
//! pause/resume/stop semantics, and launch-failure tolerance. All against
//! fakes on the paused-clock runtime — a full script pass runs in virtual
//! microseconds.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    sync::{
        Arc,
        atomic::Ordering,
    },
    time::Duration,
};

use kernel::app::plugin_ports::middleware_plugin_port::MiddlewarePluginPort as _;
use tokio::sync::watch;
use user_actor::{
    adapters::{
        app_launcher_fake::{
            FakeAppLauncher,
            RecordedLaunch,
        },
        input_fake::{
            FakeInput,
            RecordedInput,
        },
    },
    plugins::{
        activities::{
            ActivityEnv,
            ScriptedActivity,
            calc_script,
            explorer_script,
            notepad_script,
        },
        scripted::{
            ActivityPort,
            ScriptedRunnerDeps,
            ScriptedRunnerPlugin,
        },
    },
    ports::Key,
};

/// Await a watch count reaching `threshold`; panic with context on stall.
async fn await_count(rx: &mut watch::Receiver<usize>, threshold: usize, what: &str) {
    loop {
        if *rx.borrow() >= threshold {
            return;
        }
        // Generous virtual budget: the activity loop ticks every 50 ms of
        // paused time, so progress long precedes this deadline. A closed
        // channel counts as a stall too.
        match tokio::time::timeout(Duration::from_secs(60), rx.changed()).await {
            Ok(Ok(())) => {}
            _ => panic!("{what}: count stuck at {} < {threshold}", *rx.borrow()),
        }
    }
}

fn env_pair() -> (Arc<FakeAppLauncher>, Arc<FakeInput>, ActivityEnv) {
    let launcher = Arc::new(FakeAppLauncher::default());
    let input = Arc::new(FakeInput::new());
    let env = ActivityEnv {
        launcher: Arc::clone(&launcher) as Arc<dyn user_actor::ports::AppLauncherPort>,
        input: Arc::clone(&input) as Arc<dyn user_actor::ports::InputSynthesisPort>,
    };
    (launcher, input, env)
}

/// Does `haystack` contain `needle` as an ordered (not necessarily
/// contiguous) subsequence?
fn contains_subsequence<T: PartialEq>(haystack: &[T], needle: &[T]) -> bool {
    if needle.is_empty() {
        return true;
    }
    let mut needle_iter = needle.iter();
    let Some(mut wanted) = needle_iter.next() else { return true };
    for item in haystack {
        if item == wanted {
            match needle_iter.next() {
                Some(next) => wanted = next,
                None => return true,
            }
        }
    }
    false
}

#[tokio::test(start_paused = true)]
async fn runner_starts_activities_only_when_scripted() {
    let (launcher, _input, env) = env_pair();
    let count_rx = launcher.count_rx();

    let runner = Arc::new(ScriptedRunnerPlugin::new(ScriptedRunnerDeps {
        activities: vec![
            ScriptedActivity::new("notepad", notepad_script(), env.clone()),
            ScriptedActivity::new("calc", calc_script(), env.clone()),
            ScriptedActivity::new("explorer", explorer_script(), env),
        ],
    }));

    // Simulate the config push with scripting disabled: nothing runs.
    let mut event = user_actor::domain::ActorEvent::Welcome(protocol::ipc::messages::Welcome {
        session_id: 1,
        config: protocol::config::UserActorConfig {
            scripted: false,
            ..protocol::config::UserActorConfig::default()
        },
    });
    let services =
        user_actor::domain::ActorServices { runtime: user_actor::domain::SharedRuntime::default() };
    runner.pre(&mut event, &services).await;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(launcher.launches().is_empty(), "scripted=false must not start activities");

    // Enable scripting: launches start flowing (activities loop on paused
    // time, so later passes may interleave — assert membership, not order).
    let mut event = user_actor::domain::ActorEvent::Welcome(protocol::ipc::messages::Welcome {
        session_id: 1,
        config: protocol::config::UserActorConfig {
            scripted: true,
            ..protocol::config::UserActorConfig::default()
        },
    });
    runner.pre(&mut event, &services).await;
    let mut count = count_rx;
    await_count(&mut count, 3, "activity launches").await;
    let expected = ["notepad.exe", "calc.exe", "explorer.exe"];
    for launch in launcher.launches() {
        assert!(
            expected.contains(&launch.program.as_str()),
            "unexpected program launched: {}",
            launch.program
        );
    }

    // Kernel shutdown stops the activities; the launches freeze.
    runner.stop_all();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let frozen = launcher.launches().len();
    tokio::time::sleep(Duration::from_secs(120)).await;
    assert_eq!(launcher.launches().len(), frozen, "no launches after stop");
}

#[tokio::test(start_paused = true)]
async fn notepad_activity_runs_script_steps_in_order() {
    let (launcher, input, env) = env_pair();
    let activity = ScriptedActivity::new("notepad", notepad_script(), env);
    let mut launch_count = launcher.count_rx();
    let mut action_count = input.count_rx();

    activity.start();
    await_count(&mut launch_count, 1, "notepad launch").await;
    // The script has three TypeText steps after the launch + waits.
    await_count(&mut action_count, 3, "three typed texts").await;
    activity.stop();

    let launch_log: Vec<RecordedLaunch> = launcher.launches();
    assert_eq!(launch_log.first().unwrap().program, "notepad.exe");
    assert!(launch_log.first().unwrap().args.is_empty());

    let recorded = input.actions();
    assert!(
        matches!(recorded.first(), Some(RecordedInput::Text(text)) if text.starts_with("Quarterly report draft"))
    );
    assert!(
        contains_subsequence(
            &recorded,
            &[
                RecordedInput::Text(
                    "Quarterly report draft\r\nThe numbers look reasonable this month.\r\n"
                        .to_owned()
                ),
                RecordedInput::Text(
                    "TODO: verify the export dialog remembers the last folder.\r\n".to_owned()
                ),
                RecordedInput::Text("Done for now.\r\n".to_owned()),
            ]
        ),
        "the three notes must be typed in script order; got {recorded:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn calc_activity_presses_its_sequence() {
    let (launcher, input, env) = env_pair();
    let activity = ScriptedActivity::new("calc", calc_script(), env);
    let mut launch_count = launcher.count_rx();
    let mut action_count = input.count_rx();

    activity.start();
    await_count(&mut launch_count, 1, "calc launch").await;
    // 13 Key steps in one pass.
    await_count(&mut action_count, 13, "calculator key presses").await;
    activity.stop();

    let recorded = input.actions();
    let keys: Vec<Key> = recorded
        .iter()
        .filter_map(|action| match action {
            RecordedInput::KeyPress(key) => Some(*key),
            _ => None,
        })
        .collect();
    assert!(
        contains_subsequence(
            &keys,
            &[
                Key::Digit(1),
                Key::Digit(2),
                Key::Add,
                Key::Digit(3),
                Key::Digit(0),
                Key::Enter,
                Key::Multiply,
                Key::Digit(2),
                Key::Enter,
            ]
        ),
        "calculator sequence must hold; got {keys:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn explorer_activity_opens_and_navigates() {
    let (launcher, input, env) = env_pair();
    let activity = ScriptedActivity::new("explorer", explorer_script(), env);
    let mut action_count = input.count_rx();

    activity.start();
    await_count(&mut action_count, 6, "explorer actions").await;
    activity.stop();

    // Win+E opens the window (no explicit launch — the OS handles it).
    assert!(launcher.launches().is_empty(), "explorer uses the hotkey, not a launch");
    let recorded = input.actions();
    assert!(
        matches!(recorded.first(), Some(RecordedInput::Hotkey(keys))
            if keys.as_slice() == [Key::Win, Key::Letter('E')]),
        "first action must be Win+E; got {:?}",
        recorded.first()
    );
    let typed: Vec<String> = recorded
        .iter()
        .filter_map(|action| match action {
            RecordedInput::Text(text) => Some(text.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        typed,
        vec!["C:\\Users\\Public\\Documents".to_owned(), "C:\\Windows\\Temp".to_owned()],
        "both paths typed via the address bar"
    );
}

#[tokio::test(start_paused = true)]
async fn pause_freezes_and_resume_continues() {
    let (launcher, input, env) = env_pair();
    let activity = ScriptedActivity::new("notepad", notepad_script(), env);
    let mut launch_count = launcher.count_rx();
    let mut action_count = input.count_rx();

    activity.start();
    await_count(&mut launch_count, 1, "notepad launch").await;
    await_count(&mut action_count, 1, "first typed text").await;

    activity.pause();
    let frozen = input.actions().len();
    // Several virtual seconds must not advance a paused script.
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    assert_eq!(input.actions().len(), frozen, "paused activity must not act");

    activity.resume();
    await_count(&mut action_count, frozen + 1, "progress after resume").await;
    activity.stop();
}

#[tokio::test(start_paused = true)]
async fn launch_failure_aborts_the_pass_but_the_loop_survives() {
    let (launcher, input, env) = env_pair();
    launcher.fail_launches.store(true, Ordering::SeqCst);
    let activity = ScriptedActivity::new("notepad", notepad_script(), env);
    let mut launch_count = launcher.count_rx();
    let mut action_count = input.count_rx();

    activity.start();
    // A few failed passes: no launch, no typing.
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    assert!(launcher.launches().is_empty());
    assert!(input.actions().is_empty(), "no typing without the app");

    // The transport heals: the next pass launches and types.
    launcher.fail_launches.store(false, Ordering::SeqCst);
    await_count(&mut launch_count, 1, "launch after recovery").await;
    await_count(&mut action_count, 1, "typing after recovery").await;
    activity.stop();
}
