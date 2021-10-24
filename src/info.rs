use std::io::{stdout, Stdout};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::{
    cursor::{Hide, MoveUp, RestorePosition, SavePosition, Show},
    execute,
    terminal::ScrollUp,
    ExecutableCommand,
};
use serde_json as json;

use crate::opt::Opt;

macro_rules! handle_err {
    ($result:expr) => {
        if let Err(_) = $result {
            println!("Could not control terminal, no output will be provided.");
            return;
        }
    };
}

#[derive(Debug)]
pub struct InfoData {
    pub counter: AtomicU64,
    pub found_passwords: Mutex<Vec<String>>,
    pub recent_password: Mutex<String>,
}

impl InfoData {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            counter: AtomicU64::new(0),
            found_passwords: Mutex::new(vec![]),
            recent_password: Mutex::new(String::from("-")),
        })
    }
}

pub fn restore_terminal(stdout: &mut Stdout) {
    handle_err!(execute!(stdout, Show, ScrollUp(NUM_STATUS_LINES)));
}

fn final_stats(data: Arc<InfoData>) {
    println!(
        "Total passwords tried: {}",
        data.counter.load(Ordering::Relaxed)
    );
}

fn log(
    filename: &Path,
    counter: u64,
    found_passwords: &[String],
    recent_password: &str,
) -> Result<()> {
    let file = std::fs::File::create(filename)?;
    let writer = std::io::BufWriter::new(file);
    let value = json::json!({
        "counter": counter,
        "found_passwords": found_passwords,
        "recent_password": recent_password
    });
    json::to_writer_pretty(writer, &value)?;
    Ok(())
}

const NUM_STATUS_LINES: u16 = 2;
pub fn spawn_info_thread(opt: Opt, data: Arc<InfoData>) -> thread::JoinHandle<()> {
    // We might have a duration of more than a second between loops, so it's best to measure
    // the elapsed time to calculate the number of passwords per second.
    let start_time = Instant::now();
    let mut log_timer = Instant::now();
    let mut last_counter = data.counter.load(Ordering::Relaxed);
    let mut stdout = stdout();
    thread::spawn(move || {
        handle_err!(execute!(
            stdout,
            ScrollUp(NUM_STATUS_LINES),
            MoveUp(NUM_STATUS_LINES),
            Hide
        ));
        loop {
            handle_err!(stdout.execute(SavePosition));
            thread::sleep(Duration::from_millis(100));
            let time_elapsed = start_time.elapsed().as_secs_f64();
            let cur_counter = data.counter.load(Ordering::Relaxed);
            if cur_counter == last_counter {
                break;
            }
            last_counter = cur_counter;

            let password_rate = (cur_counter / 1_000_000) as f64 / time_elapsed;
            let found_passwords = data.found_passwords.lock().unwrap();
            let recent_password = data.recent_password.lock().unwrap();
            println!(
                "Speed: {:>5.2}M passwords/s, total: {}M",
                password_rate,
                cur_counter / 1_000_000
            );
            println!("Latest password: {}", recent_password);
            print!("Found passwords: {:?}", found_passwords);

            if log_timer.elapsed() > Duration::from_secs(60) {
                log_timer = Instant::now();
                if let Err(e) = log(
                    &opt.logfile,
                    cur_counter,
                    &found_passwords,
                    &recent_password,
                ) {
                    restore_terminal(&mut stdout);
                    eprintln!("Error writing logfile: {}", e);
                    return;
                }
            }
            handle_err!(stdout.execute(RestorePosition));
        }
        restore_terminal(&mut stdout);
        final_stats(data);
    })
}

pub fn run_with_info_thread(opt: Opt, f: impl FnOnce(Opt, Arc<InfoData>)) {
    let info_data = InfoData::new();
    let join_handle = spawn_info_thread(opt.clone(), info_data.clone());
    f(opt, info_data);
    // The thread should terminate when it notices that the counter doesn't increment any more.
    if let Err(e) = join_handle.join() {
        std::panic::resume_unwind(e);
    }
}
