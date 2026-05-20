use std::time::Duration;

use rand::Rng;

pub fn dummy_interval() -> Duration {
    let secs = rand::thread_rng().gen_range(3..=7);
    Duration::from_secs(secs)
}
