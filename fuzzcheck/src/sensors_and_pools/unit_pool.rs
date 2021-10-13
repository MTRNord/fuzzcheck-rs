use crate::fuzzer::PoolStorageIndex;
use crate::traits::{CompatibleWithSensor, CorpusDelta, EmptyStats, Pool, Sensor};

pub struct UnitPool {
    input_index: PoolStorageIndex,
    dead_end: bool,
}
impl UnitPool {
    #[no_coverage]
    pub(crate) fn new(input_index: PoolStorageIndex) -> Self {
        Self {
            input_index,
            dead_end: false,
        }
    }
}

impl Pool for UnitPool {
    type Stats = EmptyStats;
    #[no_coverage]
    fn stats(&self) -> Self::Stats {
        EmptyStats
    }

    #[no_coverage]
    fn len(&self) -> usize {
        1
    }
    #[no_coverage]
    fn get_random_index(&mut self) -> Option<PoolStorageIndex> {
        if self.dead_end {
            None
        } else {
            Some(self.input_index)
        }
    }
    #[no_coverage]
    fn mark_test_case_as_dead_end(&mut self, _idx: PoolStorageIndex) {
        self.dead_end = true
    }
    #[no_coverage]
    fn minify(
        &mut self,
        _target_len: usize,
        _event_handler: impl FnMut(CorpusDelta, Self::Stats) -> Result<(), std::io::Error>,
    ) -> Result<(), std::io::Error> {
        Ok(())
    }
}

impl<S: Sensor> CompatibleWithSensor<S> for UnitPool {
    #[no_coverage]
    fn process(&mut self, _input_id: PoolStorageIndex, _sensor: &mut S, _complexity: f64) -> Vec<CorpusDelta> {
        vec![]
    }
}
