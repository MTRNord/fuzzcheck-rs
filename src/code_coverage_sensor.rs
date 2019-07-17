use crate::input_pool::*;
use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::slice;

type PC = usize;

pub static mut SHARED_SENSOR: MaybeUninit<CodeCoverageSensor> = MaybeUninit::<CodeCoverageSensor>::uninit();

pub fn shared_sensor() -> &'static mut CodeCoverageSensor {
    unsafe { &mut *SHARED_SENSOR.as_mut_ptr() }
}

static MAX_NUM_GUARDS: isize = 1 << 21;

#[derive(Clone)]
pub struct CodeCoverageSensor {
    pub num_guards: isize,
    pub is_recording: bool,
    pub eight_bit_counters: HashMap<usize, u16>,
    pub features: std::collections::HashSet<Feature>,
}

impl CodeCoverageSensor {
    pub fn handle_pc_guard_init(&mut self, start: *mut u32, stop: *mut u32) {
        if !(start != stop && unsafe { *start == 0 }) {
            return;
        }

        let dist = unsafe { stop.offset_from(start) as usize };
        let buffer = unsafe { slice::from_raw_parts_mut(start, dist) };
        for x in buffer.iter_mut() {
            self.num_guards += 1;
            assert!(self.num_guards < MAX_NUM_GUARDS);
            *x = self.num_guards as u32;
        }

        self.eight_bit_counters.clear();
    }

    pub fn handle_trace_cmp(&mut self, pc: PC, arg1: u64, arg2: u64) {
        let f = ComparisonFeature::new(pc, arg1, arg2);
        self.features.insert(Feature::Comparison(f));
    }
    pub fn handle_trace_indir(&mut self, caller: PC, callee: PC) {
        let f = IndirFeature { caller, callee };
        self.features.insert(Feature::Indir(f));
    }

    pub fn iterate_over_collected_features<F>(&mut self, mut handle: F)
    where
        F: FnMut(Feature) -> (),
    {
        for (i, x) in self.eight_bit_counters.iter() {
            let f = EdgeFeature::new(*i, *x);
            handle(Feature::Edge(f));
        }
        for f in self.features.iter() {
            handle(f.clone());
        }
    }

    pub fn clear(&mut self) {
        self.eight_bit_counters.clear();
        self.features.clear();
    }
}
