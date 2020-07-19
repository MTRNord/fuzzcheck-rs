use crate::HasDefaultMutator;
use fastrand::Rng;
use fuzzcheck_traits::Mutator;

use std::iter::repeat;
use std::ops::Range;

#[derive(Default)]
pub struct VecMutator<M: Mutator> {
    pub rng: Rng,
    pub m: M,
}
impl<T> HasDefaultMutator for Vec<T>
where
    T: HasDefaultMutator,
{
    type Mutator = VecMutator<<T as HasDefaultMutator>::Mutator>;
    fn default_mutator() -> Self::Mutator {
        Self::Mutator::default()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MutationCategory {
    Element,
    Vector,
}

#[derive(Clone)]
pub struct MutationStep<S> {
    inner: Vec<S>,
    element_step: usize,
    vector_step: usize,
    category: MutationCategory,
}
impl<S> MutationStep<S> {
    fn new(category: MutationCategory) -> Self {
        Self {
            inner: Vec::new(),
            element_step: 0,
            vector_step: 0,
            category,
        }
    }
}

impl<S> MutationStep<S> {
    fn increment_element(&mut self) {
        self.element_step += 1;
        if self.element_step % 50 == 0 {
            self.category = MutationCategory::Vector;
        }
    }
    fn increment_vector(&mut self) {
        self.vector_step += 1;
        if self.vector_step % 5 == 0 && !self.inner.is_empty() {
            self.category = MutationCategory::Element;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VecOperation {
    Remove,
    Insert,
    RemoveMany,
    InsertRepeated,
    // Arbitrary,
}
impl VecOperation {
    fn from_step(step: usize) -> Self {
        match step % 4 {
            0 => Self::Remove,
            1 => Self::Insert,
            2 => Self::RemoveMany,
            3 => Self::InsertRepeated,
            _ => unreachable!(),
        }
    }
}

#[derive(Clone)]
pub struct VecMutatorCache<C> {
    inner: Vec<C>,
    sum_cplx: f64,
}
impl<C> Default for VecMutatorCache<C> {
    fn default() -> Self {
        Self {
            inner: Vec::new(),
            sum_cplx: 0.0,
        }
    }
}

pub enum UnmutateVecToken<M: Mutator> {
    Element(usize, M::UnmutateToken, f64),
    Remove(usize, f64),
    RemoveMany(Range<usize>, f64),
    Insert(usize, M::Value, M::Cache),
    InsertMany(
        usize,
        <VecMutator<M> as Mutator>::Value,
        <VecMutator<M> as Mutator>::Cache,
    ),
    Replace(<VecMutator<M> as Mutator>::Value, <VecMutator<M> as Mutator>::Cache),
    Nothing,
}

impl<M: Mutator> VecMutator<M> {
    fn mutate_element(
        &mut self,
        value: &mut Vec<M::Value>,
        cache: &mut VecMutatorCache<M::Cache>,
        step: &mut MutationStep<M::MutationStep>,
        idx: usize,
        spare_cplx: f64,
    ) -> UnmutateVecToken<M> {
        let el = &mut value[idx];
        let el_cache = &mut cache.inner[idx];
        let el_step = &mut step.inner[idx];

        let old_cplx = self.m.complexity(el, el_cache);

        let token = self.m.mutate(el, el_cache, el_step, spare_cplx);

        let new_cplx = self.m.complexity(el, el_cache);

        cache.sum_cplx += new_cplx - old_cplx;

        UnmutateVecToken::Element(idx, token, old_cplx - new_cplx)
    }

    fn insert_element(
        &mut self,
        value: &mut Vec<M::Value>,
        cache: &mut VecMutatorCache<M::Cache>,
        spare_cplx: f64,
    ) -> UnmutateVecToken<M> {
        let idx = if value.is_empty() {
            0
        } else {
            self.rng.usize(0..value.len())
        };

        let (el, el_cache) = self.m.arbitrary(self.rng.usize(..), spare_cplx);
        let el_cplx = self.m.complexity(&el, &el_cache);

        value.insert(idx, el);
        cache.inner.insert(idx, el_cache);

        let token = UnmutateVecToken::Remove(idx, el_cplx);

        cache.sum_cplx += el_cplx;

        token
    }

    fn remove_element(
        &mut self,
        value: &mut Vec<M::Value>,
        cache: &mut VecMutatorCache<M::Cache>,
    ) -> UnmutateVecToken<M> {
        if value.is_empty() {
            return UnmutateVecToken::Nothing;
        }

        let idx = self.rng.usize(0..value.len());

        let el = &value[idx];
        let el_cplx = self.m.complexity(&el, &cache.inner[idx]);

        let removed_el = value.remove(idx);
        let removed_el_cache = cache.inner.remove(idx);

        let token = UnmutateVecToken::Insert(idx, removed_el, removed_el_cache);

        cache.sum_cplx -= el_cplx;

        token
    }

    fn remove_many_elements(
        &mut self,
        value: &mut Vec<M::Value>,
        cache: &mut VecMutatorCache<M::Cache>,
    ) -> UnmutateVecToken<M> {
        if value.is_empty() {
            return UnmutateVecToken::Nothing;
        }
        let start_idx = self.rng.usize(0..value.len());

        let end_idx = 1 + self.rng.usize(start_idx..value.len());
        let (removed_elements, removed_cache) = {
            let removed_elements: Vec<_> = value.drain(start_idx..end_idx).collect();
            let removed_cache: Vec<_> = cache.inner.drain(start_idx..end_idx).collect();
            (removed_elements, removed_cache)
        };
        let removed_els_cplx = removed_elements
            .iter()
            .zip(removed_cache.iter())
            .fold(0.0, |cplx, (v, c)| self.m.complexity(&v, &c) + cplx);

        let removed_cache = VecMutatorCache {
            inner: removed_cache,
            sum_cplx: removed_els_cplx,
        };

        let token = UnmutateVecToken::InsertMany(start_idx, removed_elements, removed_cache);

        cache.sum_cplx -= removed_els_cplx;

        token
    }

    fn insert_repeated_elements(
        &mut self,
        value: &mut Vec<M::Value>,
        cache: &mut VecMutatorCache<M::Cache>,
        spare_cplx: f64,
    ) -> UnmutateVecToken<M> {
        if spare_cplx < 0.01 {
            return UnmutateVecToken::Nothing;
        }

        let idx = if value.is_empty() {
            0
        } else {
            self.rng.usize(0..value.len())
        };

        let target_cplx = crate::gen_f64(&self.rng, 0.0..spare_cplx);
        let (min_length, max_length) = self.choose_slice_length(target_cplx);
        let min_length = min_length.unwrap_or(0);

        let len = if min_length >= max_length {
            min_length
        } else {
            self.rng.usize(min_length..max_length)
        };
        if len == 0 {
            // TODO: maybe that shouldn't happen under normal circumstances?
            return UnmutateVecToken::Nothing;
        }
        // println!("len: {:.2}", len);
        // println!("max_cplx: {:.2}", target_cplx / (len as f64));
        let (el, el_cache) = self.m.arbitrary(self.rng.usize(..), target_cplx / (len as f64));
        let el_cplx = self.m.complexity(&el, &el_cache);

        insert_many(value, idx, repeat(el).take(len));
        insert_many(&mut cache.inner, idx, repeat(el_cache).take(len));

        let added_cplx = el_cplx * (len as f64);
        cache.sum_cplx += added_cplx;

        let token = UnmutateVecToken::RemoveMany(idx..(idx + len), added_cplx);

        token
    }

    // fn mutate_arbitrary(
    //     &mut self,
    //     value: &mut Vec<M::Value>,
    //     cache: &mut VecMutatorCache<M::Cache>,
    //     step: &mut VecMutatorStep<M::MutationStep>,
    //     max_cplx: f64,
    // ) -> UnmutateVecToken<M> {
    //     let (mut tmp_value, mut tmp_cache) = self.arbitrary(step.pick_step.cycle, max_cplx);
    //     std::mem::swap(value, &mut tmp_value);
    //     std::mem::swap(cache, &mut tmp_cache);

    //     step.increment_mutation_step_category();

    //     UnmutateVecToken::Replace(tmp_value, tmp_cache)
    // }

    fn choose_slice_length(&self, target_cplx: f64) -> (Option<usize>, usize) {
        let min_cplx_el = self.m.min_complexity();

        // slight underestimate of the maximum number of elements required to produce an input of max_cplx
        let max_len_most_complex = {
            let overestimated_max_len: f64 = target_cplx / min_cplx_el;
            let max_len = if overestimated_max_len.is_infinite() {
                // min_cplx_el is 0, so the max length is the maximum complexity of the length component of the vector
                crate::cplxity_to_size(target_cplx)
            } else {
                // an underestimate of the true max_length, but not by much
                (overestimated_max_len - overestimated_max_len.log2()) as usize
            };
            if max_len > 10_000 {
                /* TODO */
                // 10_000?
                target_cplx.trunc() as usize
            } else {
                max_len
            }
        };
        let max_cplx_el = self.m.max_complexity();
        // slight underestimate of the minimum number of elements required to produce an input of max_cplx
        // will be inf. if elements can be of infinite complexity
        // or if elements are of max_cplx 0.0
        let min_len_most_complex = target_cplx / max_cplx_el - (target_cplx / max_cplx_el).log2();

        // arbitrary restriction on the length of the generated number, to avoid creating absurdly large vectors
        // of very simple elements, that take up too much memory
        let max_len_most_complex = if max_len_most_complex > 10_000 {
            /* TODO */
            // 10_000?
            target_cplx.trunc() as usize
        } else {
            max_len_most_complex
        };

        if !min_len_most_complex.is_finite() {
            (None, max_len_most_complex)
        } else {
            let min_len_most_complex = min_len_most_complex.trunc() as usize;
            (Some(min_len_most_complex), max_len_most_complex)
        }
    }

    fn new_input_with_length_and_complexity(
        &mut self,
        target_len: usize,
        target_cplx: f64,
    ) -> (<Self as Mutator>::Value, <Self as Mutator>::Cache) {
        // TODO: create a new_input_with_complexity method
        let mut v = Vec::with_capacity(target_len);
        let mut cache = VecMutatorCache {
            inner: Vec::with_capacity(target_len),
            sum_cplx: 0.0,
        };

        let mut remaining_cplx = target_cplx;
        for i in 0..target_len {
            let max_cplx_element = remaining_cplx / ((target_len - i) as f64);
            let min_cplx_el = self.m.min_complexity();
            if min_cplx_el >= max_cplx_element {
                break;
            }
            let cplx_element = crate::gen_f64(&self.rng, min_cplx_el..max_cplx_element);
            let (x, x_cache) = self.m.arbitrary(self.rng.usize(..), cplx_element);
            let x_cplx = self.m.complexity(&x, &x_cache);
            v.push(x);
            cache.inner.push(x_cache);
            cache.sum_cplx += x_cplx;
            remaining_cplx -= x_cplx;
        }
        (v, cache)
    }
}

impl<M: Mutator> Mutator for VecMutator<M> {
    type Value = Vec<M::Value>;
    type Cache = VecMutatorCache<M::Cache>;
    type MutationStep = MutationStep<M::MutationStep>;
    type UnmutateToken = UnmutateVecToken<M>;

    fn max_complexity(&self) -> f64 {
        std::f64::INFINITY
    }

    fn min_complexity(&self) -> f64 {
        1.0
    }

    fn complexity(&self, value: &Self::Value, cache: &Self::Cache) -> f64 {
        1.0 + cache.sum_cplx + crate::size_to_cplxity(value.len() + 1)
    }

    fn cache_from_value(&self, value: &Self::Value) -> Self::Cache {
        let inner: Vec<_> = value.iter().map(|x| self.m.cache_from_value(x)).collect();

        let sum_cplx = value
            .iter()
            .zip(inner.iter())
            .fold(0.0, |cplx, (v, cache)| cplx + self.m.complexity(v, cache));

        VecMutatorCache { inner, sum_cplx }
    }
    fn initial_step_from_value(&self, value: &Self::Value) -> Self::MutationStep {
        let inner: Vec<_> = value.iter().map(|x| self.m.initial_step_from_value(x)).collect();
        MutationStep {
            inner,
            ..MutationStep::new(MutationCategory::Vector)
        }
    }
    fn random_step_from_value(&self, value: &Self::Value) -> Self::MutationStep {
        let inner: Vec<_> = value.iter().map(|x| self.m.random_step_from_value(x)).collect();
        MutationStep {
            inner,
            ..MutationStep::new(if value.is_empty() || self.rng.bool() { 
                MutationCategory::Vector 
            } else {
                MutationCategory::Element
            })
        }
    }

    fn arbitrary(&mut self, seed: usize, max_cplx: f64) -> (Self::Value, Self::Cache) {
        if seed == 0 || max_cplx <= 4.0 {
            return (Self::Value::default(), Self::Cache::default());
        }
        let target_cplx = fastrand::f64() * crate::gen_f64(&self.rng, 0.0..max_cplx);
        let lengths = self.choose_slice_length(target_cplx);

        if lengths.0.is_none() && self.m.max_complexity() < 0.001 {
            // distinguish between the case where elements are of max_cplx 0 and the case where they are of max_cplx inf.
            // in this case, the elements are always of cplx 0, so we can only vary the length of the vector
            // that's not true!!!
            if lengths.1 <= 0 {
                return (Self::Value::default(), Self::Cache::default());
            }
            assert!(lengths.1 > 0);
            let len = self.rng.usize(0..lengths.1);
            let (el, el_cache) = self.m.arbitrary(0, 0.0);
            let v = repeat(el).take(len).collect();
            let cache = Self::Cache {
                inner: repeat(el_cache).take(len).collect(),
                sum_cplx: 0.0,
            };
            return (v, cache);
        }
        let (min_length, max_length) = (lengths.0.unwrap_or(0), lengths.1);

        // choose a length between min_len_most_complex and max_len_most_complex
        let target_len = if min_length >= max_length {
            min_length
        } else {
            self.rng.usize(min_length..max_length)
        };

        self.new_input_with_length_and_complexity(target_len, target_cplx)
    }

    fn mutate(
        &mut self,
        value: &mut Self::Value,
        cache: &mut Self::Cache,
        step: &mut Self::MutationStep,
        max_cplx: f64,
    ) -> Self::UnmutateToken {
        let spare_cplx = max_cplx - self.complexity(value, cache);

        let token = match step.category {
            MutationCategory::Element => {
                let token = self.mutate_element(value, cache, step, step.element_step % value.len(), spare_cplx);
                step.increment_element();
                token
            }
            MutationCategory::Vector => {
                let operation = VecOperation::from_step(step.vector_step);
                let token = match operation {
                    VecOperation::Insert => self.insert_element(value, cache, spare_cplx),
                    VecOperation::InsertRepeated => self.insert_repeated_elements(value, cache, spare_cplx),
                    VecOperation::Remove => self.remove_element(value, cache),
                    VecOperation::RemoveMany => self.remove_many_elements(value, cache),
                    // VecOperation::Arbitrary => self.mutate_arbitrary(value, cache, step, max_cplx),
                };
                step.increment_vector();
                token
            }
        };
        if let UnmutateVecToken::Nothing = token {
            self.mutate(value, cache, step, max_cplx)
        } else {
            token
        }
    }

    fn unmutate(&self, value: &mut Self::Value, cache: &mut Self::Cache, t: Self::UnmutateToken) {
        match t {
            UnmutateVecToken::Element(idx, inner_t, diff_cplx) => {
                let el = &mut value[idx];
                let el_cache = &mut cache.inner[idx];
                self.m.unmutate(el, el_cache, inner_t);
                cache.sum_cplx += diff_cplx;
            }
            UnmutateVecToken::Insert(idx, el, el_cache) => {
                cache.sum_cplx += self.m.complexity(&el, &el_cache);

                value.insert(idx, el);
                cache.inner.insert(idx, el_cache);
            }
            UnmutateVecToken::Remove(idx, el_cplx) => {
                value.remove(idx);
                cache.inner.remove(idx);
                cache.sum_cplx -= el_cplx;
            }
            UnmutateVecToken::Replace(new_value, new_cache) => {
                let _ = std::mem::replace(value, new_value);
                let _ = std::mem::replace(cache, new_cache);
            }
            UnmutateVecToken::InsertMany(idx, v, c) => {
                insert_many(value, idx, v.into_iter());
                insert_many(&mut cache.inner, idx, c.inner.into_iter());
                let added_cplx = c.sum_cplx;
                cache.sum_cplx += added_cplx;
            }
            UnmutateVecToken::RemoveMany(range, cplx) => {
                value.drain(range.clone());
                cache.inner.drain(range);
                cache.sum_cplx -= cplx;
            }
            UnmutateVecToken::Nothing => {}
        }
    }
}

fn insert_many<T>(v: &mut Vec<T>, idx: usize, iter: impl Iterator<Item = T>) {
    let moved_slice = v.drain(idx..).collect::<Vec<T>>().into_iter();
    v.extend(iter);
    v.extend(moved_slice);
}
