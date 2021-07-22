use fuzzcheck_mutators::{integer::U8Mutator, vector::VecMutator};
use fuzzcheck_traits::Mutator;

#[test]
fn test_vector_mutator() {
    // let m = VecMutator::new(U8Mutator::default(), 0..=10);
    // fuzzcheck_mutators::testing_utilities::test_mutator(m, 100.0, 100.0, false, 500, 500);
    // let m = VecMutator::new(U8Mutator::default(), 0..=10);
    // fuzzcheck_mutators::testing_utilities::test_mutator(m, 20000.0, 20000.0, false, 500, 500);
    // let m = VecMutator::new(U8Mutator::default(), 10..=20);
    // fuzzcheck_mutators::testing_utilities::test_mutator(m, 10000.0, 10000.0, false, 500, 500);
    // // todo: test with an unlimited range

    let m = VecMutator::new(VecMutator::new(U8Mutator::default(), 0..=usize::MAX), 0..=usize::MAX);
    fuzzcheck_mutators::testing_utilities::test_mutator(m, 10000.0, 10000.0, false, 200, 200);
}

#[test]
fn test_vector_explore() {
    let m = VecMutator::new(VecMutator::new(U8Mutator::default(), 0..=5), 0..=5);
    let mut step = m.default_arbitrary_step();
    let (x, cplx) = m.ordered_arbitrary(&mut step, 100.0).unwrap();
    println!("{:?}", x);
    println!("cplx: {}", cplx);
    let (mut x, cplx) = m.ordered_arbitrary(&mut step, 100.0).unwrap();
    println!("{:?}", x);
    println!("cplx: {}", cplx);
    let (mut cache, mut step) = m.validate_value(&x).unwrap();

    for _ in 0..100 {
        if let Some((token, _cplx)) = m.ordered_mutate(&mut x, &mut cache, &mut step, 4096.) {
            println!("{:?}", x);
            m.unmutate(&mut x, &mut cache, token);
        }
    }
}
