use std::ops::{Range, RangeBounds, RangeInclusive};
use std::rc::{Rc, Weak};

#[cfg(feature = "regex_grammar")]
use crate::mutators::grammar::regex::grammar_from_regex;

#[derive(Clone, Debug)]
/// A grammar which can be used for fuzzing.
///
/// See [the module documentation](crate::mutators::grammar) for advice on how to create a grammar.
pub enum Grammar {
    Literal(Vec<RangeInclusive<char>>),
    Alternation(Vec<Rc<Grammar>>),
    Concatenation(Vec<Rc<Grammar>>),
    Repetition(Rc<Grammar>, Range<usize>),
    Recurse(Weak<Grammar>),
    Recursive(Rc<Grammar>),
}

#[cfg(feature = "regex_grammar")]
#[doc(cfg(feature = "regex_grammar"))]
#[no_coverage]
pub fn regex(s: &str) -> Rc<Grammar> {
    grammar_from_regex(s)
}
#[no_coverage]
pub fn literal_ranges(ranges: Vec<RangeInclusive<char>>) -> Rc<Grammar> {
    Rc::new(Grammar::Literal(ranges))
}
#[no_coverage]
pub fn literal(l: char) -> Rc<Grammar> {
    Rc::new(Grammar::Literal(vec![l..=l]))
}
#[no_coverage]
pub fn literal_range<R>(range: R) -> Rc<Grammar>
where
    R: RangeBounds<char>,
{
    let start = match range.start_bound() {
        std::ops::Bound::Included(x) => *x,
        std::ops::Bound::Excluded(x) => unsafe { char::from_u32_unchecked((*x as u32) + 1) },
        std::ops::Bound::Unbounded => panic!("The range must have a lower bound"),
    };
    let end = match range.end_bound() {
        std::ops::Bound::Included(x) => *x,
        std::ops::Bound::Excluded(x) => unsafe { char::from_u32_unchecked(*x as u32 - 1) },
        std::ops::Bound::Unbounded => panic!("The range must have an upper bound"),
    };
    Rc::new(Grammar::Literal(vec![start..=end]))
}
#[no_coverage]
pub fn alternation(gs: impl IntoIterator<Item = Rc<Grammar>>) -> Rc<Grammar> {
    Rc::new(Grammar::Alternation(gs.into_iter().collect()))
}
#[no_coverage]
pub fn concatenation(gs: impl IntoIterator<Item = Rc<Grammar>>) -> Rc<Grammar> {
    Rc::new(Grammar::Concatenation(gs.into_iter().collect()))
}
#[no_coverage]
pub fn repetition<R>(gs: Rc<Grammar>, range: R) -> Rc<Grammar>
where
    R: RangeBounds<usize>,
{
    let start = match range.start_bound() {
        std::ops::Bound::Included(x) => *x,
        std::ops::Bound::Excluded(x) => *x + 1,
        std::ops::Bound::Unbounded => panic!("The range must have a lower bound"),
    };
    let end = match range.end_bound() {
        std::ops::Bound::Included(x) => x.saturating_add(1),
        std::ops::Bound::Excluded(x) => *x,
        std::ops::Bound::Unbounded => usize::MAX,
    };
    Rc::new(Grammar::Repetition(gs, start..end))
}

#[no_coverage]
pub fn recurse(g: &Weak<Grammar>) -> Rc<Grammar> {
    Rc::new(Grammar::Recurse(g.clone()))
}
#[no_coverage]
pub fn recursive(data_fn: impl Fn(&Weak<Grammar>) -> Rc<Grammar>) -> Rc<Grammar> {
    Rc::new(Grammar::Recursive(Rc::new_cyclic(|g| {
        Rc::try_unwrap(data_fn(g)).unwrap()
    })))
}
