extern crate self as fuzzcheck;

use super::grammar::Grammar;
use crate::mutators::alternation::AlternationMutator;
use crate::mutators::character_classes::CharacterMutator;
use crate::mutators::either::Either;
use crate::mutators::fixed_len_vector::FixedLenVecMutator;
use crate::mutators::grammar::ast::AST;
use crate::mutators::map::AndMapMutator;
use crate::mutators::recursive::{RecurToMutator, RecursiveMutator};
use crate::mutators::tuples::Tuple1Mutator;
use crate::mutators::vector::VecMutator;
use crate::Mutator;
use fuzzcheck_mutators_derive::make_single_variant_mutator;
use std::any::TypeId;
use std::collections::HashMap;
use std::rc::{Rc, Weak};

make_single_variant_mutator! {
    pub enum AST {
        Token(char),
        Sequence(Vec<AST>),
    }
}

type InnerASTMutator = Either<
    AlternationMutator<AST, ASTMutator>,
    Either<
        ASTSingleVariant<
            Tuple1Mutator<CharacterMutator>,
            Tuple1Mutator<
                Either<
                    FixedLenVecMutator<AST, RecurToMutator<ASTMutator>>,
                    Either<FixedLenVecMutator<AST, ASTMutator>, VecMutator<AST, ASTMutator>>,
                >,
            >,
        >,
        RecursiveMutator<ASTMutator>,
    >,
>;

pub struct ASTMutator {
    inner: Box<InnerASTMutator>,
}

impl ASTMutator {
    #[no_coverage]
    pub fn with_string(self) -> impl Mutator<(String, AST)> {
        AndMapMutator::new(self, |x| x.to_string())
    }
}

#[derive(Clone)]
pub struct ASTMutatorCache {
    inner: Box<<InnerASTMutator as Mutator<AST>>::Cache>,
}
impl ASTMutatorCache {
    #[no_coverage]
    fn new(inner: <InnerASTMutator as Mutator<AST>>::Cache) -> Self {
        Self { inner: Box::new(inner) }
    }
}
#[derive(Clone)]
pub struct ASTMutatorMutationStep {
    inner: Box<<InnerASTMutator as Mutator<AST>>::MutationStep>,
}
impl ASTMutatorMutationStep {
    #[no_coverage]
    fn new(inner: <InnerASTMutator as Mutator<AST>>::MutationStep) -> Self {
        Self { inner: Box::new(inner) }
    }
}
#[derive(Clone)]
pub struct ASTMutatorArbitraryStep {
    inner: Box<<InnerASTMutator as Mutator<AST>>::ArbitraryStep>,
}
#[derive(Clone)]
pub struct ASTMutatorLensPath {
    pub(crate) inner: Box<<InnerASTMutator as Mutator<AST>>::LensPath>,
}
impl ASTMutatorLensPath {
    #[no_coverage]
    fn new(inner: <InnerASTMutator as Mutator<AST>>::LensPath) -> Self {
        Self { inner: Box::new(inner) }
    }
}
pub struct ASTMutatorUnmutateToken {
    pub(crate) inner: Box<<InnerASTMutator as Mutator<AST>>::UnmutateToken>,
}
impl ASTMutatorUnmutateToken {
    #[no_coverage]
    fn new(inner: <InnerASTMutator as Mutator<AST>>::UnmutateToken) -> Self {
        Self { inner: Box::new(inner) }
    }
}

impl Mutator<AST> for ASTMutator {
    #[doc(hidden)]
    type Cache = ASTMutatorCache;
    #[doc(hidden)]
    type MutationStep = ASTMutatorMutationStep;
    #[doc(hidden)]
    type ArbitraryStep = ASTMutatorArbitraryStep;
    #[doc(hidden)]
    type UnmutateToken = ASTMutatorUnmutateToken;
    #[doc(hidden)]
    type LensPath = ASTMutatorLensPath;

    #[doc(hidden)]
    #[no_coverage]
    fn default_arbitrary_step(&self) -> Self::ArbitraryStep {
        Self::ArbitraryStep {
            inner: Box::new(self.inner.default_arbitrary_step()),
        }
    }

    #[doc(hidden)]
    #[no_coverage]
    fn validate_value(&self, value: &AST) -> Option<Self::Cache> {
        let cache = self.inner.validate_value(value)?;
        Some(Self::Cache::new(cache))
    }
    #[doc(hidden)]
    #[no_coverage]
    fn default_mutation_step(&self, value: &AST, cache: &Self::Cache) -> Self::MutationStep {
        Self::MutationStep::new(self.inner.default_mutation_step(value, &cache.inner))
    }

    #[doc(hidden)]
    #[no_coverage]
    fn max_complexity(&self) -> f64 {
        self.inner.max_complexity()
    }

    #[doc(hidden)]
    #[no_coverage]
    fn min_complexity(&self) -> f64 {
        self.inner.min_complexity()
    }

    #[doc(hidden)]
    #[no_coverage]
    fn complexity(&self, value: &AST, cache: &Self::Cache) -> f64 {
        self.inner.complexity(value, &cache.inner)
    }

    #[doc(hidden)]
    #[no_coverage]
    fn ordered_arbitrary(&self, step: &mut Self::ArbitraryStep, max_cplx: f64) -> Option<(AST, f64)> {
        self.inner.ordered_arbitrary(&mut step.inner, max_cplx)
    }

    #[doc(hidden)]
    #[no_coverage]
    fn random_arbitrary(&self, max_cplx: f64) -> (AST, f64) {
        self.inner.random_arbitrary(max_cplx)
    }

    #[doc(hidden)]
    #[no_coverage]
    fn ordered_mutate(
        &self,
        value: &mut AST,
        cache: &mut Self::Cache,
        step: &mut Self::MutationStep,
        max_cplx: f64,
    ) -> Option<(Self::UnmutateToken, f64)> {
        let (token, cplx) = self
            .inner
            .ordered_mutate(value, &mut cache.inner, &mut step.inner, max_cplx)?;
        Some((Self::UnmutateToken::new(token), cplx))
    }

    #[doc(hidden)]
    #[no_coverage]
    fn random_mutate(&self, value: &mut AST, cache: &mut Self::Cache, max_cplx: f64) -> (Self::UnmutateToken, f64) {
        let (token, cplx) = self.inner.random_mutate(value, &mut cache.inner, max_cplx);
        (Self::UnmutateToken::new(token), cplx)
    }

    #[doc(hidden)]
    #[no_coverage]
    fn unmutate(&self, value: &mut AST, cache: &mut Self::Cache, t: Self::UnmutateToken) {
        self.inner.unmutate(value, &mut cache.inner, *t.inner)
    }

    #[doc(hidden)]
    #[no_coverage]
    fn lens<'a>(&self, value: &'a AST, cache: &'a Self::Cache, path: &Self::LensPath) -> &'a dyn std::any::Any {
        self.inner.lens(value, &cache.inner, &path.inner)
    }

    #[doc(hidden)]
    #[no_coverage]
    fn all_paths(&self, value: &AST, cache: &Self::Cache, register_path: &mut dyn FnMut(TypeId, Self::LensPath)) {
        self.inner.all_paths(
            value,
            &cache.inner,
            #[no_coverage]
            &mut |typeid, subpath| {
                register_path(typeid, Self::LensPath::new(subpath));
            },
        );
    }

    #[doc(hidden)]
    #[no_coverage]
    fn crossover_mutate(
        &self,
        value: &mut AST,
        cache: &mut Self::Cache,
        subvalue_provider: &dyn fuzzcheck::SubValueProvider,
        max_cplx: f64,
    ) -> (Self::UnmutateToken, f64) {
        let (token, cplx) = self
            .inner
            .crossover_mutate(value, &mut cache.inner, subvalue_provider, max_cplx);
        (Self::UnmutateToken::new(token), cplx)
    }
}

/// A mutator created by [`grammar_based_ast_mutator`](crate::mutators::grammar::grammar_based_ast_mutator)
///
/// It only generates syntax trees whose [`to_string()`](crate::mutators::grammar::AST::to_string)
/// value matches the given grammar.
pub type GrammarBasedASTMutator = ASTMutator; //impl Mutator<AST>;

#[no_coverage]
pub fn grammar_based_ast_mutator(grammar: Rc<Grammar>) -> GrammarBasedASTMutator {
    ASTMutator::from_grammar(grammar)
}

impl ASTMutator {
    #[no_coverage]
    fn token(m: CharacterMutator) -> Self {
        Self {
            inner: Box::new(Either::Right(Either::Left(ASTSingleVariant::Token(
                Tuple1Mutator::new(m),
            )))),
        }
    }
    #[no_coverage]
    fn sequence(m: Either<FixedLenVecMutator<AST, ASTMutator>, VecMutator<AST, ASTMutator>>) -> Self {
        Self {
            inner: Box::new(Either::Right(Either::Left(ASTSingleVariant::Sequence(
                Tuple1Mutator::new(Either::Right(m)),
            )))),
        }
    }
    #[no_coverage]
    fn alternation(m: AlternationMutator<AST, ASTMutator>) -> Self {
        Self {
            inner: Box::new(Either::Left(m)),
        }
    }
    #[no_coverage]
    fn recur(m: RecurToMutator<ASTMutator>) -> Self {
        Self {
            inner: Box::new(Either::Right(Either::Left(ASTSingleVariant::Sequence(
                Tuple1Mutator::new(Either::Left(FixedLenVecMutator::new(vec![m]))),
            )))),
        }
    }
    #[no_coverage]
    fn recursive(m: impl FnMut(&Weak<Self>) -> Self) -> Self {
        Self {
            inner: Box::new(Either::Right(Either::Right(RecursiveMutator::new(m)))),
        }
    }

    #[no_coverage]
    pub fn from_grammar(grammar: Rc<Grammar>) -> Self {
        let mut others = HashMap::new();
        Self::from_grammar_rec(grammar, &mut others)
    }

    #[no_coverage]
    pub fn from_grammar_rec(grammar: Rc<Grammar>, others: &mut HashMap<*const Grammar, Weak<ASTMutator>>) -> Self {
        match grammar.as_ref() {
            Grammar::Literal(l) => Self::token(CharacterMutator::new(l.clone())),
            Grammar::Alternation(gs) => Self::alternation(AlternationMutator::new(
                gs.iter()
                    .map(
                        #[no_coverage]
                        |g| Self::from_grammar_rec(g.clone(), others),
                    )
                    .collect(),
            )),
            Grammar::Concatenation(gs) => {
                let mut ms = Vec::<ASTMutator>::new();
                for g in gs {
                    let m = Self::from_grammar_rec(g.clone(), others);
                    ms.push(m);
                }
                Self::sequence(Either::Left(FixedLenVecMutator::new(ms)))
            }
            Grammar::Repetition(g, range) => Self::sequence(Either::Right(VecMutator::new(
                Self::from_grammar_rec(g.clone(), others),
                range.start..=range.end - 1,
            ))),
            Grammar::Recurse(g) => {
                if let Some(m) = others.get(&g.as_ptr()) {
                    Self::recur(RecurToMutator::from(m))
                } else {
                    panic!()
                }
            }
            Grammar::Recursive(g) => Self::recursive(
                #[no_coverage]
                |m| {
                    let weak_g = Rc::downgrade(g);
                    others.insert(weak_g.as_ptr(), m.clone());
                    Self::from_grammar_rec(g.clone(), others)
                },
            ),
        }
    }
}
