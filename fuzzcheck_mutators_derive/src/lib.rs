#![allow(dead_code)]
#![feature(proc_macro_quote)]

mod parser;
mod token_builder;

//mod struct_derive;

use crate::parser::*;
use crate::token_builder::*;

use proc_macro::{Ident, Literal, Span, TokenStream};

macro_rules! opt_ts {
    ($opt:expr, $map_pat:pat, $($part:expr) *) => {
        {
            if let Some($map_pat) = $opt {
                ts!($($part) *)
            } else {
                ts!()
            }
        }
    };
}

macro_rules! join_ts {
    ($iter:expr) => {
        {
            #[allow(unused_mut)]
            let mut tb = TokenBuilder::new();
            for part in $iter {
                tb.extend(part);
            }
            tb.end()
        }
    };
    ($iter:expr, separator: $sep:expr) => {
        {
            #[allow(unused_mut)]
            let mut tb = TokenBuilder::new();
            let mut add_sep = false;
            for part in $iter {
                if add_sep {
                    $sep.add_to(&mut tb);
                }
                tb.extend(part);
                add_sep = true;
            }
            tb.end()
        }
    };
    ($iter:expr, $part_pat:pat, $($part:expr) *) => {
        {
            #[allow(unused_mut)]
            let mut tb = TokenBuilder::new();
            for $part_pat in $iter {
                extend_ts!(&mut tb,
                    $($part) *
                );
            }
            tb.end()
        }
    };
    ($iter:expr, $part_pat:pat, $($part:expr) *, separator: $sep:expr) => {
        {
            #[allow(unused_mut)]
            let mut tb = TokenBuilder::new();
            let mut add_sep = false;
            for $part_pat in $iter {
                if add_sep {
                    $sep.add_to(&mut tb);
                }
                extend_ts!(&mut tb,
                    $($part) *
                );
                add_sep = true;
            }
            tb.end()
        }
    };
}

macro_rules! extend_ts {
    ($tb:expr, $($part:expr) *) => {
        {
            $(
                $part.add_to($tb);
            )*
        }
    };
}

macro_rules! ts {
    ($($part:expr) *) => {
        {
            #[allow(unused_mut)]
            let mut tb = TokenBuilder::new();
            $(
                $part.add_to(&mut tb);
            )*
            tb.end()
        }
    };
}

macro_rules! ident {
    ($($x:expr) *) => {{
        let mut s = String::new();
        $(
            s.push_str(&$x.to_string());
        )*
        Ident::new(&s, Span::call_site())
    }};
}

#[proc_macro_derive(HasDefaultMutator)]
pub fn derive_mutator(input: TokenStream) -> TokenStream {
    let mut parser = TokenParser::new(input);
    let mut tb = TokenBuilder::new();

    if let Some(s) = parser.eat_struct() {
        derive_struct_mutator(s, &mut tb);
    } else if let Some(e) = parser.eat_enumeration() {
        derive_enum_mutator(e, &mut tb)
    } else {
        extend_ts!(&mut tb,
            "compile_error ! ("
            Literal::string("fuzzcheck_mutators_derive could not parse the structure")
            ") ;"
        )
    }
    tb.eprint();
    tb.end()
}

fn derive_struct_mutator(parsed_struct: Struct, tb: &mut TokenBuilder) {
    if !parsed_struct.struct_fields.is_empty() {
        derive_struct_mutator_with_fields(&parsed_struct, tb)
    } else {
        derive_unit_mutator(parsed_struct, tb);
    }
}

struct DerivedStructFieldIdentifiers {
    orig: Ident,
    muta: Ident,
    m_value: Ident,
    m_cache: Ident,
    ty: TokenStream,
    generic_type: TokenStream,
}

fn derive_struct_mutator_with_fields(parsed_struct: &Struct, tb: &mut TokenBuilder) {

    let field_idents = parsed_struct
        .struct_fields
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let orig = ident!(f.identifier.as_ref().map(|z| z.to_string()).unwrap_or(i.to_string()));
            let muta = ident!("_" orig);
            let m_value = ident!(muta "_value");
            let m_cache = ident!(muta "_cache");
            let ty = f.ty.clone();
            let generic_type = ts!(ident!(muta "Type"));
            DerivedStructFieldIdentifiers {
                orig,
                muta,
                m_value,
                m_cache,
                ty,
                generic_type,
            }
        })
        .collect::<Vec<_>>();

    let generics_without_bounds = parsed_struct.generics.removing_bounds_and_eq_type();

    let basic_generics = Generics {
        lifetime_params: Vec::new(),
        type_params: field_idents.iter()
            .map(|ids| TypeParam {
                type_ident: ids.generic_type.clone(),
                ..<_>::default()
            })
            .collect(),
    };

    let basic_fields = field_idents
        .iter()
        .map(|ids| StructField {
            attributes: Vec::new(),
            visibility: ts!("pub"),
            identifier: Some(ids.muta.clone()),
            ty: ids.generic_type.clone(),
        })
        .collect::<Vec<_>>();

    let value_struct_ident_with_generic_params = ts!(
        parsed_struct.ident generics_without_bounds
    );

    let mutator_struct = {
        let mut generics = parsed_struct.generics.clone();

        let mut where_clause_items = parsed_struct.where_clause.clone().map(|wc| wc.items).unwrap_or(vec![]);

        for ids in field_idents.iter() {
            generics.type_params.push(TypeParam {
                type_ident: ids.generic_type.clone(),
                ..<_>::default()
            });
            where_clause_items.push(WhereClauseItem {
                for_lifetimes: None,
                lhs: ids.ty.clone(),
                rhs: ts!(":: core :: clone :: Clone") 
            });
            where_clause_items.push(WhereClauseItem {
                for_lifetimes: None,
                lhs: ids.generic_type.clone(),
                rhs: ts!("fuzzcheck_mutators :: fuzzcheck_traits :: Mutator < Value = " ids.ty ">")
            });
        }

        where_clause_items.push(WhereClauseItem {
            for_lifetimes: None,
            lhs: value_struct_ident_with_generic_params.clone(),
            rhs: ts!(":: core :: clone :: Clone"),
        });

        let mut mutator_struct_fields = basic_fields.clone();
        mutator_struct_fields.push(StructField {
            attributes: Vec::new(),
            visibility: ts!("pub"),
            identifier: Some(ident!("rng")),
            ty: ts!("fuzzcheck_mutators :: fastrand :: Rng"),
        });

        Struct {
            visibility: parsed_struct.visibility.clone(),
            ident: ident!(parsed_struct.ident "Mutator"),
            generics,
            kind: StructKind::Struct,
            where_clause: Some(WhereClause {
                items: where_clause_items,
            }),
            struct_fields: mutator_struct_fields,
        }
    };

    tb.extend(&mutator_struct);

    let mutator_cache_struct = {
        let mut cache_fields = basic_fields.clone();
        cache_fields.push(StructField {
            attributes: Vec::new(),
            visibility: ts!(),
            identifier: Some(ident!("cplx")),
            ty: ts!("f64"),
        });
        Struct {
            visibility: parsed_struct.visibility.clone(),
            ident: ident!(parsed_struct.ident "MutatorCache"),
            generics: basic_generics.clone(),
            kind: StructKind::Struct,
            where_clause: None,
            struct_fields: cache_fields.clone(),
        }
    };

    extend_ts!(tb,
        "# [ derive ( :: core :: clone :: Clone ) ]"
        mutator_cache_struct
    );

    let mutator_step_struct = {
        let mut step_fields = basic_fields.clone();
        step_fields.push(StructField {
            attributes: Vec::new(),
            visibility: ts!(),
            identifier: Some(ident!("step")),
            ty: ts!("u64"),
        });
        Struct {
            visibility: parsed_struct.visibility.clone(),
            ident: ident!(parsed_struct.ident "MutationStep"),
            generics: basic_generics.clone(),
            kind: StructKind::Struct,
            where_clause: None,
            struct_fields: step_fields,
        }
    };

    extend_ts!(tb,
        "# [ derive ( :: core :: clone :: Clone ) ]"
        mutator_step_struct
    );

    let (arbitrary_inner_step_enum, arbitrary_step_struct) = {
        let inner_enum = Enum {
            visibility: ts!("pub"),
            ident: ident!(parsed_struct.ident "InnerArbitraryStep"),
            generics: <_>::default(),
            where_clause: None,
            items: field_idents.iter().map(|ids| {
                EnumItem {
                    attributes: Vec::new(),
                    ident: ids.muta.clone(),
                    data: None,
                }
            }).collect()
        };
        let mut step_fields = field_idents.iter().map(|ids|
            StructField {
                identifier: Some(ids.muta.clone()), 
                ty: ts!(ids.generic_type),
                ..<_>::default()
            }
        ).collect::<Vec<_>>();
    
        step_fields.push(StructField {
            identifier: Some(ident!("fields")), 
            ty: ts!(":: std :: vec :: Vec <" inner_enum.ident ">"),
            ..<_>::default()
        });

        let step_struct = Struct {
            visibility: ts!("pub"),
            ident: ident!(parsed_struct.ident "ArbitraryStep"),
            generics: basic_generics.clone(),
            kind: StructKind::Struct,
            where_clause: None,
            struct_fields: step_fields,
        };
        (inner_enum, step_struct)
    };
    extend_ts!(tb,
        "# [ derive ( :: core :: clone :: Clone ) ]"
        arbitrary_inner_step_enum
        "# [ derive ( :: core :: clone :: Clone ) ]"
        arbitrary_step_struct

        "impl" arbitrary_step_struct.generics ":: core :: default :: Default for" arbitrary_step_struct.ident 
            arbitrary_step_struct.generics 
        "{
            fn default ( ) -> Self {
                Self {"
                    join_ts!(&field_idents, ids,
                        ids.muta ": < _ > :: default ( ) ,"
                    )
                    "fields : < _ > :: default ( )
                }
            }
        }"
    );

    let unmutate_token_struct = {
        let mut step_fields = basic_fields
            .iter()
            .map(|field| StructField {
                ty: ts!(":: std :: option :: Option <" field.ty ">"),
                ..field.clone()
            })
            .collect::<Vec<StructField>>();

        step_fields.push(StructField {
            attributes: Vec::new(),
            visibility: ts!(),
            identifier: Some(ident!("cplx")),
            ty: ts!("f64"),
        });
        Struct {
            visibility: parsed_struct.visibility.clone(),
            ident: ident!(parsed_struct.ident "UnmutateToken"),
            generics: basic_generics,
            kind: StructKind::Struct,
            where_clause: None,
            struct_fields: step_fields,
        }
    };

    extend_ts!(tb,
        "# [ derive ( :: core :: clone :: Clone ) ]"
        unmutate_token_struct
    );

    // default impl for unmutate token
    extend_ts!(tb,
        "impl" unmutate_token_struct.generics ":: core :: default :: Default for" unmutate_token_struct.ident unmutate_token_struct.generics "{
            fn default ( ) -> Self {
                Self {"
                    join_ts!(&field_idents, ids,
                        ids.muta ": None ,"
                    )
                    "cplx : f64 :: default ( )
                }
            }
        }"
    );

    // implementation of Mutator trait
    extend_ts!(tb,
        "impl" mutator_struct.generics "fuzzcheck_mutators :: fuzzcheck_traits :: Mutator for"
            mutator_struct.ident mutator_struct.generics.removing_bounds_and_eq_type() mutator_struct.where_clause
        "{
            type Value = " value_struct_ident_with_generic_params ";
            type Cache = " mutator_cache_struct.ident
                mutator_cache_struct.generics.mutating_type_params(|tp|
                    tp.type_ident = ts!("<" tp.type_ident "as fuzzcheck_mutators :: fuzzcheck_traits :: Mutator > :: Cache")
                )
                ";
            
            type MutationStep = "
                mutator_step_struct.ident
                mutator_step_struct.generics.mutating_type_params(|tp|
                    tp.type_ident = ts!("<" tp.type_ident "as fuzzcheck_mutators :: fuzzcheck_traits :: Mutator > :: MutationStep")
                )
                ";

            type ArbitraryStep = "
                arbitrary_step_struct.ident
                arbitrary_step_struct.generics.mutating_type_params(|tp|
                    tp.type_ident = ts!("<" tp.type_ident "as fuzzcheck_mutators :: fuzzcheck_traits :: Mutator > :: MutationStep")
                )
                ";
            type UnmutateToken = "
                unmutate_token_struct.ident
                unmutate_token_struct.generics.mutating_type_params(|tp|
                    tp.type_ident = ts!("<" tp.type_ident "as fuzzcheck_mutators :: fuzzcheck_traits :: Mutator > :: UnmutateToken")
                )
                ";

            fn max_complexity ( & self ) -> f64 {"
                join_ts!(&field_idents, ids,
                    "self . " ids.muta ". max_complexity ( )"
                , separator: "+")
            "}

            fn min_complexity ( & self ) -> f64 {"
                join_ts!(&field_idents, ids,
                    "self . " ids.muta ". min_complexity ( )"
                , separator: "+")
            "}
            
            fn complexity ( & self , value : & Self :: Value , cache : & Self :: Cache ) -> f64 { cache . cplx }

            fn cache_from_value ( & self , value : & Self :: Value ) -> Self :: Cache {"
                // declare all subcaches
                join_ts!(&field_idents, ids,
                    "let" ids.muta "= self ." ids.muta ". cache_from_value ( & value ." ids.orig ") ;"
                )
                // compute cplx
                "let cplx =" join_ts!(&field_idents, ids,
                    "self . " ids.muta ". complexity ( & value ." ids.orig ", &" ids.muta ")"
                , separator: "+") ";"

                "Self :: Cache {"
                    join_ts!(&field_idents, ids , ids.muta , separator: ",")
                    ", cplx
                }
            }

            fn initial_step_from_value ( & self , value : & Self :: Value ) -> Self :: MutationStep {"
                // init all substeps
                join_ts!(&field_idents, ids,
                    "let" ids.muta "= self ." ids.muta ". initial_step_from_value ( & value ." ids.orig ") ;"
                )

                "let step = 0 ;

                Self :: MutationStep {"
                join_ts!(&field_idents, ids , ids.muta , separator: ",")
                    ", step
                }
            }
            
            fn random_step_from_value ( & self , value : & Self :: Value ) -> Self :: MutationStep {"
                // init all substeps
                join_ts!(&field_idents, ids,
                    "let" ids.muta "= self ." ids.muta ". random_step_from_value ( & value ." ids.orig ") ;"
                )

                "let step = self . rng . u64 ( .. ) ;

                Self :: MutationStep {"
                    join_ts!(&field_idents, ids , ids.muta , separator: ",")
                    ", step
                }
            }

            fn ordered_arbitrary ( & mut self , step : & mut Self :: ArbitraryStep , max_cplx : f64 ) -> Option < ( Self :: Value , Self :: Cache ) > {
                Some ( self . random_arbitrary ( max_cplx ) )
            }

            fn random_arbitrary ( & mut self , max_cplx : f64 ) -> ( Self :: Value , Self :: Cache ) {"
                join_ts!(&field_idents, ids,
                    "let mut" ids.m_value ": Option < _ > = None ;
                     let mut" ids.m_cache ": Option < _ > = None ;"
                )
                "let mut indices = ( 0 .. " field_idents.len() ") . collect :: < Vec < _ > > ( ) ;
                fuzzcheck_mutators :: fastrand :: shuffle ( & mut indices ) ;
                let seed = fuzzcheck_mutators :: fastrand :: usize ( .. ) ;
                let mut cplx = f64 :: default ( ) ;

                for idx in indices . iter ( ) {
                    match idx {"
                    join_ts!(field_idents.iter().enumerate(), (i, ids),
                        i "=> {
                            let ( value , cache ) = self . " ids.muta " . random_arbitrary ( max_cplx - cplx ) ;
                            cplx += self . " ids.muta ". complexity ( & value , & cache ) ; " 
                            ids.m_value "= Some ( value ) ;"
                            ids.m_cache "= Some ( cache ) ;
                        }"
                    )
                            "_ => unreachable ! ( )
                    }
                }
                (
                    Self :: Value {"
                        join_ts!(&field_idents, ids,
                            ids.orig ":" ids.m_value ". unwrap ( ) ,"
                        )
                    "} ,
                    Self :: Cache {"
                        join_ts!(&field_idents, ids,
                            ids.muta ":" ids.m_cache " . unwrap ( ) ,"
                        )
                        "cplx
                    }
                )
            }

            fn mutate ( & mut self , value : & mut Self :: Value , cache : & mut Self :: Cache , step : & mut Self :: MutationStep , max_cplx : f64 ) -> Option < Self :: UnmutateToken >
            {
                let orig_step = step . step ;
                step . step += 1 ;
                let current_cplx = self . complexity ( value , cache ) ;
                match orig_step % " field_idents.len() "{"
                join_ts!(field_idents.iter().enumerate(), (i, ids),
                    i " => {
                        let current_field_cplx = self ." ids.muta ". complexity ( & value ." ids.orig ", & cache ." ids.muta ") ;
                        let max_field_cplx = max_cplx - current_cplx - current_field_cplx ;
                        let token = self ." ids.muta ". mutate ( & mut  value ." ids.orig ", & mut cache ." ids.muta ", & mut step ." ids.muta ", max_field_cplx ) ;
                        let new_field_complexity = self ." ids.muta ". complexity ( & value ." ids.orig ", & cache ." ids.muta ") ;
                        cache . cplx = cache . cplx - current_field_cplx + new_field_complexity ;
                        Some ( Self :: UnmutateToken {"
                            ids.muta ": token ,
                            cplx : current_cplx ,
                            .. Self :: UnmutateToken :: default ( )
                        } )
                    }"
                )
                    "_ => unreachable ! ( )
                }
            }

            fn unmutate ( & self , value : & mut Self :: Value , cache : & mut Self :: Cache , t : Self :: UnmutateToken )
            {
                cache . cplx = t . cplx ;"
                join_ts!(&field_idents, ids,
                    "if let Some ( subtoken ) = t ." ids.muta "{"
                        "self ." ids.muta ". unmutate ( & mut value ." ids.orig ", & mut cache ." ids.muta ", subtoken ) ;"
                    "}"
                )
            "}
        }"
    );

    {
        // default impl
        let where_clause = {
            let mut where_clause = mutator_struct.where_clause.clone().unwrap_or_default();

            for field in &basic_fields {
                where_clause.items.push(WhereClauseItem {
                    for_lifetimes: None,
                    lhs: ts!(field.ty),
                    rhs: ts!(":: core :: default :: Default"),
                });
            }
            where_clause
        };

        extend_ts!(tb,
        "impl" mutator_struct.generics ":: core :: default :: Default for" mutator_struct.ident
            mutator_struct.generics.removing_bounds_and_eq_type() where_clause
        "{
            fn default ( ) -> Self {
                Self {"
                    join_ts!(&mutator_struct.struct_fields, field,
                        field.identifier ":" "<" field.ty "as :: core :: default :: Default > :: default ( )"
                    , separator: ",")
                "}
            }
        }"
        )
    }
    {
        let where_clause = {
            let mut where_clause = parsed_struct.where_clause.clone().unwrap_or_default();
            for field in parsed_struct.struct_fields.iter() {
                where_clause.items.extend(vec![
                    WhereClauseItem {
                        for_lifetimes: None,
                        lhs: field.ty.clone(),
                        rhs: ts!(":: core :: clone :: Clone + fuzzcheck_mutators :: HasDefaultMutator"),
                    },
                    WhereClauseItem {
                        for_lifetimes: None,
                        lhs: ts!("<" field.ty " as fuzzcheck_mutators :: HasDefaultMutator > :: Mutator"),
                        rhs: ts!(":: core :: default :: Default"),
                    },
                    WhereClauseItem {
                        for_lifetimes: None,
                        lhs: value_struct_ident_with_generic_params.clone(),
                        rhs: ts!(":: core :: clone :: Clone"),
                    }
                ]);
            }
            where_clause
        };

        let generics_mutator = {
            let mut type_params = generics_without_bounds.type_params.clone();
            for field in parsed_struct.struct_fields.iter() {
                type_params.push(TypeParam {
                    type_ident: ts!("<" field.ty "as fuzzcheck_mutators :: HasDefaultMutator > :: Mutator"),
                    ..<_>::default()
                });
            }
            Generics {
                lifetime_params: generics_without_bounds.lifetime_params.clone(),
                type_params,
            }
        };

        extend_ts!(tb,
        "impl" parsed_struct.generics "fuzzcheck_mutators :: HasDefaultMutator for" parsed_struct.ident
            generics_without_bounds where_clause
        "{
            type Mutator = " mutator_struct.ident generics_mutator ";

            fn default_mutator ( ) -> Self :: Mutator {
                Self :: Mutator :: default ( )
            }
        }"
        )
    }
}

fn derive_enum_mutator(parsed_enum: Enum, tb: &mut TokenBuilder) {
    if !parsed_enum.items.is_empty() {
        derive_enum_mutator_with_items(&parsed_enum, tb)
    } else {
        todo!("Build mutator for empty enum");
    }
}

struct EnumItemDataForMutatorDerive {
    item: EnumItem,                                 // Aa
    fields: Vec<EnumItemDataFieldForMutatorDerive>, // (u8, _Aa_0, _Aa_0_Type) or (pub x: u16, _Aa_x, _Aa_x_Type),  }
}
struct EnumItemDataFieldForMutatorDerive {
    field: StructField,
    name: Ident,
    mutator_ty: Ident,
}

fn derive_enum_mutator_with_items(parsed_enum: &Enum, tb: &mut TokenBuilder) {
    let (basic_generics, items_for_derive, mutator_struct) = {
        // mutator struct
        /*
        generics: existing generics + generic mutator type params
        where_clause_items: existing where_clause + “Mutator” conditions
        mutator_field_types: the generic types for the sub-mutators, one for each field
        */
        let mut generics = parsed_enum.generics.clone();
        let mut where_clause = parsed_enum.where_clause.clone().unwrap_or_default();

        /*
            items_for_derive contains the items of the enum plus some information about
            their fields such as the name and type of the submutators associated with them
        */
        let items_for_derive = parsed_enum
            .items
            .iter()
            .map(|item| EnumItemDataForMutatorDerive {
                item: item.clone(),
                fields: if let Some(EnumItemData::Struct(_, fields)) = &item.data {
                    fields
                        .iter()
                        .enumerate()
                        .map(|(i, field)| {
                            let submutator_name = ident!(
                                "_" item.ident "_" field
                                    .identifier
                                    .as_ref()
                                    .map(<_>::to_string)
                                    .unwrap_or(i.to_string())
                            );
                            let submutator_type_ident = ident!(submutator_name "_Type");
                            EnumItemDataFieldForMutatorDerive {
                                field: field.clone(),
                                name: submutator_name,
                                mutator_ty: submutator_type_ident,
                            }
                        })
                        .collect::<Vec<_>>()
                } else {
                    vec![]
                },
            })
            .collect::<Vec<_>>();

        let fields_iter = items_for_derive.iter().flat_map(|item| item.fields.iter());

        // the generic types corresponding to each field in each item
        let basic_generics = Generics {
            lifetime_params: Vec::new(),
            type_params: fields_iter
                .clone()
                .map(|x| TypeParam {
                    type_ident: ts!(x.mutator_ty),
                    ..<_>::default()
                })
                .collect(),
        };

        let basic_fields = fields_iter
            .clone()
            .map(|x| StructField {
                attributes: Vec::new(),
                visibility: ts!("pub"),
                identifier: Some(x.name.clone()),
                ty: ts!(x.mutator_ty),
            })
            .collect::<Vec<_>>();

        /*
           for each field, add a generic parameter for its mutator as well as a where_clause_item
           ensuring it impls the Mutator trait and that it impls the Clone trait
        */
        for EnumItemDataFieldForMutatorDerive {
            field,
            name: _,
            mutator_ty: submutator_ty,
        } in fields_iter.clone()
        {
            let ty_param = TypeParam {
                type_ident: ts!(submutator_ty),
                ..<_>::default()
            };
            generics.type_params.push(ty_param);
            where_clause.items.push(WhereClauseItem {
                for_lifetimes: None,
                lhs: field.ty.clone(),
                rhs: ts!(":: core :: clone :: Clone"),
            });
            where_clause.items.push(WhereClauseItem {
                for_lifetimes: None,
                lhs: ts!(submutator_ty),
                rhs: ts!("fuzzcheck_mutators :: fuzzcheck_traits :: Mutator < Value = " field.ty ">"),
            });
        }
        /* also add requirement that the whole value is Clone */
        where_clause.items.push(WhereClauseItem {
            for_lifetimes: None,
            lhs: ts!(parsed_enum.ident parsed_enum.generics.removing_bounds_and_eq_type()),
            rhs: ts!(":: core :: clone :: Clone"),
        });

        let mut mutator_struct_fields = basic_fields.clone();
        mutator_struct_fields.push(StructField {
            attributes: Vec::new(),
            visibility: ts!("pub"),
            identifier: Some(ident!("rng")),
            ty: ts!("fuzzcheck_mutators :: fastrand :: Rng"),
        });

        (
            basic_generics,
            items_for_derive,
            Struct {
                visibility: parsed_enum.visibility.clone(),
                ident: ident!(parsed_enum.ident "Mutator"),
                generics,
                kind: StructKind::Struct,
                where_clause: Some(where_clause),
                struct_fields: mutator_struct_fields,
            },
        )
    };
    extend_ts!(tb, mutator_struct);

    /*
        the enum items to use for “Inner” version of mutator types
        e.g. if the original enum is:
        enum X {
            Aa(u8, u16)
            Bb { x: bool }
            Cc
        }
        then the inner items are:
            Aa { _0: _Aa_0_Type, _1: _Aa_1_Type }
            Bb { _x: _Bb_x_Type }
            Cc
    */
    let inner_items = items_for_derive
        .iter()
        .map(|item| EnumItem {
            attributes: Vec::new(),
            ident: item.item.ident.clone(),
            data: if item.fields.is_empty() {
                None
            } else {
                Some(EnumItemData::Struct(
                    StructKind::Struct,
                    item.fields
                        .iter()
                        .map(|field| StructField {
                            identifier: Some(field.name.clone()),
                            ty: ts!(field.mutator_ty),
                            ..<_>::default()
                        })
                        .collect(),
                ))
            },
        })
        .collect::<Vec<_>>();

    let (cache_enum, cache_struct) = {
        // mutator cache
        let cache_enum = Enum {
            visibility: parsed_enum.visibility.clone(),
            ident: ident!(parsed_enum.ident "InnerMutatorCache"),
            generics: basic_generics.clone(),
            where_clause: None,
            items: inner_items.clone(),
        };

        let cache_struct = Struct {
            visibility: parsed_enum.visibility.clone(),
            ident: ident!(parsed_enum.ident "MutatorCache"),
            generics: basic_generics.clone(),
            kind: StructKind::Struct,
            where_clause: None,
            struct_fields: vec![
                StructField {
                    identifier: Some(ident!("inner")),
                    ty: ts!(cache_enum.ident cache_enum.generics),
                    ..<_>::default()
                },
                StructField {
                    identifier: Some(ident!("cplx")),
                    ty: ts!("f64"),
                    ..<_>::default()
                },
            ],
        };

        (cache_enum, cache_struct)
    };

    extend_ts!(tb,
        "# [ derive ( core :: clone :: Clone ) ] "
        cache_enum
        "# [ derive ( core :: clone :: Clone ) ] "
        cache_struct
    );

    let (step_enum, step_struct) = {
        // mutation step
        let step_enum = Enum {
            visibility: parsed_enum.visibility.clone(),
            ident: ident!(parsed_enum.ident "InnerMutationStep"),
            generics: basic_generics.clone(),
            where_clause: None,
            items: inner_items.clone(),
        };

        let field_inner = StructField {
            identifier: Some(ident!("inner")),
            ty: ts!(step_enum.ident step_enum.generics),
            ..<_>::default()
        };
        let field_step = StructField {
            identifier: Some(ident!("step")),
            ty: ts!("u64"),
            ..<_>::default()
        };

        let step_struct = Struct {
            visibility: parsed_enum.visibility.clone(),
            ident: ident!(parsed_enum.ident "MutationStep"),
            generics: basic_generics.clone(),
            kind: StructKind::Struct,
            where_clause: None,
            struct_fields: vec![field_inner, field_step],
        };

        (step_enum, step_struct)
    };

    extend_ts!(tb,
        "# [ derive ( core :: clone :: Clone ) ] "
        step_enum
        "# [ derive ( core :: clone :: Clone ) ] "
        step_struct
    );

    let unmutate_enum = {
        let unmutate_enum = Enum {
            visibility: parsed_enum.visibility.clone(),
            ident: ident!(parsed_enum.ident "UnmutateToken"),
            generics: basic_generics.clone(),
            where_clause: None,
            items: inner_items
                .clone()
                .into_iter()
                .map(|inner_item| EnumItem {
                    data: match inner_item.data {
                        Some(EnumItemData::Struct(kind, fields)) => Some(EnumItemData::Struct(
                            kind,
                            fields
                                .into_iter()
                                .map(|field| StructField {
                                    ty: ts!(":: std :: option :: Option :: <" field.ty ">"),
                                    ..field
                                })
                                .collect(),
                        )),
                        data @ Some(EnumItemData::Discriminant(_)) | data @ None => data,
                    },
                    ..inner_item
                })
                .collect(),
        };
        unmutate_enum
    };

    tb.extend(&unmutate_enum);

    {
        // impl Mutator
        let parsed_enum_generics_without_bounds = parsed_enum.generics.removing_bounds_and_eq_type();
        let mutator_struct_generics_without_bounds = mutator_struct.generics.removing_bounds_and_eq_type();

        let cplx_choose_item = ((parsed_enum.items.len() as f64).log2() * 100.0).round() / 100.0;
        let enum_has_fields = items_for_derive.iter().find(|item| !item.fields.is_empty()).is_some();

        let items_with_fields_iter = items_for_derive.iter().filter(|item| !item.fields.is_empty());

        extend_ts!(tb,
            "impl" mutator_struct.generics "fuzzcheck_mutators :: fuzzcheck_traits :: Mutator for"
                mutator_struct.ident mutator_struct_generics_without_bounds mutator_struct.where_clause
            "{
                type Value = " parsed_enum.ident parsed_enum_generics_without_bounds ";
                type Cache = " 
                    cache_struct.ident cache_struct.generics.mutating_type_params(|tp|
                        tp.type_ident = ts!("<" tp.type_ident "as fuzzcheck_mutators :: fuzzcheck_traits :: Mutator > :: Cache")
                    )
                    ";
                type MutationStep = "
                    step_struct.ident step_struct.generics.mutating_type_params(|tp|
                        tp.type_ident = ts!("<" tp.type_ident "as fuzzcheck_mutators :: fuzzcheck_traits :: Mutator > :: MutationStep")
                    )
                    ";
                type UnmutateToken = "
                    unmutate_enum.ident unmutate_enum.generics.mutating_type_params(|tp|
                        tp.type_ident = ts!("<" tp.type_ident "as fuzzcheck_mutators :: fuzzcheck_traits :: Mutator > :: UnmutateToken")
                    )
                ";

                fn max_complexity ( & self ) -> f64 {"
                    cplx_choose_item
                    if enum_has_fields {
                        ts!(
                            "+ [ "
                                join_ts!(items_with_fields_iter.clone(), item,
                                    join_ts!(&item.fields, field,
                                        "self ." field.name ". max_complexity ( ) "
                                    , separator: "+")
                                , separator: ",")
                            "] . iter ( ) . max_by ( | x , y | x . partial_cmp ( y ) . unwrap_or ( core :: cmp :: Ordering :: Equal ) ) . unwrap ( )"
                        )
                    } else {
                        ts!()
                    }
                "}
                fn min_complexity ( & self ) -> f64 {"
                    cplx_choose_item
                    if enum_has_fields {
                        ts!(
                            "+ ["
                                join_ts!(items_with_fields_iter.clone(), item,
                                    join_ts!(&item.fields, field,
                                        "self ." field.name ". min_complexity ( ) "
                                    , separator: "+")
                                , separator: ",")
                            "] . iter ( ) . min_by ( | x , y | x . partial_cmp ( y ) . unwrap_or ( core :: cmp :: Ordering :: Equal ) ) . unwrap ( )"
                        )
                    } else {
                        ts!()
                    }
                "}
                fn complexity ( & self , value : & Self :: Value , cache : & Self :: Cache ) -> f64 { 
                    cache . cplx 
                }

                fn cache_from_value ( & self , value : & Self :: Value ) -> Self :: Cache {
                    match value {"
                        join_ts!(&items_for_derive, item,
                            if let Some(EnumItemData::Struct(kind, _)) = &item.item.data {
                                ts!(
                                    parsed_enum.ident "::" item.item.ident
                                    kind.open()
                                        join_ts!(&item.fields, f,
                                            opt_ts!(&f.field.identifier, f, f ":") f.name
                                        , separator: ",")
                                    kind.close()
                                    "=> {
                                        let mut cplx = " cplx_choose_item ";"
                                        join_ts!(&item.fields, f,
                                            "let" ident!("inner_" f.name) "= self ." f.name ". cache_from_value ( &" f.name ") ;"
                                            "cplx += self ." f.name ". complexity ( &" f.name ", &" ident!("inner_" f.name) " ) ;"
                                        )
                                        "let inner = XInnerMutatorCache :: " item.item.ident
                                        "{"
                                            join_ts!(&item.fields, f,
                                                f.name ":" ident!("inner_" f.name)
                                            , separator: ",")
                                        "} ;
                                        XMutatorCache {
                                            inner ,
                                            cplx ,
                                        }
                                    }"
                                )
                            } else {
                                ts!(
                                    parsed_enum.ident "::" item.item.ident "=> {
                                        XMutatorCache {
                                            inner : XInnerMutatorCache ::" item.item.ident ",
                                            cplx : " cplx_choose_item "
                                        }
                                    }"
                                )
                            }
                        )
                    "}
                }

                fn initial_step_from_value ( & self , value : & Self :: Value ) -> Self :: MutationStep {
                    match value {"
                        join_ts!(&items_for_derive, item,
                            if let Some(EnumItemData::Struct(kind, _)) = &item.item.data {
                                ts!(
                                    parsed_enum.ident "::" item.item.ident
                                    kind.open()
                                        join_ts!(&item.fields, f,
                                            opt_ts!(&f.field.identifier, ident, ident ":") f.name
                                        , separator: ",")
                                    kind.close()
                                    "=> {
                                        let inner = XInnerMutationStep :: " item.item.ident
                                        "{"
                                            join_ts!(&item.fields, f,
                                                f.name ": self ." f.name ". initial_step_from_value ( &" f.name ")"
                                            , separator: ",")
                                        "} ;
                                        let step = 0 ;
                                        XMutationStep {
                                            inner ,
                                            step ,
                                        }
                                    }"
                                )
                            } else {
                                ts!(
                                    parsed_enum.ident "::" item.item.ident "=> {
                                        XMutationStep {
                                            inner : XInnerMutationStep ::" item.item.ident ",
                                            step : 0
                                        }
                                    }"
                                )
                            }
                        )
                    "}
                }

                fn random_step_from_value ( & self , value : & Self :: Value ) -> Self :: MutationStep {
                    match value {"
                        join_ts!(items_for_derive, item,
                            if let Some(EnumItemData::Struct(kind, _)) = &item.item.data {
                                ts!(
                                    parsed_enum.ident "::" item.item.ident
                                    kind.open()
                                        join_ts!(&item.fields, f,
                                            opt_ts!(&f.field.identifier, ident, ident ":") f.name
                                        , separator: ",")
                                    kind.close()
                                    "=> {
                                        let inner = XInnerMutationStep :: " item.item.ident
                                        "{"
                                            join_ts!(&item.fields, f,
                                                f.name ": self ." f.name ". random_step_from_value ( &" f.name ")"
                                            , separator: ",")
                                        "} ;
                                        let step = self . rng . u64 ( .. ) ;
                                        XMutationStep {
                                            inner ,
                                            step ,
                                        }
                                    }"
                                )
                            } else {
                                ts!(
                                    parsed_enum.ident "::" item.item.ident "=> {
                                        XMutationStep {
                                            inner : XInnerMutationStep ::" item.item.ident ",
                                            step : self . rng . u64 ( .. )
                                        }
                                    }"
                                )
                            }
                        )
                    "}
                }

                fn ordered_arbitrary ( & mut self , step : usize , max_cplx : f64 ) -> Option < ( Self :: Value , Self :: Cache ) > {
                    todo ! ( )
                }

                fn random_arbitrary ( & mut self , max_cplx : f64 ) -> ( Self :: Value , Self :: Cache ) {
                    todo ! ( )
                }

                fn mutate ( & mut self , value : & mut Self :: Value , cache : & mut Self :: Cache , step : & mut Self :: MutationStep , max_cplx : f64 ) -> Option < Self :: UnmutateToken > {
                    todo ! ( )
                }

                fn unmutate ( & self , value : & mut Self :: Value , cache : & mut Self :: Cache , t : Self :: UnmutateToken ) {
                    todo ! ( )
                }
            }"
        )
    }
}

fn derive_unit_mutator(parsed_struct: Struct, tb: &mut TokenBuilder) {
    let generics_without_bounds = parsed_struct.generics.clone().removing_bounds_and_eq_type();
    let mutator_ident = ident!(parsed_struct.ident "Mutator");

    extend_ts!(tb,
        "type" mutator_ident generics_without_bounds
            "= fuzzcheck_mutators :: unit :: UnitMutator < " parsed_struct.ident generics_without_bounds "> ;"

        "impl" parsed_struct.generics "HasDefaultMutator for"
            parsed_struct.ident generics_without_bounds parsed_struct.where_clause
        "{
            type Mutator = " mutator_ident generics_without_bounds ";
            fn default_mutator ( ) -> Self :: Mutator {
                Self :: Mutator :: new ( " parsed_struct.ident " { } )
            }
        }"
    );
}
