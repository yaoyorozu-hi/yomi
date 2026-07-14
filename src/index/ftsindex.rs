//! The SQLite FTS5 implementation of the [`Index`] trait. All SQL lives on
//! `Catalog`; this type is the thin trait binding so a future engine (tantivy)
//! can be dropped in without touching callers.

use crate::catalog::Catalog;
use crate::index::{Hit, Index, IndexDoc, Query};
use anyhow::Result;

pub struct FtsIndex<'a> {
    pub cat: &'a Catalog,
}

impl<'a> FtsIndex<'a> {
    pub fn new(cat: &'a Catalog) -> Self {
        FtsIndex { cat }
    }
}

impl Index for FtsIndex<'_> {
    fn upsert(&self, docs: &[IndexDoc]) -> Result<usize> {
        self.cat.transaction(|| {
            for d in docs {
                self.cat.insert_entry(d)?;
            }
            Ok(docs.len())
        })
    }

    fn query(&self, q: &Query) -> Result<Vec<Hit>> {
        self.cat.query_entries(q)
    }

    fn delete_session(&self, session_uuid: &str) -> Result<usize> {
        self.cat.transaction(|| {
            let n = self.cat.delete_entries_for_session(session_uuid)?;
            self.cat.delete_index_state_for_session(session_uuid)?;
            Ok(n)
        })
    }
}
