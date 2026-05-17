use core::marker::PhantomData;

/// Entry kinds for base-field trace columns and public inputs.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum BaseEntry {
    Preprocessed { offset: usize },
    Main { offset: usize },
    Periodic,
    Public,
}

/// A variable within the evaluation window for base-field columns.
#[derive(Copy, Clone, Debug)]
pub struct SymbolicVariable<F> {
    pub entry: BaseEntry,
    pub index: usize,
    pub(crate) _phantom: PhantomData<F>,
}

impl<F> SymbolicVariable<F> {
    pub const fn new(entry: BaseEntry, index: usize) -> Self {
        Self {
            entry,
            index,
            _phantom: PhantomData,
        }
    }

    pub const fn degree_multiple(&self) -> usize {
        match self.entry {
            BaseEntry::Preprocessed { .. } | BaseEntry::Main { .. } | BaseEntry::Periodic => 1,
            BaseEntry::Public => 0,
        }
    }
}
