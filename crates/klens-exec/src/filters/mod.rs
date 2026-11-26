//! Pluggable, block-aware terminal command filters implementing `klens_core::CommandFilter`.
//!
//! Every filter receives ANSI-stripped text and strictly enforces Constitution Article 4:
//! on `exit_code != 0`, `truncated_errors` is ALWAYS `false` and error context blocks
//! are preserved line-for-line without loss.

pub mod cargo;
mod common;
pub mod docker;
pub mod dotnet;
pub mod eslint;
pub mod generic;
pub mod git;
pub mod go_test;
pub mod gradle;
pub mod make;
pub mod node;
pub mod pytest;

use klens_core::CommandFilter;

pub use cargo::CargoFilter;
pub use docker::DockerFilter;
pub use dotnet::DotnetFilter;
pub use eslint::EslintFilter;
pub use generic::GenericSafeFilter;
pub use git::GitFilter;
pub use go_test::GoTestFilter;
pub use gradle::GradleFilter;
pub use make::MakeFilter;
pub use node::NodePkgFilter;
pub use pytest::PytestFilter;

/// Ordered registry of `CommandFilter` implementations with `GenericSafeFilter` fallback.
pub struct FilterRegistry {
    filters: Vec<Box<dyn CommandFilter>>,
}

impl FilterRegistry {
    /// Build the default filter registry.
    ///
    /// Ordering note: `EslintFilter` MUST precede `NodePkgFilter` so `npx`/`pnpm`/`yarn`/`npm exec`
    /// invocations of `eslint` match `eslint` while `npx vitest`/`npm test`/`pnpm build`/`tsc`
    /// continue falling through to `node`.
    pub fn with_defaults() -> Self {
        Self {
            filters: vec![
                Box::new(CargoFilter),
                Box::new(GitFilter),
                Box::new(PytestFilter),
                Box::new(GoTestFilter),
                Box::new(EslintFilter),
                Box::new(NodePkgFilter),
                Box::new(DockerFilter),
                Box::new(MakeFilter),
                Box::new(GradleFilter),
                Box::new(DotnetFilter),
                Box::new(GenericSafeFilter),
            ],
        }
    }

    /// Select the first matching filter for `(program, args)`.
    /// Always falls back to `GenericSafeFilter`.
    pub fn select(&self, program: &str, args: &[String]) -> &dyn CommandFilter {
        for filter in &self.filters {
            if filter.matches(program, args) {
                return filter.as_ref();
            }
        }
        self.filters
            .last()
            .expect("FilterRegistry always contains fallback filter")
            .as_ref()
    }

    /// Look up a filter directly by its stable `id()` (used by `klens runs show`).
    pub fn by_id(&self, id: &str) -> &dyn CommandFilter {
        for filter in &self.filters {
            if filter.id() == id {
                return filter.as_ref();
            }
        }
        self.filters
            .last()
            .expect("FilterRegistry always contains fallback filter")
            .as_ref()
    }
}
