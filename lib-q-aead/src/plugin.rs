//! Plugin Architecture for AEAD Algorithms
//!
//! This module provides a plugin system that allows dynamic loading and registration
//! of AEAD algorithms at runtime.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{
    String,
    ToString,
};
use alloc::vec::Vec;

use lib_q_core::{
    Algorithm,
    Error,
    Result,
};

use crate::AeadWithMetadata;
use crate::metadata::AeadMetadata;

/// Plugin dependency information
#[derive(Debug, Clone, PartialEq)]
pub struct PluginDependency {
    /// Name of the dependency
    pub name: String,
    /// Required version range (e.g., ">=1.0.0,<2.0.0")
    pub version_range: String,
    /// Whether the dependency is optional
    pub optional: bool,
}

/// Plugin metadata with versioning and dependency information
#[derive(Debug, Clone)]
pub struct PluginInfo {
    /// Plugin name
    pub name: String,
    /// Plugin version
    pub version: String,
    /// Plugin description
    pub description: String,
    /// Plugin dependencies
    pub dependencies: Vec<PluginDependency>,
    /// Plugin author
    pub author: Option<String>,
    /// Plugin license
    pub license: Option<String>,
    /// Plugin repository URL
    pub repository: Option<String>,
}

/// Version comparison result
#[derive(Debug, Clone, PartialEq)]
pub enum VersionComparison {
    /// Versions are equal
    Equal,
    /// First version is greater than second
    Greater,
    /// First version is less than second
    Less,
    /// Versions cannot be compared (invalid format)
    Incompatible,
}

/// Plugin trait for AEAD algorithms
pub trait AeadPlugin: Send + Sync {
    /// Get the algorithm identifier for this plugin
    fn algorithm(&self) -> Algorithm;

    /// Create a new AEAD instance
    fn create(&self) -> Result<Box<dyn AeadWithMetadata>>;

    /// Get algorithm metadata
    fn metadata(&self) -> &'static AeadMetadata;

    /// Get plugin name
    fn name(&self) -> &'static str;

    /// Get plugin version
    fn version(&self) -> &'static str;

    /// Get plugin description
    fn description(&self) -> &'static str;

    /// Get detailed plugin information including dependencies
    fn info(&self) -> PluginInfo {
        PluginInfo {
            name: self.name().to_string(),
            version: self.version().to_string(),
            description: self.description().to_string(),
            dependencies: Vec::new(),
            author: None,
            license: None,
            repository: None,
        }
    }

    /// Check if plugin dependencies are satisfied
    fn check_dependencies(&self, _available_plugins: &BTreeMap<String, String>) -> Result<()> {
        // Default implementation: no dependencies
        Ok(())
    }
}

/// Version utility functions
impl PluginInfo {
    /// Compare two semantic versions
    pub fn compare_versions(version1: &str, version2: &str) -> VersionComparison {
        let v1_parts: Vec<u32> = version1.split('.').filter_map(|s| s.parse().ok()).collect();
        let v2_parts: Vec<u32> = version2.split('.').filter_map(|s| s.parse().ok()).collect();

        if v1_parts.len() != 3 || v2_parts.len() != 3 {
            return VersionComparison::Incompatible;
        }

        for (a, b) in v1_parts.iter().zip(v2_parts.iter()) {
            match a.cmp(b) {
                core::cmp::Ordering::Less => return VersionComparison::Less,
                core::cmp::Ordering::Greater => return VersionComparison::Greater,
                core::cmp::Ordering::Equal => continue,
            }
        }

        VersionComparison::Equal
    }

    /// Check if a version satisfies a version range
    pub fn version_satisfies_range(version: &str, range: &str) -> bool {
        // Simple version range checking (supports >=, <=, ==, >, <)
        if let Some(required) = range.strip_prefix(">=") {
            matches!(
                Self::compare_versions(version, required),
                VersionComparison::Greater | VersionComparison::Equal
            )
        } else if let Some(required) = range.strip_prefix("<=") {
            matches!(
                Self::compare_versions(version, required),
                VersionComparison::Less | VersionComparison::Equal
            )
        } else if let Some(required) = range.strip_prefix(">") {
            matches!(
                Self::compare_versions(version, required),
                VersionComparison::Greater
            )
        } else if let Some(required) = range.strip_prefix("<") {
            matches!(
                Self::compare_versions(version, required),
                VersionComparison::Less
            )
        } else if let Some(required) = range.strip_prefix("==") {
            matches!(
                Self::compare_versions(version, required),
                VersionComparison::Equal
            )
        } else {
            // Default to exact match
            matches!(
                Self::compare_versions(version, range),
                VersionComparison::Equal
            )
        }
    }
}

/// Registry for AEAD plugins with enhanced dependency management
pub struct PluginRegistry {
    plugins: Vec<Box<dyn AeadPlugin>>,
    plugin_versions: BTreeMap<String, String>,
}

impl PluginRegistry {
    /// Create a new plugin registry
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
            plugin_versions: BTreeMap::new(),
        }
    }

    /// Register a plugin with dependency checking
    pub fn register_plugin(&mut self, plugin: Box<dyn AeadPlugin>) -> Result<()> {
        // Check for duplicate algorithms
        let algorithm = plugin.algorithm();
        if self.plugins.iter().any(|p| p.algorithm() == algorithm) {
            return Err(Error::InvalidState {
                operation: "register_plugin".to_string(),
                reason: "Algorithm already registered".to_string(),
            });
        }

        // Check plugin dependencies
        plugin.check_dependencies(&self.plugin_versions)?;

        // Register the plugin
        let plugin_name = plugin.name().to_string();
        let plugin_version = plugin.version().to_string();
        self.plugin_versions
            .insert(plugin_name.clone(), plugin_version);
        self.plugins.push(plugin);

        Ok(())
    }

    /// Get plugin information by name
    pub fn get_plugin_info(&self, name: &str) -> Option<PluginInfo> {
        self.plugins
            .iter()
            .find(|p| p.name() == name)
            .map(|p| p.info())
    }

    /// List all registered plugins with their versions
    pub fn list_plugins(&self) -> Vec<PluginInfo> {
        self.plugins.iter().map(|p| p.info()).collect()
    }

    /// Check if a plugin version is compatible
    pub fn is_plugin_compatible(&self, name: &str, required_version: &str) -> bool {
        if let Some(version) = self.plugin_versions.get(name) {
            PluginInfo::version_satisfies_range(version, required_version)
        } else {
            false
        }
    }

    /// Get a plugin by algorithm
    pub fn get_plugin(&self, algorithm: Algorithm) -> Option<&dyn AeadPlugin> {
        self.plugins
            .iter()
            .find(|p| p.algorithm() == algorithm)
            .map(|p| p.as_ref())
    }

    /// Create an AEAD instance using a plugin
    pub fn create_aead(&self, algorithm: Algorithm) -> Result<Box<dyn AeadWithMetadata>> {
        let plugin = self
            .get_plugin(algorithm)
            .ok_or_else(|| Error::UnsupportedAlgorithm {
                algorithm: "Plugin not found".to_string(),
            })?;

        plugin.create()
    }

    /// Get all registered algorithms
    pub fn available_algorithms(&self) -> Vec<Algorithm> {
        self.plugins.iter().map(|p| p.algorithm()).collect()
    }

    /// Get all plugins
    pub fn plugins(&self) -> &[Box<dyn AeadPlugin>] {
        &self.plugins
    }

    /// Check if an algorithm is available
    pub fn is_available(&self, algorithm: Algorithm) -> bool {
        self.plugins.iter().any(|p| p.algorithm() == algorithm)
    }

    /// Get plugin metadata for an algorithm
    pub fn get_metadata(&self, algorithm: Algorithm) -> Option<&'static AeadMetadata> {
        self.get_plugin(algorithm).map(|p| p.metadata())
    }

    /// Get all plugin metadata
    pub fn get_all_metadata(&self) -> Vec<&'static AeadMetadata> {
        self.plugins.iter().map(|p| p.metadata()).collect()
    }

    /// Remove a plugin
    pub fn remove_plugin(&mut self, algorithm: Algorithm) -> Result<()> {
        let initial_len = self.plugins.len();
        self.plugins.retain(|p| p.algorithm() != algorithm);

        if self.plugins.len() == initial_len {
            Err(Error::UnsupportedAlgorithm {
                algorithm: "Plugin not found".to_string(),
            })
        } else {
            Ok(())
        }
    }

    /// Clear all plugins
    pub fn clear(&mut self) {
        self.plugins.clear();
    }

    /// Get plugin count
    pub fn plugin_count(&self) -> usize {
        self.plugins.len()
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Macro to create a plugin implementation
#[macro_export]
macro_rules! impl_aead_plugin {
    ($struct_name:ident, $algorithm:expr, $name:expr, $version:expr, $description:expr) => {
        impl $crate::plugin::AeadPlugin for $struct_name {
            fn algorithm(&self) -> lib_q_core::Algorithm {
                $algorithm
            }

            fn create(&self) -> lib_q_core::Result<alloc::boxed::Box<dyn lib_q_core::Aead>> {
                Ok(alloc::boxed::Box::new(Self::new()))
            }

            fn metadata(&self) -> &'static $crate::metadata::AeadMetadata {
                $crate::metadata::get_metadata($algorithm)
                    .expect("Metadata not found for algorithm")
            }

            fn name(&self) -> &'static str {
                $name
            }

            fn version(&self) -> &'static str {
                $version
            }

            fn description(&self) -> &'static str {
                $description
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use lib_q_core::{
        Aead,
        AeadKey,
        Nonce,
    };

    use super::*;

    // Mock plugin for testing
    struct MockPlugin {
        algorithm: Algorithm,
    }

    impl MockPlugin {
        fn new(algorithm: Algorithm) -> Self {
            Self { algorithm }
        }
    }

    impl AeadPlugin for MockPlugin {
        fn algorithm(&self) -> Algorithm {
            self.algorithm
        }

        fn create(&self) -> Result<Box<dyn AeadWithMetadata>> {
            Ok(Box::new(MockAead))
        }

        fn metadata(&self) -> &'static AeadMetadata {
            crate::metadata::get_metadata(self.algorithm).expect("Metadata not found")
        }

        fn name(&self) -> &'static str {
            "Mock Plugin"
        }

        fn version(&self) -> &'static str {
            "1.0.0"
        }

        fn description(&self) -> &'static str {
            "Mock plugin for testing"
        }
    }

    struct MockAead;

    impl Aead for MockAead {
        fn encrypt(
            &self,
            _key: &AeadKey,
            _nonce: &Nonce,
            _plaintext: &[u8],
            _associated_data: Option<&[u8]>,
        ) -> Result<Vec<u8>> {
            Ok(alloc::vec![1, 2, 3, 4])
        }

        fn decrypt(
            &self,
            _key: &AeadKey,
            _nonce: &Nonce,
            _ciphertext: &[u8],
            _associated_data: Option<&[u8]>,
        ) -> Result<Vec<u8>> {
            Ok(alloc::vec![5, 6, 7, 8])
        }
    }

    impl AeadWithMetadata for MockAead {
        fn metadata(&self) -> &'static AeadMetadata {
            crate::metadata::get_metadata(Algorithm::Saturnin).expect("Metadata not found")
        }
    }

    #[test]
    fn test_plugin_registry_creation() {
        let registry = PluginRegistry::new();
        assert_eq!(registry.plugin_count(), 0);
        assert!(registry.available_algorithms().is_empty());
    }

    #[test]
    fn test_plugin_registration() {
        let mut registry = PluginRegistry::new();

        let plugin = Box::new(MockPlugin::new(Algorithm::Saturnin));
        let result = registry.register_plugin(plugin);

        assert!(result.is_ok());
        assert_eq!(registry.plugin_count(), 1);
        assert!(registry.is_available(Algorithm::Saturnin));
        assert!(
            registry
                .available_algorithms()
                .contains(&Algorithm::Saturnin)
        );
    }

    #[test]
    fn test_duplicate_plugin_registration() {
        let mut registry = PluginRegistry::new();

        let plugin1 = Box::new(MockPlugin::new(Algorithm::Saturnin));
        let plugin2 = Box::new(MockPlugin::new(Algorithm::Saturnin));

        registry.register_plugin(plugin1).unwrap();
        let result = registry.register_plugin(plugin2);

        assert!(result.is_err());
        if let Err(Error::InvalidState { operation, reason }) = result {
            assert_eq!(operation, "register_plugin");
            assert!(reason.contains("already registered"));
        } else {
            panic!("Expected InvalidState error");
        }
    }

    #[test]
    fn test_plugin_creation() {
        let mut registry = PluginRegistry::new();

        let plugin = Box::new(MockPlugin::new(Algorithm::Saturnin));
        registry.register_plugin(plugin).unwrap();

        let aead = registry.create_aead(Algorithm::Saturnin);
        assert!(aead.is_ok());
    }

    #[test]
    fn test_plugin_metadata() {
        let mut registry = PluginRegistry::new();

        let plugin = Box::new(MockPlugin::new(Algorithm::Saturnin));
        registry.register_plugin(plugin).unwrap();

        let metadata = registry.get_metadata(Algorithm::Saturnin);
        assert!(metadata.is_some());

        if let Some(meta) = metadata {
            assert_eq!(meta.algorithm, Algorithm::Saturnin);
        }
    }

    #[test]
    fn test_plugin_removal() {
        let mut registry = PluginRegistry::new();

        let plugin = Box::new(MockPlugin::new(Algorithm::Saturnin));
        registry.register_plugin(plugin).unwrap();

        assert_eq!(registry.plugin_count(), 1);

        let result = registry.remove_plugin(Algorithm::Saturnin);
        assert!(result.is_ok());
        assert_eq!(registry.plugin_count(), 0);
        assert!(!registry.is_available(Algorithm::Saturnin));
    }

    #[test]
    fn test_plugin_clear() {
        let mut registry = PluginRegistry::new();

        let plugin1 = Box::new(MockPlugin::new(Algorithm::Saturnin));
        let plugin2 = Box::new(MockPlugin::new(Algorithm::Shake256Aead));

        registry.register_plugin(plugin1).unwrap();
        registry.register_plugin(plugin2).unwrap();

        assert_eq!(registry.plugin_count(), 2);

        registry.clear();
        assert_eq!(registry.plugin_count(), 0);
        assert!(registry.available_algorithms().is_empty());
    }

    #[test]
    fn test_unsupported_algorithm() {
        let registry = PluginRegistry::new();

        let result = registry.create_aead(Algorithm::Saturnin);
        assert!(result.is_err());

        if let Err(Error::UnsupportedAlgorithm { algorithm }) = result {
            assert!(algorithm.contains("not found"));
        } else {
            panic!("Expected UnsupportedAlgorithm error");
        }
    }
}
