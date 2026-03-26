pub mod file_integrity;
pub mod log_analyzer;
pub mod network_hunter;
pub mod process_scanner;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

/// Threat severity levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Display)]
#[strum(serialize_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Single scan finding / IOC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub category: String,
    pub threat_score: u32,
    pub timestamp: DateTime<Utc>,
    pub artifacts: Vec<String>,
    pub mitre_technique: Option<String>,
    pub recommendations: Vec<String>,
}

impl ScanResult {
    pub fn new(
        title: impl Into<String>,
        description: impl Into<String>,
        severity: Severity,
        category: impl Into<String>,
        threat_score: u32,
    ) -> Self {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let title_str = title.into();
        let mut h = DefaultHasher::new();
        title_str.hash(&mut h);
        chrono::Utc::now().timestamp().hash(&mut h);
        let id = format!("LTHF-{:016X}", h.finish());

        Self {
            id,
            title: title_str,
            description: description.into(),
            severity,
            category: category.into(),
            threat_score,
            timestamp: Utc::now(),
            artifacts: Vec::new(),
            mitre_technique: None,
            recommendations: Vec::new(),
        }
    }

    pub fn with_artifacts(mut self, artifacts: Vec<String>) -> Self {
        self.artifacts = artifacts;
        self
    }

    pub fn with_mitre(mut self, technique: impl Into<String>) -> Self {
        self.mitre_technique = Some(technique.into());
        self
    }

    pub fn with_recommendations(mut self, recs: Vec<String>) -> Self {
        self.recommendations = recs;
        self
    }
}

/// Shannon entropy calculation for DNS tunneling detection
pub fn shannon_entropy(data: &str) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = std::collections::HashMap::new();
    for c in data.chars() {
        *freq.entry(c).or_insert(0u32) += 1;
    }
    let len = data.len() as f64;
    freq.values()
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}
