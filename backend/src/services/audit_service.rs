use crate::models::SmartContract;
use smart_contract_analysis::{AnalysisResult, AnalyzerConfig, GasUsage, SmartContractAnalyzer};
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct AuditService {
    analyzer: SmartContractAnalyzer,
}

impl AuditService {
    pub fn new() -> Self {
        let config = AnalyzerConfig::default();
        let analyzer = SmartContractAnalyzer::new(config);
        AuditService { analyzer }
    }

    pub fn audit_contract(&self, contract: SmartContract) -> AnalysisResult {
        // Perform the analysis
        self.analyzer.analyze_smart_contract(&contract.code)
    }
}
