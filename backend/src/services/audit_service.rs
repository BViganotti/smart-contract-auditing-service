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
        let start_time = Instant::now();

        let mut result = AnalysisResult {
            warnings: Vec::new(),
            vulnerabilities: Vec::new(),
            gas_usage: GasUsage::default(),
            complexity_score: 0,
            function_complexities: HashMap::new(),
            analysis_result: String::new(),
            analysis_time: Duration::default(),
            pattern_results: Vec::new(),
            error: None,
        };

        // Parse and analyze the contract
        let analysis = self.analyzer.analyze_smart_contract(&contract.code);
        result.warnings = analysis.warnings;
        result.vulnerabilities = analysis.vulnerabilities;
        result.gas_usage = analysis.gas_usage;
        result.complexity_score = analysis.complexity_score;
        result.function_complexities = analysis.function_complexities;
        result.pattern_results = analysis.pattern_results;
        result.analysis_result = "Analysis completed successfully".to_string();
        result.analysis_time = start_time.elapsed();

        result
    }
}
