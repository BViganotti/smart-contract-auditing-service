use crate::models::SmartContract;
use smart_contract_analysis::{AnalysisResult, AnalyzerConfig, SmartContractAnalyzer};

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
        println!("audit_service: Auditing contract: {}", contract.id);
        println!("audit_service: Contract code: {}", contract.code);
        let result = self.analyzer.analyze_smart_contract(&contract.code);
        println!("audit_service: Audit completed");
        //if let Some(error) = &result.error {
        //    eprintln!("audit_service: Error during audit: {}", error);
        //}
        result
    }
}
