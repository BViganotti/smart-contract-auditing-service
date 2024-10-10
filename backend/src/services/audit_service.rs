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
        match self.analyzer.analyze_smart_contract(&contract.code) {
            Ok(result) => {
                println!("audit_service: Audit completed successfully");
                result
            }
            Err(e) => {
                eprintln!("audit_service: Error during audit: {:?}", e);
                AnalysisResult::default()
            }
        }
    }
}
