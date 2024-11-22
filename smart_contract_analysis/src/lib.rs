use analyzers::GovernanceAnalyzer;
use rayon::prelude::*;
use serde::Serialize;
use solang_parser::parse;
use solang_parser::pt::*;
use std::collections::HashMap;
use std::time::{Duration, Instant};

mod analyzers;
use analyzers::{
    IntegerOverflowAnalyzer,
    ReentrancyAnalyzer,
    UncheckedCallsAnalyzer,
    DosAnalyzer,
    TimestampAnalyzer,
    AccessControlAnalyzer,
    VulnerabilityAnalyzer,
    ComplexityAnalyzer,
    GasAnalyzer,
    OracleAnalyzer,
    FlashloanAnalyzer,
};

pub struct SmartContractAnalyzer {
    config: AnalyzerConfig,
}

pub struct AnalyzerConfig {
    max_contract_size: usize,
    enable_parallel: bool,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            max_contract_size: 10000,
            enable_parallel: true,
        }
    }
}

#[derive(Debug, Serialize, Default)]
pub struct GasUsage {
    pub estimated_deployment_cost: u64,
    pub estimated_function_costs: Vec<(String, u64)>,
}

#[derive(Debug, Serialize, Default)]
pub struct AnalysisResult {
    pub warnings: Vec<FormattedWarning>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub gas_usage: GasUsage,
    pub complexity_score: u32,
    pub function_complexities: HashMap<String, u32>,
    pub summary: AnalysisSummary,
    pub analysis_time: Duration,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Default)]
pub struct AnalysisSummary {
    pub total_vulnerabilities: usize,
    pub critical_vulnerabilities: usize,
    pub high_vulnerabilities: usize,
    pub medium_vulnerabilities: usize,
    pub low_vulnerabilities: usize,
    pub total_warnings: usize,
    pub gas_efficiency_score: u32,
    pub code_quality_score: u32,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct FormattedWarning {
    pub category: String,
    pub message: String,
    pub line_number: usize,
    pub code_snippet: String,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
pub enum VulnerabilityType {
    FlashLoanAttack,
    TimelockBypass,
    UnsafeDelegateCall,
    InsecureVoting,
    GasOptimization,
    UnprotectedGovernance,
    UncheckedCalls,
    IntegerOverflow,
    Reentrancy,
    DosVulnerability,
    HighComplexity,
    MevExposure,
    OracleManipulation,
    Composability,
    StateSync,
    UpgradePattern,
    AccessControlIssue,
}

impl Default for VulnerabilityType {
    fn default() -> Self {
        VulnerabilityType::UnprotectedGovernance
    }
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct Vulnerability {
    pub vulnerability_type: VulnerabilityType,
    pub severity: String,
    pub description: String,
    pub location: Location,
    pub code_snippet: Option<String>,
    pub recommendation: Option<String>,
    pub category: String,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct Location {
    pub start: usize,
    pub end: usize,
}

impl Location {
    pub fn from_loc(loc: &Loc) -> Self {
        Self {
            start: loc.start(),
            end: loc.end(),
        }
    }
}

impl SmartContractAnalyzer {
    pub fn new(config: AnalyzerConfig) -> Self {
        Self { config }
    }

    pub fn analyze_smart_contract(&self, contract_code: &str) -> AnalysisResult {
        let start_time = Instant::now();
        let mut result = AnalysisResult::default();

        // Parse the contract
        let (pt, messages) = match parse(contract_code, 0) {
            Ok((pt, messages)) => (pt, messages),
            Err(e) => {
                result.error = Some(format!("Failed to parse contract: {:?}", e));
                return result;
            }
        };

        // Filter out comments and only keep actual errors
        let errors: Vec<_> = messages
            .iter()
            .filter(|msg| !msg.to_string().starts_with("// "))
            .collect();

        if !errors.is_empty() {
            result.error = Some(format!("Parse errors: {}", errors.iter().map(|e| e.to_string()).collect::<Vec<_>>().join(", ")));
            return result;
        }

        let node_count = self.count_nodes(&pt);
        if node_count > self.config.max_contract_size {
            result.error = Some(format!(
                "Contract size ({} nodes) exceeds maximum allowed size ({} nodes)",
                node_count, self.config.max_contract_size
            ));
            return result;
        }

        // Initialize analyzers
        let analyzers: Vec<Box<dyn VulnerabilityAnalyzer + Send>> = vec![
            Box::new(IntegerOverflowAnalyzer::new()),
            Box::new(ReentrancyAnalyzer::new()),
            Box::new(UncheckedCallsAnalyzer::new()),
            Box::new(DosAnalyzer::new()),
            Box::new(TimestampAnalyzer::new()),
            Box::new(AccessControlAnalyzer::new()),
            Box::new(ComplexityAnalyzer::new()),
            Box::new(GasAnalyzer::new()),
            Box::new(OracleAnalyzer::new()),
            Box::new(FlashloanAnalyzer::new()),
            Box::new(GovernanceAnalyzer::new()),
            Box::new(OracleAnalyzer::new()),
            Box::new(GasAnalyzer::new()),
        ];

        // Run analyzers
        let vulnerabilities = if self.config.enable_parallel {
            analyzers
                .into_par_iter()
                .map(|mut analyzer| analyzer.analyze(&pt).unwrap_or_default())
                .reduce(Vec::new, |mut acc, vulns| {
                    acc.extend(vulns);
                    acc
                })
        } else {
            let mut vulns = Vec::new();
            for mut analyzer in analyzers {
                if let Ok(analyzer_vulns) = analyzer.analyze(&pt) {
                    vulns.extend(analyzer_vulns);
                }
            }
            vulns
        };

        result.vulnerabilities = vulnerabilities;

        // Calculate summary
        self.calculate_summary(&mut result);
        
        // Calculate gas usage and complexity
        result.gas_usage = self.estimate_gas_usage(&pt);
        result.complexity_score = self.calculate_complexity_score(&pt);
        
        result.analysis_time = start_time.elapsed();
        result
    }

    fn calculate_summary(&self, result: &mut AnalysisResult) {
        let mut summary = AnalysisSummary::default();
        
        for vuln in &result.vulnerabilities {
            summary.total_vulnerabilities += 1;
            match vuln.severity.as_str() {
                "Critical" => summary.critical_vulnerabilities += 1,
                "High" => summary.high_vulnerabilities += 1,
                "Medium" => summary.medium_vulnerabilities += 1,
                "Low" => summary.low_vulnerabilities += 1,
                _ => {}
            }
        }
        
        summary.total_warnings = result.warnings.len();
        summary.gas_efficiency_score = self.calculate_gas_efficiency_score(&result.gas_usage);
        summary.code_quality_score = self.calculate_code_quality_score(result);
        
        result.summary = summary;
    }

    fn calculate_gas_efficiency_score(&self, gas_usage: &GasUsage) -> u32 {
        let base_score: u32 = 100;
        let deployment_penalty = (gas_usage.estimated_deployment_cost / 1_000_000) as u32;
        let function_penalty = gas_usage.estimated_function_costs
            .iter()
            .map(|(_, cost)| (*cost / 100_000) as u32)
            .sum::<u32>();
            
        base_score.saturating_sub(deployment_penalty + function_penalty)
    }
    
    fn calculate_code_quality_score(&self, result: &AnalysisResult) -> u32 {
        let base_score: u32 = 100;
        let vulnerability_penalty = result.vulnerabilities.len() as u32 * 5;
        let warning_penalty = result.warnings.len() as u32 * 2;
        
        base_score.saturating_sub(vulnerability_penalty + warning_penalty)
    }

    fn calculate_complexity_score(&self, pt: &SourceUnit) -> u32 {
        let mut total_complexity = 0;
        
        for part in &pt.0 {
            if let SourceUnitPart::ContractDefinition(contract) = part {
                for part in &contract.parts {
                    if let ContractPart::FunctionDefinition(func) = part {
                        total_complexity += self.calculate_function_complexity(func);
                    }
                }
            }
        }
        
        total_complexity
    }

    fn calculate_function_complexity(&self, func: &FunctionDefinition) -> u32 {
        let mut complexity = 1; // Base complexity

        if let Some(body) = &func.body {
            complexity += self.calculate_statement_complexity(body);
        }

        complexity
    }

    fn calculate_statement_complexity(&self, stmt: &Statement) -> u32 {
        match stmt {
            Statement::Block { loc: _, unchecked: _, statements } => {
                statements.iter().map(|s| self.calculate_statement_complexity(s)).sum()
            }
            Statement::If(_, cond, then_stmt, else_stmt) => {
                1 + self.calculate_expression_complexity(cond) +
                self.calculate_statement_complexity(then_stmt) +
                else_stmt.as_ref().map_or(0, |s| self.calculate_statement_complexity(s))
            }
            Statement::While(_, cond, body) => {
                2 + self.calculate_expression_complexity(cond) +
                self.calculate_statement_complexity(body)
            }
            Statement::For(_loc, init, cond, post, body) => {
                2 + init.as_ref().map_or(0, |s| self.calculate_statement_complexity(s)) +
                cond.as_ref().map_or(0, |e| self.calculate_expression_complexity(e)) +
                post.as_ref().map_or(0, |e| self.calculate_expression_complexity(e)) +
                body.as_ref().map_or(0, |s| self.calculate_statement_complexity(s))
            }
            Statement::Expression(_, expr) => self.calculate_expression_complexity(expr),
            _ => 1,
        }
    }

    fn calculate_expression_complexity(&self, expr: &Expression) -> u32 {
        match expr {
            Expression::FunctionCall(_, func, args) => {
                1 + self.calculate_expression_complexity(func) +
                args.iter().map(|arg| self.calculate_expression_complexity(arg)).sum::<u32>()
            }
            Expression::MemberAccess(_, expr, _) => {
                1 + self.calculate_expression_complexity(expr)
            }
            Expression::ArraySubscript(_, array, index) => {
                1 + self.calculate_expression_complexity(array) + 
                index.as_ref().map_or(0, |e| self.calculate_expression_complexity(e))
            }
            _ => 1,
        }
    }

    fn estimate_gas_usage(&self, pt: &SourceUnit) -> GasUsage {
        let mut gas_usage = GasUsage::default();
        
        for part in &pt.0 {
            if let SourceUnitPart::ContractDefinition(contract) = part {
                gas_usage.estimated_deployment_cost += self.estimate_contract_deployment_cost(contract);
                
                for part in &contract.parts {
                    if let ContractPart::FunctionDefinition(func) = part {
                        let func_cost = self.estimate_function_cost(func);
                        if let Some(name) = &func.name {
                            gas_usage.estimated_function_costs.push((name.name.clone(), func_cost));
                        }
                    }
                }
            }
        }
        
        gas_usage
    }

    fn estimate_contract_deployment_cost(&self, contract: &ContractDefinition) -> u64 {
        let mut cost = 32000; // Base deployment cost
        
        for part in &contract.parts {
            match part {
                ContractPart::VariableDefinition(var) => {
                    cost += 20000; // Storage variable cost
                }
                ContractPart::FunctionDefinition(func) => {
                    cost += 10000; // Function definition cost
                }
                _ => {}
            }
        }
        
        cost
    }

    fn estimate_function_cost(&self, func: &FunctionDefinition) -> u64 {
        21000 // Base transaction cost
    }

    fn count_nodes(&self, pt: &SourceUnit) -> usize {
        1 + pt.0.iter().map(|part| self.count_source_unit_part(part)).sum::<usize>()
    }

    fn count_source_unit_part(&self, part: &SourceUnitPart) -> usize {
        match part {
            SourceUnitPart::ContractDefinition(contract) => {
                1 + contract.parts.iter().map(|part| self.count_contract_part(part)).sum::<usize>()
            }
            _ => 1,
        }
    }

    fn count_contract_part(&self, part: &ContractPart) -> usize {
        match part {
            ContractPart::FunctionDefinition(func) => {
                1 + if let Some(body) = &func.body {
                    self.count_statement(body)
                } else {
                    0
                }
            }
            _ => 1,
        }
    }

    fn count_statement(&self, statement: &Statement) -> usize {
        match statement {
            Statement::Block { loc: _, unchecked: _, statements } => {
                1 + statements.iter().map(|stmt| self.count_statement(stmt)).sum::<usize>()
            }
            Statement::If(_, cond, then_stmt, else_stmt) => {
                1 + self.count_expression(cond)
                    + self.count_statement(then_stmt)
                    + else_stmt.as_ref().map_or(0, |stmt| self.count_statement(stmt))
            }
            Statement::While(_, cond, body) => {
                1 + self.count_expression(cond) + self.count_statement(body)
            }
            Statement::For(loc, init, cond, post, body) => {
                1 + init.as_ref().map_or(0, |s| self.count_statement(s)) +
                cond.as_ref().map_or(0, |e| self.count_expression(e)) +
                post.as_ref().map_or(0, |e| self.count_expression(e)) +
                body.as_ref().map_or(0, |s| self.count_statement(s))
            }
            Statement::Expression(_, expr) => 1 + self.count_expression(expr),
            _ => 1,
        }
    }

    fn count_expression(&self, expr: &Expression) -> usize {
        match expr {
            Expression::FunctionCall(_, func, args) => {
                1 + self.count_expression(func)
                    + args.iter().map(|arg| self.count_expression(arg)).sum::<usize>()
            }
            Expression::MemberAccess(_, expr, _) => 1 + self.count_expression(expr),
            Expression::ArraySubscript(_, array, index) => {
                1 + self.count_expression(array) + 
                index.as_ref().map_or(0, |e| self.count_expression(e))
            }
            _ => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_smart_contract() {
        let analyzer = SmartContractAnalyzer::new(AnalyzerConfig::default());
        let result = analyzer.analyze_smart_contract(
            r#"
            contract Test {
                uint256 public value;
                
                function setValue(uint256 newValue) public {
                    value = newValue;
                }
            }
            "#,
        );
        
        assert!(result.error.is_none());
        assert!(result.analysis_time.as_secs() < 1);
    }
}