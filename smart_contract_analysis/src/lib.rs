use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use solang_parser::parse;
use solang_parser::pt::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

#[derive(Debug, Serialize, Default, Clone)]
pub struct PatternResult {
    pub pattern_index: usize,
    pub location: Location,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct Vulnerability {
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Default for Severity {
    fn default() -> Self {
        Severity::Low
    }
}

impl ToString for Severity {
    fn to_string(&self) -> String {
        match self {
            Severity::Low => "Low".to_string(),
            Severity::Medium => "Medium".to_string(),
            Severity::High => "High".to_string(),
            Severity::Critical => "Critical".to_string(),
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

        // Perform various checks
        if self.config.enable_parallel {
            self.parallel_analysis(&pt, &mut result);
        } else {
            self.sequential_analysis(&pt, &mut result);
        }

        // Perform static analysis
        self.static_analysis(&mut result, &pt);

        // Calculate summary
        let mut summary = AnalysisSummary::default();
        summary.total_vulnerabilities = result.vulnerabilities.len();
        summary.total_warnings = result.warnings.len();
        
        for vuln in &result.vulnerabilities {
            match vuln.severity.as_str() {
                "Critical" => summary.critical_vulnerabilities += 1,
                "High" => summary.high_vulnerabilities += 1,
                "Medium" => summary.medium_vulnerabilities += 1,
                "Low" => summary.low_vulnerabilities += 1,
                _ => {}
            }
        }
        
        // Calculate scores
        summary.gas_efficiency_score = self.calculate_gas_efficiency_score(&result.gas_usage);
        summary.code_quality_score = self.calculate_code_quality_score(&result);
        
        result.summary = summary;
        result.analysis_time = start_time.elapsed();

        result
    }
    
    fn calculate_gas_efficiency_score(&self, gas_usage: &GasUsage) -> u32 {
        // Implementation of gas efficiency scoring
        let base_score: u32 = 100;
        let deployment_penalty = (gas_usage.estimated_deployment_cost / 1_000_000) as u32;
        let function_penalty = gas_usage.estimated_function_costs
            .iter()
            .map(|(_, cost)| (*cost / 100_000) as u32)
            .sum::<u32>();
            
        base_score.saturating_sub(deployment_penalty + function_penalty)
    }
    
    fn calculate_code_quality_score(&self, result: &AnalysisResult) -> u32 {
        // Implementation of code quality scoring
        let base_score: u32 = 100;
        let vulnerability_penalty = result.vulnerabilities.len() as u32 * 10;
        let warning_penalty = result.warnings.len() as u32 * 5;
        let complexity_penalty = result.complexity_score / 10;
        
        base_score.saturating_sub(vulnerability_penalty + warning_penalty + complexity_penalty)
    }

    fn parallel_analysis(&self, pt: &SourceUnit, result: &mut AnalysisResult) {
        let checks: Vec<(&str, fn(&Self, &SourceUnit, &mut AnalysisResult))> = vec![
            ("Reentrancy", Self::check_reentrancy),
            ("Unchecked External Calls", Self::check_unchecked_calls),
            ("Integer Overflow/Underflow", Self::check_integer_overflow),
            ("Tx.origin", Self::check_tx_origin),
            ("Events", Self::check_events),
            ("Deprecated Functions", Self::check_deprecated_functions),
            ("Assert/Require/Revert", Self::check_assert_require_revert),
            ("Access Control", Self::check_access_control),
            ("Front Running", Self::check_front_running),
            ("Timestamp Dependency", Self::check_timestamp_dependency),
            ("DoS", Self::check_dos_vectors),
            ("Arithmetic Precision", Self::check_arithmetic_precision),
            ("Storage Layout", Self::check_storage_layout),
            ("Randomness", Self::check_randomness),
            ("Upgrade Pattern", Self::check_upgrade_pattern),
            ("Flash Loan Attack", Self::check_flash_loan_vulnerability),
            ("Signature Replay", Self::check_signature_replay),
            ("Uninitialized Storage", Self::check_uninitialized_storage),
            ("Locked Ether", Self::check_locked_ether),
            ("Arbitrary Jump", Self::check_arbitrary_jump),
            ("Delegate Call", Self::check_delegate_call),
            ("Block Gas Limit", Self::check_block_gas_limit),
            ("Function Default Visibility", Self::check_function_visibility),
            ("Unchecked Return Values", Self::check_unchecked_return_values),
            ("Short Address Attack", Self::check_short_address),
            ("Race Condition", Self::check_race_condition),
            ("Denial of Service by Block Gas Limit", Self::check_dos_gas_limit),
            ("Forcibly Sending Ether", Self::check_forcibly_sending_ether),
            ("Weak Random Number Generation", Self::check_weak_prng),
            ("Unchecked Constructor", Self::check_unchecked_constructor),
            ("ERC20 Compliance", Self::check_erc20_compliance),
            ("ERC721 Compliance", Self::check_erc721_compliance),
            ("Proxy Pattern Safety", Self::check_proxy_pattern),
            ("Cross-Contract Reentrancy", Self::check_cross_contract_reentrancy),
            ("Oracle Manipulation", Self::check_oracle_manipulation),
            ("Sandwich Attack Vulnerability", Self::check_sandwich_attack),
            ("Malicious Token Integration", Self::check_malicious_token),
            ("MEV Vulnerability", Self::check_mev_vulnerability),
            ("Access Control Hierarchy", Self::check_access_control_hierarchy),
            ("Centralization Risks", Self::check_centralization_risks),
            ("Flashloan Resistance", Self::check_flashloan_resistance),
            ("Price Oracle Freshness", Self::check_price_oracle_freshness),
            ("Governance Attack Vectors", Self::check_governance_attack_vectors),
            ("Composability Risks", Self::check_composability_risks),
            ("ECDSA Implementation", Self::check_ecdsa_implementation),
            ("Hash Function Usage", Self::check_hash_function_security),
            ("Random Number Generation", Self::check_cryptographic_rng),
            ("Key Management", Self::check_key_management),
            ("Signature Malleability", Self::check_signature_malleability),
            ("Zero Knowledge Proof", Self::check_zk_proof_implementation),
            ("Commitment Scheme", Self::check_commitment_schemes),
            ("Encryption Implementation", Self::check_encryption_implementation),
            ("Digital Signature Usage", Self::check_digital_signature_usage),
            ("Replay Protection", Self::check_advanced_replay_protection),
            ("Cryptographic Protocol", Self::check_cryptographic_protocol),
            ("Side Channel Resistance", Self::check_side_channel_resistance),
            ("Timing Attack Vulnerability", Self::check_timing_attack),
            ("Authorization", Self::check_tx_origin),
            ("Reentrancy", Self::check_reentrancy),
            ("Arithmetic", Self::check_integer_overflow),
        ];

        let result_arc = Arc::new(Mutex::new(AnalysisResult::default()));

        checks.par_iter().for_each(|&(_name, check)| {
            let mut local_result = AnalysisResult::default();
            check(self, pt, &mut local_result);
            let mut shared_result = result_arc.lock().unwrap();
            shared_result.warnings.extend(local_result.warnings);
            shared_result
                .vulnerabilities
                .extend(local_result.vulnerabilities);
        });

        // Merge the results back into the original result
        let shared_result = result_arc.lock().unwrap();
        result.warnings.extend(shared_result.warnings.clone());
        result
            .vulnerabilities
            .extend(shared_result.vulnerabilities.clone());
    }

    fn sequential_analysis(&self, pt: &SourceUnit, result: &mut AnalysisResult) {
        self.check_reentrancy(pt, result);
        self.check_unchecked_calls(pt, result);
        self.check_deprecated_functions(pt, result);
        self.check_assert_require_revert(pt, result);
        self.check_integer_overflow(pt, result);
        self.check_tx_origin(pt, result);
        self.check_events(pt, result);
    }

    fn static_analysis(&self, result: &mut AnalysisResult, pt: &SourceUnit) {
        let contracts: Vec<_> = pt.0
            .iter()
            .filter_map(|part| {
                if let SourceUnitPart::ContractDefinition(contract) = part {
                    Some(contract)
                } else {
                    None
                }
            })
            .collect();

        if self.config.enable_parallel {
            let function_complexities: HashMap<_, _> = contracts
                .par_iter()
                .flat_map(|contract| {
                    contract
                        .parts
                        .par_iter()
                        .filter_map(|part| {
                            if let ContractPart::FunctionDefinition(func) = part {
                                Some((
                                    format!(
                                        "{}::{}",
                                        contract.name.as_ref().map_or("Unknown", |n| &n.name),
                                        func.name.as_ref().map_or("unnamed", |n| &n.name)
                                    ),
                                    self.calculate_function_complexity(func),
                                ))
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<_>>()
                })
                .collect();

            result.function_complexities = function_complexities;
        } else {
            for contract in contracts {
                for part in &contract.parts {
                    if let ContractPart::FunctionDefinition(func) = part {
                        let complexity = self.calculate_function_complexity(func);
                        result.function_complexities.insert(
                            format!(
                                "{}::{}",
                                contract.name.as_ref().map_or("Unknown", |n| &n.name),
                                func.name.as_ref().map_or("unnamed", |n| &n.name)
                            ),
                            complexity,
                        );
                    }
                }
            }
        }

        result.complexity_score = result.function_complexities.values().sum();
        result.gas_usage = self.estimate_gas_usage(pt);

        let total_nodes = self.count_nodes(pt);
        result.complexity_score += total_nodes as u32;

        for part in &pt.0 {
            if let SourceUnitPart::ContractDefinition(contract) = part {
                let contract_nodes = self.count_source_unit_part(part);
                let contract_name = contract.name.as_ref().map_or("Unknown", |n| &n.name);
                
                if contract_nodes > 500 {
                    result.warnings.push(FormattedWarning {
                        category: "Contract Size".to_string(),
                        message: format!(
                            "Contract '{}' is large ({} nodes). Consider breaking it into smaller contracts.",
                            contract_name, contract_nodes
                        ),
                        line_number: contract.loc.start(),
                        code_snippet: "".to_string(),
                    });
                }

                for part in &contract.parts {
                    if let ContractPart::FunctionDefinition(func) = part {
                        let func_nodes = self.count_contract_part(part);
                        let func_name = func.name.as_ref().map_or("unnamed", |n| &n.name);
                        
                        if func_nodes > 50 {
                            result.warnings.push(FormattedWarning {
                                category: "Function Size".to_string(),
                                message: format!(
                                    "Function '{}' in contract '{}' is complex ({} nodes). Consider breaking it into smaller functions.",
                                    func_name, contract_name, func_nodes
                                ),
                                line_number: func.loc.start(),
                                code_snippet: "".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    fn estimate_gas_usage(&self, pt: &SourceUnit) -> GasUsage {
        let mut gas_usage = GasUsage::default();

        for part in &pt.0 {
            if let SourceUnitPart::ContractDefinition(contract) = part {
                gas_usage.estimated_deployment_cost = self.estimate_contract_deployment_cost(contract);

                // Analyze each function's gas usage
                for part in &contract.parts {
                    if let ContractPart::FunctionDefinition(func) = part {
                        let function_name = func.name.as_ref().map_or("unnamed", |n| &n.name).to_string();
                        let cost = self.estimate_function_cost(func);
                        gas_usage.estimated_function_costs.push((function_name, cost));

                        // Check for gas optimization opportunities
                        self.analyze_function_gas_optimizations(func, &mut gas_usage);
                    }
                }

                // Analyze storage layout efficiency
                self.analyze_storage_layout_efficiency(contract, &mut gas_usage);
            }
        }

        gas_usage
    }

    fn analyze_function_gas_optimizations(&self, func: &FunctionDefinition, gas_usage: &mut GasUsage) {
        if let Some(body) = &func.body {
            // Check for expensive operations in loops
            self.check_loop_operations(body, gas_usage);
            
            // Check for redundant storage reads
            self.check_storage_access_patterns(body, gas_usage);
            
            // Check for memory vs storage usage
            self.check_memory_usage(body, gas_usage);
        }
    }

    fn check_loop_operations(&self, stmt: &Statement, gas_usage: &mut GasUsage) {
        match stmt {
            Statement::ForLoop { body, .. } | Statement::WhileLoop { body, .. } => {
                // Check for expensive operations inside loops
                let expensive_ops = self.find_expensive_operations(body);
                if !expensive_ops.is_empty() {
                    gas_usage.estimated_function_costs.push((
                        "loop_optimization".to_string(),
                        expensive_ops.len() as u64 * 1000,
                    ));
                }
            }
            Statement::Block { statements, .. } => {
                for stmt in statements {
                    self.check_loop_operations(stmt, gas_usage);
                }
            }
            _ => {}
        }
    }

    fn find_expensive_operations(&self, stmt: &Statement) -> Vec<String> {
        let mut expensive_ops = Vec::new();
        
        match stmt {
            Statement::Expression(_, expr) => {
                if let Expression::FunctionCall(_, name, _) = expr {
                    if let Expression::Variable(id) = &**name {
                        // List of expensive operations
                        let expensive = [
                            "storage", "sload", "sstore", "call", "delegatecall",
                            "staticcall", "create", "create2", "log", "sha3",
                        ];
                        
                        if expensive.iter().any(|&op| id.name.contains(op)) {
                            expensive_ops.push(id.name.clone());
                        }
                    }
                }
            }
            Statement::Block { statements, .. } => {
                for stmt in statements {
                    expensive_ops.extend(self.find_expensive_operations(stmt));
                }
            }
            _ => {}
        }
        
        expensive_ops
    }

    fn check_storage_access_patterns(&self, stmt: &Statement, gas_usage: &mut GasUsage) {
        let mut storage_reads = std::collections::HashMap::new();
        self.collect_storage_reads(stmt, &mut storage_reads);
        
        // Identify redundant storage reads
        for (var_name, count) in storage_reads {
            if count > 1 {
                gas_usage.estimated_function_costs.push((
                    format!("redundant_storage_read_{}", var_name),
                    count as u64 * 800, // SLOAD cost
                ));
            }
        }
    }

    fn collect_storage_reads(&self, stmt: &Statement, reads: &mut std::collections::HashMap<String, u32>) {
        match stmt {
            Statement::Expression(_, expr) => {
                if let Expression::Variable(id) = expr {
                    reads.entry(id.name.clone())
                        .and_modify(|count| *count += 1)
                        .or_insert(1);
                }
            }
            Statement::Block { statements, .. } => {
                for stmt in statements {
                    self.collect_storage_reads(stmt, reads);
                }
            }
            _ => {}
        }
    }

    fn check_memory_usage(&self, stmt: &Statement, gas_usage: &mut GasUsage) {
        match stmt {
            Statement::Block { statements, loc: _, unchecked: _ } => {
                for stmt in statements {
                    self.check_memory_usage(stmt, gas_usage);
                }
            }
            Statement::VariableDefinition(_, _, expr) => {
                if let Some(expr) = expr {
                    self.analyze_memory_expr(expr, gas_usage);
                }
            }
            Statement::Expression(_, expr) => {
                self.analyze_memory_expr(expr, gas_usage);
            }
            _ => {}
        }
    }

    fn analyze_memory_expr(&self, expr: &Expression, gas_usage: &mut GasUsage) {
        match expr {
            Expression::ArrayLiteral(_, elements) => {
                gas_usage.estimated_deployment_cost += (elements.len() as u64) * 20;
            }
            Expression::StringLiteral(_, value) => {
                gas_usage.estimated_deployment_cost += (value.len() as u64) * 4;
            }
            _ => {}
        }
    }

    fn analyze_storage_layout_efficiency(&self, contract: &ContractDefinition, gas_usage: &mut GasUsage) {
        for part in &contract.parts {
            if let ContractPart::VariableDefinition(var) = part {
                if let Expression::Type(_, ty) = &var.ty {
                    let size = self.get_type_size(ty);
                    
                    // Check if variable can fit in current slot
                    if size <= 32 {
                        // Start new slot
                        gas_usage.estimated_function_costs.push((
                            "storage_layout_optimization".to_string(),
                            size as u64 * 200,
                        ));
                    } else {
                        // Start new slot
                        gas_usage.estimated_function_costs.push((
                            "storage_layout_optimization".to_string(),
                            (size / 32) as u64 * 200,
                        ));
                    }
                }
            }
        }

        // Calculate wasted storage
        let wasted_bytes: u32 = 0;
            
        if wasted_bytes > 0 {
            gas_usage.estimated_function_costs.push((
                "storage_layout_optimization".to_string(),
                wasted_bytes as u64 * 200,
            ));
        }
    }

    fn get_type_size(&self, ty: &Type) -> u32 {
        match ty {
            Type::Address => 20,
            Type::Bool => 1,
            Type::Uint(size) => *size as u32 / 8,
            Type::Int(size) => *size as u32 / 8,
            Type::Bytes(size) => *size as u32,
            _ => 32, // Default to full slot for complex types
        }
    }

    fn check_reentrancy(&self, pt: &SourceUnit, result: &mut AnalysisResult) {
        for part in &pt.0 {
            if let SourceUnitPart::ContractDefinition(contract) = part {
                for part in &contract.parts {
                    if let ContractPart::FunctionDefinition(func) = part {
                        if self.function_has_reentrancy(func) {
                            result.vulnerabilities.push(Vulnerability {
                                severity: Severity::High.to_string(),
                                description: format!(
                                    "Potential reentrancy vulnerability in function '{}'. The function makes external calls and modifies state afterwards.",
                                    func.name.as_ref().map_or("unnamed", |n| &n.name)
                                ),
                                location: Location::from_loc(&func.loc),
                                code_snippet: None,
                                recommendation: None,
                                category: "Reentrancy".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    fn function_has_reentrancy(&self, func: &FunctionDefinition) -> bool {
        let mut has_external_call = false;
        let mut has_state_change_after_call = false;

        if let Some(body) = &func.body {
            self.analyze_statement(
                body,
                &mut has_external_call,
                &mut has_state_change_after_call,
            );
        }

        has_external_call && has_state_change_after_call
    }

    fn analyze_statement(
        &self,
        stmt: &Statement,
        has_external_call: &mut bool,
        has_state_change_after_call: &mut bool,
    ) {
        match stmt {
            Statement::Block { statements, .. } => {
                for stmt in statements {
                    self.analyze_statement(stmt, has_external_call, has_state_change_after_call);
                }
            }
            Statement::Expression(_, expr) => {
                self.analyze_expression(expr, has_external_call, has_state_change_after_call);
            }
            Statement::VariableDefinition(_, _, Some(expr)) => {
                self.analyze_expression(expr, has_external_call, has_state_change_after_call);
            }
            Statement::If(_, cond, then_stmt, else_stmt) => {
                self.analyze_expression(cond, has_external_call, has_state_change_after_call);
                self.analyze_statement(then_stmt, has_external_call, has_state_change_after_call);
                if let Some(else_stmt) = else_stmt {
                    self.analyze_statement(
                        else_stmt,
                        has_external_call,
                        has_state_change_after_call,
                    );
                }
            }
            // Add other statement types as needed
            _ => {}
        }
    }

    fn analyze_expression(
        &self,
        expr: &Expression,
        has_external_call: &mut bool,
        has_state_change_after_call: &mut bool,
    ) {
        match expr {
            Expression::FunctionCall(_, name, _) => {
                if let Expression::MemberAccess(_, member_expr, member) = &**name {
                    if let Expression::Variable(id) = &**member_expr {
                        if id.name == "address"
                            && (member.name == "call" || member.name == "delegatecall")
                        {
                            *has_external_call = true;
                        }
                    }
                }
            }
            Expression::Assign(_, _, _) => {
                if *has_external_call {
                    *has_state_change_after_call = true;
                }
            }
            // Add other expression types as needed
            _ => {}
        }
    }

    fn check_unchecked_calls(&self, pt: &SourceUnit, result: &mut AnalysisResult) {
        for part in &pt.0 {
            if let SourceUnitPart::ContractDefinition(contract) = part {
                for part in &contract.parts {
                    if let ContractPart::FunctionDefinition(func) = part {
                        for stmt in &func.body {
                            self.check_unchecked_calls_in_statement(stmt, result);
                        }
                    }
                }
            }
        }
    }

    fn check_unchecked_calls_in_statement(&self, stmt: &Statement, result: &mut AnalysisResult) {
        match stmt {
            Statement::Expression(_, expr) => {
                self.check_unchecked_calls_in_expression(expr, result);
            }
            Statement::Block { statements, .. } => {
                for stmt in statements {
                    self.check_unchecked_calls_in_statement(stmt, result);
                }
            }
            _ => {}
        }
    }

    fn check_unchecked_calls_in_expression(&self, expr: &Expression, result: &mut AnalysisResult) {
        if let Expression::FunctionCall(loc, func_expr, args) = expr {
            if let Expression::MemberAccess(_, _, member) = &**func_expr {
                if member.name == "call" || member.name == "delegatecall" || member.name == "send" {
                    result.vulnerabilities.push(Vulnerability {
                        severity: Severity::Medium.to_string(),
                        description: format!(
                            "Unchecked return value from external call using '{}'. This could lead to silent failures and potential loss of funds.",
                            member.name
                        ),
                        location: Location::from_loc(loc),
                        code_snippet: Some(format!("// Original code:\n{:?}", expr)),
                        recommendation: Some(format!(
                            "Add a return value check:\nrequire({}.{}(...), 'External call failed');",
                            member.name, member.name
                        )),
                        category: "Unchecked External Calls".to_string(),
                    });
                }
            }
        }
    }

    fn check_deprecated_functions(&self, pt: &SourceUnit, result: &mut AnalysisResult) {
        let deprecated_functions = vec!["suicide", "block.blockhash", "sha3"];

        for part in &pt.0 {
            if let SourceUnitPart::ContractDefinition(contract) = part {
                for part in &contract.parts {
                    if let ContractPart::FunctionDefinition(func) = part {
                        if let Some(body) = &func.body {
                            self.check_deprecated_functions_in_statement(
                                body,
                                &deprecated_functions,
                                result,
                            );
                        }
                    }
                }
            }
        }
    }

    fn check_deprecated_functions_in_statement(
        &self,
        stmt: &Statement,
        deprecated: &[&str],
        result: &mut AnalysisResult,
    ) {
        match stmt {
            Statement::Block { statements, .. } => {
                for stmt in statements {
                    self.check_deprecated_functions_in_statement(stmt, deprecated, result);
                }
            }
            Statement::Expression(_, expr) => {
                self.check_deprecated_functions_in_expression(expr, deprecated, result);
            }
            // Add other statement types as needed
            _ => {}
        }
    }

    fn check_deprecated_functions_in_expression(
        &self,
        expr: &Expression,
        deprecated: &[&str],
        result: &mut AnalysisResult,
    ) {
        match expr {
            Expression::FunctionCall(loc, func, _) => {
                if let Expression::Variable(id) = &**func {
                    if deprecated.contains(&id.name.as_str()) {
                        result.warnings.push(FormattedWarning {
                            category: "Deprecated Function".to_string(),
                            message: format!("Use of deprecated function '{}' at {:?}", id.name, loc),
                            line_number: loc.start(),
                            code_snippet: format!("{}()", id.name),
                        });
                    }
                }
            }
            // Add other expression types as needed
            _ => {}
        }
    }

    fn check_assert_require_revert(&self, pt: &SourceUnit, result: &mut AnalysisResult) {
        for part in &pt.0 {
            if let SourceUnitPart::ContractDefinition(contract) = part {
                for part in &contract.parts {
                    if let ContractPart::FunctionDefinition(func) = part {
                        if let Some(body) = &func.body {
                            self.check_assert_require_revert_in_statement(body, result);
                        }
                    }
                }
            }
        }
    }

    fn check_assert_require_revert_in_statement(
        &self,
        stmt: &Statement,
        result: &mut AnalysisResult,
    ) {
        match stmt {
            Statement::Block { statements, .. } => {
                for stmt in statements {
                    self.check_assert_require_revert_in_statement(stmt, result);
                }
            }
            Statement::Expression(_, expr) => {
                self.check_assert_require_revert_in_expression(expr, result);
            }
            Statement::If(_, cond, then_stmt, else_stmt) => {
                self.check_assert_require_revert_in_expression(cond, result);
                self.check_assert_require_revert_in_statement(then_stmt, result);
                if let Some(else_stmt) = else_stmt {
                    self.check_assert_require_revert_in_statement(else_stmt, result);
                }
            }
            // Add other statement types as needed
            _ => {}
        }
    }

    fn check_assert_require_revert_in_expression(
        &self,
        expr: &Expression,
        result: &mut AnalysisResult,
    ) {
        match expr {
            Expression::FunctionCall(loc, func, _) => {
                if let Expression::Variable(id) = &**func {
                    if id.name == "assert" || id.name == "require" || id.name == "revert" {
                        result.warnings.push(FormattedWarning {
                            category: "Assert/Require/Revert".to_string(),
                            message: format!("Use of '{}' at {:?}", id.name, loc),
                            line_number: loc.start(),
                            code_snippet: format!("{}()", id.name),
                        });
                    }
                }
            }
            // Add other expression types as needed
            _ => {}
        }
    }

    fn check_integer_overflow(&self, pt: &SourceUnit, result: &mut AnalysisResult) {
        for part in &pt.0 {
            if let SourceUnitPart::ContractDefinition(contract) = part {
                for part in &contract.parts {
                    if let ContractPart::FunctionDefinition(func) = part {
                        if let Some(body) = &func.body {
                            self.check_integer_overflow_in_statement(body, result);
                        }
                    }
                }
            }
        }
    }

    fn check_integer_overflow_in_statement(&self, stmt: &Statement, result: &mut AnalysisResult) {
        match stmt {
            Statement::Block { statements, .. } => {
                for stmt in statements {
                    self.check_integer_overflow_in_statement(stmt, result);
                }
            }
            Statement::Expression(loc, expr) => {
                self.check_integer_overflow_in_expression(loc, expr, result);
            }
            // Add other statement types as needed
            _ => {}
        }
    }

    fn check_integer_overflow_in_expression(
        &self,
        loc: &Loc,
        expr: &Expression,
        result: &mut AnalysisResult,
    ) {
        match expr {
            Expression::Add(_, _, _)
            | Expression::Subtract(_, _, _)
            | Expression::Multiply(_, _, _)
            | Expression::Divide(_, _, _)
            | Expression::Modulo(_, _, _) => {
                result.vulnerabilities.push(Vulnerability {
                    severity: Severity::High.to_string(),
                    description: "Potential integer overflow. Consider using SafeMath.".to_string(),
                    location: Location::from_loc(loc),
                    code_snippet: None,
                    recommendation: None,
                    category: "Integer Overflow".to_string(),
                });
            }
            // Add other expression types as needed
            _ => {}
        }
    }

    fn check_tx_origin(&self, pt: &SourceUnit, result: &mut AnalysisResult) {
        for part in &pt.0 {
            if let SourceUnitPart::ContractDefinition(contract) = part {
                for part in &contract.parts {
                    if let ContractPart::FunctionDefinition(func) = part {
                        if let Some(body) = &func.body {
                            self.check_tx_origin_in_statement(body, result);
                        }
                    }
                }
            }
        }
    }

    fn check_tx_origin_in_statement(&self, stmt: &Statement, result: &mut AnalysisResult) {
        match stmt {
            Statement::Block { statements, .. } => {
                for stmt in statements {
                    self.check_tx_origin_in_statement(stmt, result);
                }
            }
            Statement::Expression(loc, expr) => {
                self.check_tx_origin_in_expression(loc, expr, result);
            }
            // Add other statement types as needed
            _ => {}
        }
    }

    fn check_tx_origin_in_expression(
        &self,
        loc: &Loc,
        expr: &Expression,
        result: &mut AnalysisResult,
    ) {
        match expr {
            Expression::MemberAccess(_, _, member) if member.name == "origin" => {
                result.vulnerabilities.push(Vulnerability {
                    severity: Severity::Medium.to_string(),
                    description: "Use of tx.origin. Consider using msg.sender instead.".to_string(),
                    location: Location::from_loc(loc),
                    code_snippet: None,
                    recommendation: None,
                    category: "Tx.origin".to_string(),
                });
            }
            // Add other expression types as needed
            _ => {}
        }
    }

    fn check_events(&self, pt: &SourceUnit, result: &mut AnalysisResult) {
        for part in &pt.0 {
            if let SourceUnitPart::ContractDefinition(contract) = part {
                let mut has_events = false;
                for part in &contract.parts {
                    if let ContractPart::EventDefinition(_) = part {
                        has_events = true;
                        break;
                    }
                }
                if !has_events {
                    result.warnings.push(FormattedWarning {
                        category: "Events".to_string(),
                        message: format!("Contract '{:?}' does not define any events. Consider adding events for important state changes.", contract.name),
                        line_number: 0,
                        code_snippet: "".to_string(),
                    });
                }
            }
        }
    }

    fn check_access_control(&self, pt: &SourceUnit, result: &mut AnalysisResult) {
        for part in &pt.0 {
            if let SourceUnitPart::ContractDefinition(contract) = part {
                let mut has_owner = false;
                let mut has_access_control = false;
                
                // Check for common access control patterns
                for part in &contract.parts {
                    match part {
                        ContractPart::VariableDefinition(var) => {
                            if let Some(name) = &var.name {
                                if name.name == "owner" || name.name.contains("admin") {
                                    has_owner = true;
                                }
                            }
                        }
                        ContractPart::FunctionDefinition(func) => {
                            // Check for onlyOwner-like modifiers
                            if let Some(attributes) = &func.attributes {
                                for attr in attributes {
                                    if let Expression::FunctionCall(_, name, _) = &attr {
                                        if let Expression::Variable(id) = &**name {
                                            if id.name.contains("only") {
                                                has_access_control = true;
                                            }
                                        }
                                    }
                                }
                            }
                            
                            // Check for privileged operations without access control
                            if !has_access_control {
                                self.check_privileged_operations(func, result);
                            }
                        }
                        _ => {}
                    }
                }
                
                // Warn if contract has privileged operations but no clear access control
                if !has_owner && !has_access_control {
                    result.warnings.push(FormattedWarning {
                        category: "Access Control".to_string(),
                        message: "Contract lacks explicit access control mechanisms.".to_string(),
                        line_number: contract.loc.start(),
                        code_snippet: "".to_string(),
                    });
                }
            }
        }
    }

    fn check_privileged_operations(&self, func: &FunctionDefinition, result: &mut AnalysisResult) {
        let mut has_privileged_ops = false;
        
        if let Some(body) = &func.body {
            // Check for sensitive operations
            has_privileged_ops = self.statement_has_privileged_ops(body);
        }
        
        if has_privileged_ops {
            result.vulnerabilities.push(Vulnerability {
                severity: Severity::High.to_string(),
                description: format!(
                    "Function '{}' contains privileged operations without proper access control",
                    func.name.as_ref().map_or("unnamed", |n| &n.name)
                ),
                location: Location::from_loc(&func.loc),
                code_snippet: None,
                recommendation: Some("Consider adding access control modifiers like 'onlyOwner' or implementing role-based access control.".to_string()),
                category: "Access Control".to_string(),
            });
        }
    }

    fn statement_has_privileged_ops(&self, stmt: &Statement) -> bool {
        match stmt {
            Statement::Expression(_, expr) => self.expression_has_privileged_ops(expr),
            Statement::Block { statements, .. } => {
                statements.iter().any(|s| self.statement_has_privileged_ops(s))
            }
            _ => false,
        }
    }

    fn expression_has_privileged_ops(&self, expr: &Expression) -> bool {
        match expr {
            Expression::FunctionCall(_, name, _) => {
                if let Expression::Variable(id) = &**name {
                    // List of sensitive function names
                    let sensitive = [
                        "selfdestruct", "delegatecall", "call", "transfer",
                        "transferFrom", "mint", "burn", "upgrade",
                    ];
                    sensitive.iter().any(|&op| id.name.contains(op))
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    fn check_front_running(&self, pt: &SourceUnit, result: &mut AnalysisResult) {
        for part in &pt.0 {
            if let SourceUnitPart::ContractDefinition(contract) = part {
                for part in &contract.parts {
                    if let ContractPart::FunctionDefinition(func) = part {
                        let mut has_price_dependency = false;
                        let mut has_state_change = false;
                        
                        if let Some(body) = &func.body {
                            self.analyze_front_running_vulnerability(
                                body,
                                &mut has_price_dependency,
                                &mut has_state_change,
                            );
                        }
                        
                        if has_price_dependency && has_state_change {
                            result.vulnerabilities.push(Vulnerability {
                                severity: Severity::High.to_string(),
                                description: format!(
                                    "Potential front-running vulnerability in function '{}'. The function depends on prices or balances and modifies state.",
                                    func.name.as_ref().map_or("unnamed", |n| &n.name)
                                ),
                                location: Location::from_loc(&func.loc),
                                code_snippet: None,
                                recommendation: Some("Consider implementing commit-reveal schemes or other front-running mitigation patterns.".to_string()),
                                category: "Front Running".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    fn analyze_front_running_vulnerability(
        &self,
        stmt: &Statement,
        has_price_dependency: &mut bool,
        has_state_change: &mut bool,
    ) {
        match stmt {
            Statement::Expression(_, expr) => {
                self.analyze_front_running_expression(expr, has_price_dependency, has_state_change);
            }
            Statement::Block { statements, .. } => {
                for stmt in statements {
                    self.analyze_front_running_vulnerability(stmt, has_price_dependency, has_state_change);
                }
            }
            _ => {}
        }
    }

    fn analyze_front_running_expression(
        &self,
        expr: &Expression,
        has_price_dependency: &mut bool,
        has_state_change: &mut bool,
    ) {
        match expr {
            Expression::FunctionCall(_, name, _) => {
                if let Expression::Variable(id) = &**name {
                    // Check for price/balance related functions
                    if id.name.contains("price") || id.name.contains("balance") || 
                       id.name.contains("amount") || id.name.contains("value") {
                        *has_price_dependency = true;
                    }
                    
                    // Check for state changes
                    if id.name.contains("transfer") || id.name.contains("send") ||
                       id.name.contains("mint") || id.name.contains("burn") {
                        *has_state_change = true;
                    }
                }
            }
            _ => {}
        }
    }

    fn check_flash_loan_vulnerability(&self, pt: &SourceUnit, result: &mut AnalysisResult) {
        for part in &pt.0 {
            if let SourceUnitPart::ContractDefinition(contract) = part {
                let mut has_price_dependency = false;
                let mut has_external_call = false;
                let mut has_state_change = false;

                for part in &contract.parts {
                    if let ContractPart::FunctionDefinition(func) = part {
                        if let Some(body) = &func.body {
                            self.analyze_flash_loan_vulnerability(
                                body,
                                &mut has_price_dependency,
                                &mut has_external_call,
                                &mut has_state_change,
                            );

                            if has_price_dependency && has_external_call && has_state_change {
                                result.vulnerabilities.push(Vulnerability {
                                    severity: Severity::Critical.to_string(),
                                    description: format!(
                                        "Potential flash loan vulnerability in function '{}'. The function depends on prices/balances, makes external calls, and modifies state.",
                                        func.name.as_ref().map_or("unnamed", |n| &n.name)
                                    ),
                                    location: Location::from_loc(&func.loc),
                                    code_snippet: None,
                                    recommendation: Some("Consider implementing checks against flash loan attacks, such as requiring minimum time locks or using cumulative price oracles.".to_string()),
                                    category: "Flash Loan".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    fn analyze_flash_loan_vulnerability(
        &self,
        stmt: &Statement,
        has_price_dependency: &mut bool,
        has_external_call: &mut bool,
        has_state_change: &mut bool,
    ) {
        match stmt {
            Statement::Expression(_, expr) => {
                self.analyze_flash_loan_expression(
                    expr,
                    has_price_dependency,
                    has_external_call,
                    has_state_change,
                );
            }
            Statement::Block { statements, .. } => {
                for stmt in statements {
                    self.analyze_flash_loan_vulnerability(
                        stmt,
                        has_price_dependency,
                        has_external_call,
                        has_state_change,
                    );
                }
            }
            _ => {}
        }
    }

    fn analyze_flash_loan_expression(
        &self,
        expr: &Expression,
        has_price_dependency: &mut bool,
        has_external_call: &mut bool,
        has_state_change: &mut bool,
    ) {
        match expr {
            Expression::FunctionCall(_, name, _) => {
                if let Expression::Variable(id) = &**name {
                    // Check for price/balance related functions
                    if id.name.contains("price") || id.name.contains("balance") || 
                       id.name.contains("amount") || id.name.contains("supply") {
                        *has_price_dependency = true;
                    }
                    
                    // Check for external calls
                    if id.name.contains("call") || id.name.contains("transfer") ||
                       id.name.contains("send") || id.name.contains("delegatecall") {
                        *has_external_call = true;
                    }
                    
                    // Check for state changes
                    if id.name.contains("mint") || id.name.contains("burn") ||
                       id.name.contains("swap") || id.name.contains("update") {
                        *has_state_change = true;
                    }
                }
            }
            _ => {}
        }
    }

    fn check_signature_replay(&self, pt: &SourceUnit, result: &mut AnalysisResult) {
        for part in &pt.0 {
            if let SourceUnitPart::ContractDefinition(contract) = part {
                let mut has_signature_validation = false;
                let mut has_nonce_check = false;

                for part in &contract.parts {
                    if let ContractPart::FunctionDefinition(func) = part {
                        if let Some(body) = &func.body {
                            self.analyze_signature_validation(
                                body,
                                &mut has_signature_validation,
                                &mut has_nonce_check,
                            );

                            if has_signature_validation && !has_nonce_check {
                                result.vulnerabilities.push(Vulnerability {
                                    severity: Severity::High.to_string(),
                                    description: format!(
                                        "Potential signature replay vulnerability in function '{}'. Signatures are validated but nonces are not checked.",
                                        func.name.as_ref().map_or("unnamed", |n| &n.name)
                                    ),
                                    location: Location::from_loc(&func.loc),
                                    code_snippet: None,
                                    recommendation: Some("Implement nonce checking for signatures to prevent replay attacks.".to_string()),
                                    category: "Signature Replay".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    fn analyze_signature_validation(
        &self,
        stmt: &Statement,
        has_signature_validation: &mut bool,
        has_nonce_check: &mut bool,
    ) {
        match stmt {
            Statement::Expression(_, expr) => {
                if let Expression::FunctionCall(_, name, _) = expr {
                    if let Expression::Variable(id) = &**name {
                        // Check for signature validation
                        if id.name.contains("ecrecover") || id.name.contains("recover") ||
                           id.name.contains("signature") || id.name.contains("verify") {
                            *has_signature_validation = true;
                        }
                        
                        // Check for nonce usage
                        if id.name.contains("nonce") {
                            *has_nonce_check = true;
                        }
                    }
                }
            }
            Statement::Block { statements, .. } => {
                for stmt in statements {
                    self.analyze_signature_validation(stmt, has_signature_validation, has_nonce_check);
                }
            }
            _ => {}
        }
    }

    fn check_uninitialized_storage(&self, pt: &SourceUnit, result: &mut AnalysisResult) {
        for part in &pt.0 {
            if let SourceUnitPart::ContractDefinition(contract) = part {
                let mut storage_vars = std::collections::HashMap::new();
                
                // Collect storage variables
                for part in &contract.parts {
                    if let ContractPart::VariableDefinition(var) = part {
                        if let Some(name) = &var.name {
                            storage_vars.insert(name.name.clone(), false);
                        }
                    }
                }
                
                // Check initialization in constructor
                for part in &contract.parts {
                    if let ContractPart::FunctionDefinition(func) = part {
                        if func.is_constructor() {
                            if let Some(body) = &func.body {
                                self.check_storage_initialization(body, &mut storage_vars);
                            }
                        }
                    }
                }
                
                // Report uninitialized storage variables
                for (var_name, initialized) in storage_vars {
                    if !initialized {
                        result.warnings.push(FormattedWarning {
                            category: "Uninitialized Storage".to_string(),
                            message: format!("Storage variable '{}' is not initialized in the constructor", var_name),
                            line_number: 0, // We would need to store the line number when collecting vars
                            code_snippet: "".to_string(),
                        });
                    }
                }
            }
        }
    }

    fn check_storage_initialization(
        &self,
        stmt: &Statement,
        storage_vars: &mut std::collections::HashMap<String, bool>,
    ) {
        match stmt {
            Statement::Expression(_, Expression::Assign(_, left, _)) => {
                if let Expression::Variable(id) = &**left {
                    storage_vars.insert(id.name.clone(), true);
                }
            }
            Statement::Block { statements, .. } => {
                for stmt in statements {
                    self.check_storage_initialization(stmt, storage_vars);
                }
            }
            _ => {}
        }
    }

    fn check_delegate_call(&self, pt: &SourceUnit, result: &mut AnalysisResult) {
        for part in &pt.0 {
            if let SourceUnitPart::ContractDefinition(contract) = part {
                for part in &contract.parts {
                    if let ContractPart::FunctionDefinition(func) = part {
                        if let Some(body) = &func.body {
                            let mut has_delegate_call = false;
                            let mut has_input_validation = false;
                            
                            self.analyze_delegate_call(body, &mut has_delegate_call, &mut has_input_validation);
                            
                            if has_delegate_call && !has_input_validation {
                                result.vulnerabilities.push(Vulnerability {
                                    severity: Severity::Critical.to_string(),
                                    description: "Unsafe delegatecall usage detected in function '{}'. No input validation found.".to_string(),
                                    location: Location::from_loc(&func.loc),
                                    code_snippet: None,
                                    recommendation: Some("Implement strict input validation for delegatecall parameters and consider using a proxy pattern.".to_string()),
                                    category: "Delegate Call".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    fn analyze_delegate_call(&self, stmt: &Statement, has_delegate_call: &mut bool, has_input_validation: &mut bool) {
        match stmt {
            Statement::Block { statements, loc: _, unchecked: _ } => {
                for stmt in statements {
                    self.analyze_delegate_call(stmt, has_delegate_call, has_input_validation);
                }
            }
            Statement::If { condition, .. } => {
                if let Expression::FunctionCall(_, func, _) = condition {
                    if let Expression::MemberAccess(_, _, member) = &**func {
                        if member.name == "delegatecall" {
                            *has_input_validation = true;
                        }
                    }
                }
            }
            Statement::Expression(_, expr) => {
                if let Expression::FunctionCall(_, func, _) = expr {
                    if let Expression::MemberAccess(_, _, member) = &**func {
                        if member.name == "delegatecall" {
                            *has_delegate_call = true;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn check_block_gas_limit(&self, pt: &SourceUnit, result: &mut AnalysisResult) {
        for part in &pt.0 {
            if let SourceUnitPart::ContractDefinition(contract) = part {
                for part in &contract.parts {
                    if let ContractPart::FunctionDefinition(func) = part {
                        if let Some(body) = &func.body {
                            let mut has_loop = false;
                            let mut has_array_operation = false;
                            let mut has_gas_check = false;
                            
                            self.analyze_gas_usage(body, &mut has_loop, &mut has_array_operation, &mut has_gas_check);
                            
                            if (has_loop || has_array_operation) && !has_gas_check {
                                result.warnings.push(FormattedWarning {
                                    category: "Block Gas Limit".to_string(),
                                    message: format!("Function '{}' contains operations that might exceed block gas limit", func.name.as_ref().map_or("unnamed", |n| &n.name)),
                                    line_number: func.loc.start(),
                                    code_snippet: "".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    fn analyze_gas_usage(&self, stmt: &Statement, has_loop: &mut bool, has_array_operation: &mut bool, has_gas_check: &mut bool) {
        match stmt {
            Statement::Block { statements, loc: _, unchecked: _ } => {
                for stmt in statements {
                    self.analyze_gas_usage(stmt, has_loop, has_array_operation, has_gas_check);
                }
            }
            Statement::For { .. } | Statement::While { .. } => {
                *has_loop = true;
            }
            Statement::If { condition, .. } => {
                if let Expression::MemberAccess(_, obj, member) = condition {
                    if let Expression::Variable(id) = &**obj {
                        if id.name == "gasleft" || member.name == "gas" {
                            *has_gas_check = true;
                        }
                    }
                }
            }
            Statement::Expression(_, expr) => {
                self.analyze_gas_usage_expr(expr, has_array_operation);
            }
            _ => {}
        }
    }

    fn analyze_gas_usage_expr(&self, expr: &Expression, has_array_operation: &mut bool) {
        match expr {
            Expression::ArraySubscript(..) => {
                *has_array_operation = true;
            }
            Expression::FunctionCall(_, func, _) => {
                if let Expression::MemberAccess(_, _, member) = &**func {
                    if ["push", "pop", "length"].contains(&member.name.as_str()) {
                        *has_array_operation = true;
                    }
                }
            }
            _ => {}
        }
    }

    fn check_function_visibility(&self, pt: &SourceUnit, result: &mut AnalysisResult) {
        for part in &pt.0 {
            if let SourceUnitPart::ContractDefinition(contract) = part {
                for part in &contract.parts {
                    if let ContractPart::FunctionDefinition(func) = part {
                        // Check if function has any visibility attributes
                        let has_visibility = func.attributes.iter().any(|attr| {
                            matches!(
                                attr,
                                FunctionAttribute::Visibility(_)
                            )
                        });
                        
                        if !has_visibility {
                            result.warnings.push(FormattedWarning {
                                category: "Function Visibility".to_string(),
                                message: format!(
                                    "Function '{}' has no explicit visibility specifier",
                                    func.name.as_ref().map_or("unnamed", |n| &n.name)
                                ),
                                line_number: func.loc.start(),
                                code_snippet: "".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    fn check_unchecked_return_values(&self, pt: &SourceUnit, result: &mut AnalysisResult) {
        for part in &pt.0 {
            if let SourceUnitPart::ContractDefinition(contract) = part {
                for part in &contract.parts {
                    if let ContractPart::FunctionDefinition(func) = part {
                        if let Some(body) = &func.body {
                            let mut has_external_call = false;
                            let mut has_return_check = false;
                            
                            self.analyze_return_checks(body, &mut has_external_call, &mut has_return_check);
                            
                            if has_external_call && !has_return_check {
                                result.vulnerabilities.push(Vulnerability {
                                    severity: Severity::Medium.to_string(),
                                    description: format!("Unchecked return value in function '{}'", func.name.as_ref().map_or("unnamed", |n| &n.name)),
                                    location: Location::from_loc(&func.loc),
                                    code_snippet: None,
                                    recommendation: Some("Always check return values of external calls.".to_string()),
                                    category: "Unchecked Return Values".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    fn analyze_return_checks(&self, stmt: &Statement, has_external_call: &mut bool, has_return_check: &mut bool) {
        match stmt {
            Statement::Block { statements, loc: _, unchecked: _ } => {
                for stmt in statements {
                    self.analyze_return_checks(stmt, has_external_call, has_return_check);
                }
            }
            Statement::If { condition, .. } => {
                if let Expression::FunctionCall(_, func, _) = condition {
                    if let Expression::MemberAccess(_, _, member) = &**func {
                        if ["call", "send", "transfer"].contains(&member.name.as_str()) {
                            *has_return_check = true;
                        }
                    }
                }
            }
            Statement::Expression(_, expr) => {
                if let Expression::FunctionCall(_, func, _) = expr {
                    if let Expression::MemberAccess(_, _, member) = &**func {
                        if ["call", "send", "transfer"].contains(&member.name.as_str()) {
                            *has_external_call = true;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn check_short_address(&self, pt: &SourceUnit, result: &mut AnalysisResult) {
        for part in &pt.0 {
            if let SourceUnitPart::ContractDefinition(contract) = part {
                for part in &contract.parts {
                    if let ContractPart::FunctionDefinition(func) = part {
                        if let Some(params) = &func.params {
                            for param in params {
                                if let Some(typ) = &param.typ {
                                    if typ.to_string().contains("address") {
                                        result.warnings.push(FormattedWarning {
                                            category: "Short Address".to_string(),
                                            message: format!("Function '{}' accepts address parameter. Verify input length to prevent short address attacks.", func.name.as_ref().map_or("unnamed", |n| &n.name)),
                                            line_number: func.loc.start(),
                                            code_snippet: "".to_string(),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn check_race_condition(&self, pt: &SourceUnit, result: &mut AnalysisResult) {
        for part in &pt.0 {
            if let SourceUnitPart::ContractDefinition(contract) = part {
                for part in &contract.parts {
                    if let ContractPart::FunctionDefinition(func) = part {
                        if let Some(body) = &func.body {
                            let mut has_state_change = false;
                            let mut has_external_dependency = false;
                            
                            self.analyze_race_conditions(body, &mut has_state_change, &mut has_external_dependency);
                            
                            if has_state_change && has_external_dependency {
                                result.vulnerabilities.push(Vulnerability {
                                    severity: Severity::High.to_string(),
                                    description: format!("Potential race condition in function '{}'. State changes depend on external calls.", func.name.as_ref().map_or("unnamed", |n| &n.name)),
                                    location: Location::from_loc(&func.loc),
                                    code_snippet: None,
                                    recommendation: Some("Implement checks-effects-interactions pattern or use mutex locks.".to_string()),
                                    category: "Race Condition".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    fn analyze_race_conditions(&self, stmt: &Statement, has_state_change: &mut bool, has_external_dependency: &mut bool) {
        match stmt {
            Statement::Block { statements, loc: _, unchecked: _ } => {
                for stmt in statements {
                    self.analyze_race_conditions(stmt, has_state_change, has_external_dependency);
                }
            }
            Statement::Expression(_, expr) => {
                self.analyze_race_condition_expr(expr, has_state_change, has_external_dependency);
            }
            _ => {}
        }
    }

    fn analyze_race_condition_expr(&self, expr: &Expression, has_state_change: &mut bool, has_external_dependency: &mut bool) {
        match expr {
            Expression::Assignment(..) => {
                *has_state_change = true;
            }
            Expression::FunctionCall(_, func, _) => {
                if let Expression::MemberAccess(_, _, member) = &**func {
                    if ["call", "send", "transfer"].contains(&member.name.as_str()) {
                        *has_external_dependency = true;
                    }
                }
            }
            _ => {}
        }
    }

    fn check_weak_prng(&self, pt: &SourceUnit, result: &mut AnalysisResult) {
        for part in &pt.0 {
            if let SourceUnitPart::ContractDefinition(contract) = part {
                for part in &contract.parts {
                    if let ContractPart::FunctionDefinition(func) = part {
                        if let Some(body) = &func.body {
                            let mut uses_block_hash = false;
                            let mut uses_timestamp = false;
                            let mut uses_block_number = false;
                            
                            self.analyze_random_source(
                                body,
                                &mut uses_block_hash,
                                &mut uses_timestamp,
                                &mut uses_block_number
                            );
                            
                            if uses_block_hash || uses_timestamp || uses_block_number {
                                result.vulnerabilities.push(Vulnerability {
                                    severity: Severity::High.to_string(),
                                    description: "Weak random number generation in function '{}'", func.name.as_ref().map_or("unnamed", |n| &n.name),
                                    location: Location::from_loc(&func.loc),
                                    code_snippet: None,
                                    recommendation: Some("Use a secure source of randomness such as Chainlink VRF.".to_string()),
                                    category: "Weak PRNG".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    fn analyze_random_source(&self, stmt: &Statement, uses_weak_source: &mut bool, has_entropy_source: &mut bool, has_seed_protection: &mut bool) {
        match stmt {
            Statement::Block { statements, loc: _, unchecked: _ } => {
                for stmt in statements {
                    self.analyze_random_source(stmt, uses_weak_source, has_entropy_source, has_seed_protection);
                }
            }
            Statement::Expression(_, expr) => {
                self.analyze_random_source_expr(expr, uses_weak_source, has_entropy_source, has_seed_protection);
            }
            _ => {}
        }
    }

    fn analyze_random_source_expr(&self, expr: &Expression, uses_weak_source: &mut bool, has_entropy_source: &mut bool, has_seed_protection: &mut bool) {
        match expr {
            Expression::MemberAccess(_, obj, member) => {
                if let Expression::Variable(id) = &**obj {
                    if (id.name == "block" && (member.name == "timestamp" || member.name == "number" || member.name == "difficulty")) ||
                       (id.name == "msg" && member.name == "sender") {
                        *uses_weak_source = true;
                    }
                }
            }
            Expression::FunctionCall(_, func, _) => {
                if let Expression::MemberAccess(_, _, member) = &**func {
                    if member.name == "random" {
                        *has_entropy_source = true;
                    }
                    if member.name == "seed" {
                        *has_seed_protection = true;
                    }
                }
            }
            _ => {}
        }
    }

    fn check_unchecked_constructor(&self, pt: &SourceUnit, result: &mut AnalysisResult) {
        for part in &pt.0 {
            if let SourceUnitPart::ContractDefinition(contract) = part {
                let mut has_constructor = false;
                let mut has_input_validation = false;
                
                for part in &contract.parts {
                    if let ContractPart::FunctionDefinition(func) = part {
                        if func.is_constructor() {
                            has_constructor = true;
                            if let Some(body) = &func.body {
                                self.analyze_constructor_validation(body, &mut has_input_validation);
                            }
                        }
                    }
                }
                
                if has_constructor && !has_input_validation {
                    result.warnings.push(FormattedWarning {
                        category: "Unchecked Constructor".to_string(),
                        message: format!("Constructor in contract '{:?}' lacks input validation", contract.name),
                        line_number: contract.loc.start(),
                        code_snippet: "".to_string(),
                    });
                }
            }
        }
    }

    fn analyze_constructor_validation(&self, stmt: &Statement, has_validation: &mut bool) {
        match stmt {
            Statement::Expression(_, expr) => {
                if let Expression::FunctionCall(_, name, _) = expr {
                    if let Expression::Variable(id) = &**name {
                        if id.name.contains("require") || id.name.contains("assert") {
                            *has_validation = true;
                        }
                    }
                }
            }
            Statement::Block { statements, .. } => {
                for stmt in statements {
                    self.analyze_constructor_validation(stmt, has_validation);
                }
            }
            _ => {}
        }
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
            Statement::Block { statements, .. } => statements
                .iter()
                .map(|s| self.calculate_statement_complexity(s))
                .sum(),
            Statement::If(_, cond, then_stmt, else_stmt) => {
                1 + self.calculate_expression_complexity(cond)
                    + self.calculate_statement_complexity(then_stmt)
                    + else_stmt
                        .as_ref()
                        .map_or(0, |s| self.calculate_statement_complexity(s))
            }
            Statement::While(_, cond, body) => {
                1 + self.calculate_expression_complexity(cond)
                    + self.calculate_statement_complexity(body)
            }
            Statement::For(_, init, cond, update, body) => {
                1 + init
                    .as_ref()
                    .map_or(0, |s| self.calculate_statement_complexity(s))
                    + cond
                        .as_ref()
                        .map_or(0, |e| self.calculate_expression_complexity(e))
                    + update
                        .as_ref()
                        .map_or(0, |e| self.calculate_expression_complexity(e))
                    + self.calculate_statement_complexity(body.as_ref().unwrap())
            }
            Statement::Expression(_, expr) => self.calculate_expression_complexity(expr),
            // Add other statement types as needed
            _ => 0,
        }
    }

    fn calculate_expression_complexity(&self, expr: &Expression) -> u32 {
        match expr {
            Expression::FunctionCall(_, _, _) => 2, // Function calls are typically more complex
            Expression::Add(_, _, _)
            | Expression::Subtract(_, _, _)
            | Expression::Multiply(_, _, _)
            | Expression::Divide(_, _, _)
            | Expression::Modulo(_, _, _) => 1,
            Expression::Power(_, _, _) => 2, // Exponentiation is typically more complex
            Expression::BitwiseOr(_, _, _)
            | Expression::BitwiseAnd(_, _, _)
            | Expression::BitwiseXor(_, _, _) => 1,
            Expression::ShiftLeft(_, _, _) | Expression::ShiftRight(_, _, _) => 1,
            Expression::Less(_, _, _)
            | Expression::More(_, _, _)
            | Expression::LessEqual(_, _, _)
            | Expression::MoreEqual(_, _, _)
            | Expression::Equal(_, _, _)
            | Expression::NotEqual(_, _, _) => 1,
            Expression::And(_, _, _) | Expression::Or(_, _, _) => 1,
            // Add other expression types as needed
            _ => 0,
        }
    }

    fn estimate_contract_deployment_cost(&self, contract: &ContractDefinition) -> u64 {
        // This is a simplified estimation and should be replaced with a more accurate method
        let base_cost = 100000; // Base deployment cost
        let state_variable_cost = contract
            .parts
            .iter()
            .filter(|part| matches!(part, ContractPart::VariableDefinition(_)))
            .count() as u64
            * 20000;
        let function_cost = contract
            .parts
            .iter()
            .filter(|part| matches!(part, ContractPart::FunctionDefinition(_)))
            .count() as u64
            * 50000;

        base_cost + state_variable_cost + function_cost
    }

    fn estimate_function_cost(&self, func: &FunctionDefinition) -> u64 {
        let base_cost = 21000; // Base transaction cost
        let complexity_cost = self.calculate_function_complexity(func) as u64 * 200;

        base_cost + complexity_cost
    }

    fn count_nodes(&self, pt: &SourceUnit) -> usize {
        pt.0.len()
            + pt.0
                .iter()
                .map(|part| self.count_source_unit_part(part))
                .sum::<usize>()
    }

    fn count_source_unit_part(&self, part: &SourceUnitPart) -> usize {
        match part {
            SourceUnitPart::ContractDefinition(contract) => {
                1 + contract
                    .parts
                    .iter()
                    .map(|part| self.count_contract_part(part))
                    .sum::<usize>()
            }
            _ => 1,
        }
    }

    fn count_contract_part(&self, part: &ContractPart) -> usize {
        match part {
            ContractPart::FunctionDefinition(func) => {
                1 + func
                    .body
                    .as_ref()
                    .map_or(0, |body| self.count_statement(body))
            }
            _ => 1,
        }
    }

    fn count_statement(&self, statement: &Statement) -> usize {
        match statement {
            Statement::Block { statements, .. } => {
                1 + statements
                    .iter()
                    .map(|s| self.count_statement(s))
                    .sum::<usize>()
            }
            Statement::If(_, cond, then_stmt, else_stmt) => {
                1 + self.count_expression(cond)
                    + self.count_statement(then_stmt)
                    + else_stmt.as_ref().map_or(0, |s| self.count_statement(s))
            }
            Statement::While(_, cond, body) => {
                1 + self.count_expression(cond) + self.count_statement(body)
            }
            Statement::For(_, init, cond, update, body) => {
                1 + init.as_ref().map_or(0, |s| self.count_statement(s))
                    + cond.as_ref().map_or(0, |e| self.count_expression(e))
                    + update.as_ref().map_or(0, |e| self.count_expression(e))
                    + self.count_statement(body.as_ref().unwrap())
            }
            Statement::Expression(_, expr) => 1 + self.count_expression(expr),
            // Add other statement types as needed
            _ => 1,
        }
    }

    fn count_expression(&self, expr: &Expression) -> usize {
        match expr {
            Expression::Add(_, left, right)
            | Expression::Subtract(_, left, right)
            | Expression::Multiply(_, left, right)
            | Expression::Divide(_, left, right)
            | Expression::Modulo(_, left, right)
            | Expression::Power(_, left, right)
            | Expression::BitwiseOr(_, left, right)
            | Expression::BitwiseAnd(_, left, right)
            | Expression::BitwiseXor(_, left, right)
            | Expression::ShiftLeft(_, left, right)
            | Expression::ShiftRight(_, left, right)
            | Expression::And(_, left, right)
            | Expression::Or(_, left, right)
            | Expression::Less(_, left, right)
            | Expression::More(_, left, right)
            | Expression::LessEqual(_, left, right)
            | Expression::MoreEqual(_, left, right)
            | Expression::Equal(_, left, right)
            | Expression::NotEqual(_, left, right) => {
                1 + self.count_expression(left) + self.count_expression(right)
            }
            Expression::FunctionCall(_, func, args) => {
                1 + self.count_expression(func)
                    + args
                        .iter()
                        .map(|arg| self.count_expression(arg))
                        .sum::<usize>()
            }
            Expression::MemberAccess(_, _, _) => 1,
            // Add other expression types as needed
            _ => 1,
        }
    }

    fn check_storage_layout(&self, pt: &SourceUnit, result: &mut AnalysisResult) {
        for part in &pt.0 {
            if let SourceUnitPart::ContractDefinition(contract) = part {
                let mut slot_count = 0;
                let mut slot_types = Vec::new();

                for part in &contract.parts {
                    if let ContractPart::VariableDefinition(var) = part {
                        if let Expression::Type(_, ty) = &var.ty {
                            let size = self.get_type_size(ty);
                            if let Some(name) = &var.name {
                                slot_types.push((name.name.clone(), size));
                                slot_count += (size + 31) / 32; // Round up to nearest slot
                            }
                        }
                    }
                }

                // Check for inefficient storage layout
                if !slot_types.is_empty() {
                    let mut sorted_slots = slot_types.clone();
                    sorted_slots.sort_by(|a, b| b.1.cmp(&a.1)); // Sort by size descending

                    let current_size: u32 = slot_types.iter().map(|(_, size)| (size + 31) / 32 * 32).sum();
                    let optimal_size: u32 = sorted_slots.iter().map(|(_, size)| (size + 31) / 32 * 32).sum();

                    if current_size > optimal_size {
                        result.warnings.push(FormattedWarning {
                            category: "Storage Layout".to_string(),
                            message: format!(
                                "Inefficient storage layout in contract '{}'. Current size: {} slots, Optimal size: {} slots",
                                contract.name.as_ref().map_or("Unknown", |n| &n.name),
                                current_size / 32,
                                optimal_size / 32
                            ),
                            line_number: contract.loc.start(),
                            code_snippet: "".to_string(),
                        });
                    }
                }
            }
        }
    }

    fn check_randomness(&self, pt: &SourceUnit, result: &mut AnalysisResult) {
        for part in &pt.0 {
            if let SourceUnitPart::ContractDefinition(contract) = part {
                for part in &contract.parts {
                    if let ContractPart::FunctionDefinition(func) = part {
                        if let Some(body) = &func.body {
                            let mut uses_weak_randomness = false;
                            let mut has_critical_operation = false;
                            
                            self.analyze_randomness(body, &mut uses_weak_randomness, &mut has_critical_operation);
                            
                            if uses_weak_randomness && has_critical_operation {
                                result.vulnerabilities.push(Vulnerability {
                                    severity: Severity::High.to_string(),
                                    description: "Use of weak randomness source in critical operation".to_string(),
                                    location: Location::from_loc(&func.loc),
                                    code_snippet: None,
                                    recommendation: Some("Use a secure source of randomness such as Chainlink VRF".to_string()),
                                    category: "Randomness".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    fn analyze_randomness(&self, stmt: &Statement, uses_weak_randomness: &mut bool, has_critical_operation: &mut bool) {
        match stmt {
            Statement::Block { statements, loc: _, unchecked: _ } => {
                for stmt in statements {
                    self.analyze_randomness(stmt, uses_weak_randomness, has_critical_operation);
                }
            }
            Statement::Expression(_, expr) => {
                self.analyze_randomness_expr(expr, uses_weak_randomness, has_critical_operation);
            }
            _ => {}
        }
    }

    fn analyze_randomness_expr(&self, expr: &Expression, uses_weak_randomness: &mut bool, has_critical_operation: &mut bool) {
        match expr {
            Expression::MemberAccess(_, obj, member) => {
                if let Expression::Variable(id) = &**obj {
                    if id.name == "block" && (member.name == "timestamp" || member.name == "number" || member.name == "difficulty") {
                        *uses_weak_randomness = true;
                    }
                }
            }
            Expression::FunctionCall(_, func, _) => {
                if let Expression::MemberAccess(_, _, member) = &**func {
                    if member.name == "random" {
                        *has_critical_operation = true;
                    }
                }
            }
            _ => {}
        }
    }

    fn check_upgrade_pattern(&self, pt: &SourceUnit, result: &mut AnalysisResult) {
        for part in &pt.0 {
            if let SourceUnitPart::ContractDefinition(contract) = part {
                let mut has_upgrade_capability = false;
                let mut has_proper_storage = false;
                let mut has_initialization = false;

                for part in &contract.parts {
                    match part {
                        ContractPart::FunctionDefinition(func) => {
                            if let Some(ref name) = func.name {
                                if name.name.contains("upgrade") {
                                    has_upgrade_capability = true;
                                    if let Some(body) = &func.body {
                                        self.analyze_upgrade_safety(body, &mut has_proper_storage, &mut has_initialization);
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }

                if has_upgrade_capability && (!has_proper_storage || !has_initialization) {
                    result.vulnerabilities.push(Vulnerability {
                        severity: Severity::High.to_string(),
                        description: "Unsafe upgrade pattern detected".to_string(),
                        location: Location::from_loc(&contract.loc),
                        code_snippet: None,
                        recommendation: Some("Implement proper storage layout and initialization checks in upgrade functions".to_string()),
                        category: "Upgrade Pattern".to_string(),
                    });
                }
            }
        }
    }

    fn analyze_upgrade_safety(&self, stmt: &Statement, has_proper_storage: &mut bool, has_initialization: &mut bool) {
        match stmt {
            Statement::Block { statements, loc: _, unchecked: _ } => {
                for stmt in statements {
                    self.analyze_upgrade_safety(stmt, has_proper_storage, has_initialization);
                }
            }
            Statement::Expression(_, expr) => {
                self.analyze_upgrade_expr(expr, has_proper_storage, has_initialization);
            }
            _ => {}
        }
    }

    fn analyze_upgrade_expr(&self, expr: &Expression, has_proper_storage: &mut bool, has_initialization: &mut bool) {
        match expr {
            Expression::FunctionCall(_, func, _) => {
                if let Expression::MemberAccess(_, _, member) = &**func {
                    if member.name.contains("storage") {
                        *has_proper_storage = true;
                    }
                    if member.name.contains("initialize") {
                        *has_initialization = true;
                    }
                }
            }
            _ => {}
        }
    }

    fn check_timestamp_dependency(&self, pt: &SourceUnit, result: &mut AnalysisResult) {
        for part in &pt.0 {
            if let SourceUnitPart::ContractDefinition(contract) = part {
                for part in &contract.parts {
                    if let ContractPart::FunctionDefinition(func) = part {
                        if let Some(body) = &func.body {
                            let mut has_timestamp = false;
                            let mut has_critical_operation = false;
                            
                            self.analyze_timestamp_dependency(body, &mut has_timestamp, &mut has_critical_operation);
                            
                            if has_timestamp && has_critical_operation {
                                result.vulnerabilities.push(Vulnerability {
                                    severity: Severity::Medium.to_string(),
                                    description: "Function uses block.timestamp for critical operations".to_string(),
                                    location: Location::from_loc(&func.loc),
                                    code_snippet: None,
                                    recommendation: Some("Consider using block.number instead of block.timestamp for time-dependent logic".to_string()),
                                    category: "Timestamp Dependency".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    fn analyze_timestamp_dependency(&self, stmt: &Statement, has_timestamp: &mut bool, has_critical_operation: &mut bool) {
        match stmt {
            Statement::Block { statements, loc: _, unchecked: _ } => {
                for stmt in statements {
                    self.analyze_timestamp_dependency(stmt, has_timestamp, has_critical_operation);
                }
            }
            Statement::Expression(_, expr) => {
                self.analyze_timestamp_expr(expr, has_timestamp, has_critical_operation);
            }
            _ => {}
        }
    }

    fn analyze_timestamp_expr(&self, expr: &Expression, has_timestamp: &mut bool, has_critical_operation: &mut bool) {
        match expr {
            Expression::MemberAccess(_, obj, member) => {
                if let Expression::Variable(id) = &**obj {
                    if id.name == "block" && member.name == "timestamp" {
                        *has_timestamp = true;
                    }
                }
            }
            Expression::FunctionCall(_, func, _) => {
                if let Expression::MemberAccess(_, _, member) = &**func {
                    if ["transfer", "send", "call", "delegatecall"].contains(&member.name.as_str()) {
                        *has_critical_operation = true;
                    }
                }
            }
            _ => {}
        }
    }

    fn check_dos_vectors(&self, pt: &SourceUnit, result: &mut AnalysisResult) {
        for part in &pt.0 {
            if let SourceUnitPart::ContractDefinition(contract) = part {
                for part in &contract.parts {
                    if let ContractPart::FunctionDefinition(func) = part {
                        if let Some(body) = &func.body {
                            let mut has_unbounded_operation = false;
                            let mut has_external_call = false;
                            
                            self.analyze_dos_vectors(body, &mut has_unbounded_operation, &mut has_external_call);
                            
                            if has_unbounded_operation && has_external_call {
                                result.vulnerabilities.push(Vulnerability {
                                    severity: Severity::High.to_string(),
                                    description: "Potential DoS vector found: unbounded operation with external calls".to_string(),
                                    location: Location::from_loc(&func.loc),
                                    code_snippet: None,
                                    recommendation: Some("Consider implementing a pull payment pattern or limiting the loop bounds".to_string()),
                                    category: "DoS".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    fn analyze_dos_vectors(&self, stmt: &Statement, has_unbounded_operation: &mut bool, has_external_call: &mut bool) {
        match stmt {
            Statement::Block { statements, loc: _, unchecked: _ } => {
                for stmt in statements {
                    self.analyze_dos_vectors(stmt, has_unbounded_operation, has_external_call);
                }
            }
            Statement::For { .. } | Statement::While { .. } => {
                *has_unbounded_operation = true;
            }
            Statement::Expression(_, expr) => {
                self.analyze_dos_expr(expr, has_external_call);
            }
            _ => {}
        }
    }

    fn analyze_dos_expr(&self, expr: &Expression, has_external_call: &mut bool) {
        match expr {
            Expression::FunctionCall(_, func, _) => {
                if let Expression::MemberAccess(_, _, member) = &**func {
                    if ["call", "send", "transfer"].contains(&member.name.as_str()) {
                        *has_external_call = true;
                    }
                }
            }
            _ => {}
        }
    }

    fn check_arithmetic_precision(&self, pt: &SourceUnit, result: &mut AnalysisResult) {
        for part in &pt.0 {
            if let SourceUnitPart::ContractDefinition(contract) = part {
                for part in &contract.parts {
                    if let ContractPart::FunctionDefinition(func) = part {
                        if let Some(body) = &func.body {
                            let mut has_division = false;
                            let mut has_precision_loss = false;
                            
                            self.analyze_arithmetic_precision(body, &mut has_division, &mut has_precision_loss);
                            
                            if has_division && has_precision_loss {
                                result.vulnerabilities.push(Vulnerability {
                                    severity: Severity::Medium.to_string(),
                                    description: "Potential precision loss in arithmetic operations".to_string(),
                                    location: Location::from_loc(&func.loc),
                                    code_snippet: None,
                                    recommendation: Some("Consider using a higher precision type or SafeMath library".to_string()),
                                    category: "Arithmetic Precision".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    fn analyze_arithmetic_precision(&self, stmt: &Statement, has_division: &mut bool, has_precision_loss: &mut bool) {
        match stmt {
            Statement::Block { statements, loc: _, unchecked: _ } => {
                for stmt in statements {
                    self.analyze_arithmetic_precision(stmt, has_division, has_precision_loss);
                }
            }
            Statement::Expression(_, expr) => {
                self.analyze_arithmetic_expr(expr, has_division, has_precision_loss);
            }
            _ => {}
        }
    }

    fn analyze_arithmetic_expr(&self, expr: &Expression, has_division: &mut bool, has_precision_loss: &mut bool) {
        match expr {
            Expression::BinaryOperation(_, op, _, _) => {
                if op == "/" {
                    *has_division = true;
                    *has_precision_loss = true;
                }
            }
            _ => {}
        }
    }

    fn check_tx_origin(&self, pt: &SourceUnit, result: &mut AnalysisResult) {
        for part in &pt.0 {
            if let SourceUnitPart::ContractDefinition(contract) = part {
                for part in &contract.parts {
                    if let ContractPart::FunctionDefinition(func) = part {
                        if let Some(body) = &func.body {
                            let mut uses_tx_origin = false;
                            let mut has_auth_check = false;
                            
                            self.analyze_tx_origin(body, &mut uses_tx_origin, &mut has_auth_check);
                            
                            if uses_tx_origin && !has_auth_check {
                                result.vulnerabilities.push(Vulnerability {
                                    severity: Severity::High.to_string(),
                                    description: "Function uses tx.origin for authorization".to_string(),
                                    location: Location::from_loc(&func.loc),
                                    code_snippet: None,
                                    recommendation: Some("Use msg.sender instead of tx.origin for authorization checks".to_string()),
                                    category: "Authorization".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    fn analyze_tx_origin(&self, stmt: &Statement, uses_tx_origin: &mut bool, has_auth_check: &mut bool) {
        match stmt {
            Statement::Block { statements, loc: _, unchecked: _ } => {
                for stmt in statements {
                    self.analyze_tx_origin(stmt, uses_tx_origin, has_auth_check);
                }
            }
            Statement::If { condition, .. } => {
                if let Expression::MemberAccess(_, obj, member) = condition {
                    if let Expression::Variable(id) = &**obj {
                        if id.name == "tx" && member.name == "origin" {
                            *uses_tx_origin = true;
                        }
                        if id.name == "msg" && member.name == "sender" {
                            *has_auth_check = true;
                        }
                    }
                }
            }
            Statement::Expression(_, expr) => {
                self.analyze_tx_origin_expr(expr, uses_tx_origin, has_auth_check);
            }
            _ => {}
        }
    }

    fn analyze_tx_origin_expr(&self, expr: &Expression, uses_tx_origin: &mut bool, has_auth_check: &mut bool) {
        match expr {
            Expression::MemberAccess(_, obj, member) => {
                if let Expression::Variable(id) = &**obj {
                    if id.name == "tx" && member.name == "origin" {
                        *uses_tx_origin = true;
                    }
                    if id.name == "msg" && member.name == "sender" {
                        *has_auth_check = true;
                    }
                }
            }
            _ => {}
        }
    }

    fn check_reentrancy(&self, pt: &SourceUnit, result: &mut AnalysisResult) {
        for part in &pt.0 {
            if let SourceUnitPart::ContractDefinition(contract) = part {
                for part in &contract.parts {
                    if let ContractPart::FunctionDefinition(func) = part {
                        if let Some(body) = &func.body {
                            let mut has_external_call = false;
                            let mut has_state_update = false;
                            let mut has_reentrancy_guard = false;
                            
                            self.analyze_reentrancy(body, &mut has_external_call, &mut has_state_update, &mut has_reentrancy_guard);
                            
                            if has_external_call && has_state_update && !has_reentrancy_guard {
                                result.vulnerabilities.push(Vulnerability {
                                    severity: Severity::Critical.to_string(),
                                    description: "Potential reentrancy vulnerability detected".to_string(),
                                    location: Location::from_loc(&func.loc),
                                    code_snippet: None,
                                    recommendation: Some("Implement checks-effects-interactions pattern or use ReentrancyGuard".to_string()),
                                    category: "Reentrancy".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    fn analyze_reentrancy(&self, stmt: &Statement, has_external_call: &mut bool, has_state_update: &mut bool, has_reentrancy_guard: &mut bool) {
        match stmt {
            Statement::Block { statements, loc: _, unchecked: _ } => {
                for stmt in statements {
                    self.analyze_reentrancy(stmt, has_external_call, has_state_update, has_reentrancy_guard);
                }
            }
            Statement::Expression(_, expr) => {
                self.analyze_reentrancy_expr(expr, has_external_call, has_state_update, has_reentrancy_guard);
            }
            Statement::If { condition, .. } => {
                if let Expression::MemberAccess(_, obj, member) = condition {
                    if let Expression::Variable(id) = &**obj {
                        if id.name == "nonReentrant" || member.name == "nonReentrant" {
                            *has_reentrancy_guard = true;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn analyze_reentrancy_expr(&self, expr: &Expression, has_external_call: &mut bool, has_state_update: &mut bool, has_reentrancy_guard: &mut bool) {
        match expr {
            Expression::FunctionCall(_, func, _) => {
                if let Expression::MemberAccess(_, _, member) = &**func {
                    if ["call", "send", "transfer"].contains(&member.name.as_str()) {
                        *has_external_call = true;
                    }
                    if member.name == "nonReentrant" {
                        *has_reentrancy_guard = true;
                    }
                }
            }
            Expression::Assignment(..) => {
                *has_state_update = true;
            }
            _ => {}
        }
    }

    fn check_integer_overflow(&self, pt: &SourceUnit, result: &mut AnalysisResult) {
        for part in &pt.0 {
            if let SourceUnitPart::ContractDefinition(contract) = part {
                for part in &contract.parts {
                    if let ContractPart::FunctionDefinition(func) = part {
                        if let Some(body) = &func.body {
                            let mut has_arithmetic = false;
                            let mut has_safe_math = false;
                            let mut has_bounds_check = false;
                            
                            self.analyze_integer_overflow(body, &mut has_arithmetic, &mut has_safe_math, &mut has_bounds_check);
                            
                            if has_arithmetic && !has_safe_math && !has_bounds_check {
                                result.vulnerabilities.push(Vulnerability {
                                    severity: Severity::High.to_string(),
                                    description: "Potential integer overflow/underflow detected".to_string(),
                                    location: Location::from_loc(&func.loc),
                                    code_snippet: None,
                                    recommendation: Some("Use SafeMath library or Solidity 0.8+ built-in overflow checks".to_string()),
                                    category: "Arithmetic".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    fn analyze_integer_overflow(&self, stmt: &Statement, has_arithmetic: &mut bool, has_safe_math: &mut bool, has_bounds_check: &mut bool) {
        match stmt {
            Statement::Block { statements, loc: _, unchecked: _ } => {
                for stmt in statements {
                    self.analyze_integer_overflow(stmt, has_arithmetic, has_safe_math, has_bounds_check);
                }
            }
            Statement::If { condition, .. } => {
                if let Expression::BinaryOperation(_, op, _, _) = condition {
                    if op == ">" || op == "<" || op == ">=" || op == "<=" {
                        *has_bounds_check = true;
                    }
                }
            }
            Statement::Expression(_, expr) => {
                self.analyze_integer_overflow_expr(expr, has_arithmetic, has_safe_math);
            }
            _ => {}
        }
    }

    fn analyze_integer_overflow_expr(&self, expr: &Expression, has_arithmetic: &mut bool, has_safe_math: &mut bool) {
        match expr {
            Expression::BinaryOperation(_, op, _, _) => {
                if ["+", "-", "*", "/"].contains(&op.as_str()) {
                    *has_arithmetic = true;
                }
            }
            Expression::FunctionCall(_, func, _) => {
                if let Expression::MemberAccess(_, _, member) = &**func {
                    if ["add", "sub", "mul", "div"].contains(&member.name.as_str()) {
                        *has_safe_math = true;
                    }
                }
            }
            _ => {}
        }
    }
}
