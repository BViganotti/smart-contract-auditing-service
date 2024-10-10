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

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub warnings: Vec<String>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub gas_usage: GasUsage,
    pub complexity_score: u32,
    pub function_complexities: HashMap<String, u32>,
    pub analysis_result: String,
    pub analysis_time: Duration,
    pub pattern_results: Vec<PatternMatchResult>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PatternMatchResult {
    pub pattern_index: usize,
    pub location: Loc,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct GasUsage {
    pub estimated_deployment_cost: u64,
    pub estimated_function_costs: Vec<(String, u64)>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Vulnerability {
    pub severity: Severity,
    pub description: String,
    pub location: Loc,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl SmartContractAnalyzer {
    pub fn new(config: AnalyzerConfig) -> Self {
        Self { config }
    }

    pub fn analyze_smart_contract(&self, contract_code: &str) -> AnalysisResult {
        println!("Starting analysis of smart contract");
        let start_time = Instant::now();
        let mut result = AnalysisResult::default();

        // Parse the contract
        let (pt, errors) = match parse(contract_code, 0) {
            Ok((pt, errors)) => (pt, errors),
            Err(e) => {
                result.error = Some(format!("Failed to parse contract: {:?}", e));
                return result;
            }
        };

        if !errors.is_empty() {
            result.error = Some(format!("Parse errors: {:?}", errors));
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

        result.analysis_time = start_time.elapsed();
        result.analysis_result = if result.warnings.is_empty() {
            "No issues found".to_string()
        } else {
            format!("{} issues found", result.warnings.len())
        };

        result
    }

    fn parallel_analysis(&self, pt: &SourceUnit, result: &mut AnalysisResult) {
        let checks: Vec<(&str, fn(&Self, &SourceUnit, &mut AnalysisResult))> = vec![
            ("Reentrancy", Self::check_reentrancy),
            ("Unchecked External Calls", Self::check_unchecked_calls),
            ("Integer Overflow/Underflow", Self::check_integer_overflow),
            // Add more checks as needed
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

    fn check_reentrancy(&self, pt: &SourceUnit, result: &mut AnalysisResult) {
        for part in &pt.0 {
            if let SourceUnitPart::ContractDefinition(contract) = part {
                for part in &contract.parts {
                    if let ContractPart::FunctionDefinition(func) = part {
                        if self.function_has_reentrancy(func) {
                            result.warnings.push(format!(
                                "Potential reentrancy in function '{}'",
                                func.name.as_ref().map_or("unnamed", |n| &n.name)
                            ));
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
            Expression::FunctionCall(_, func, _) => {
                if let Expression::MemberAccess(_, member_expr, member) = &**func {
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
                        if let Some(body) = &func.body {
                            self.check_unchecked_calls_in_statement(body, result);
                        }
                    }
                }
            }
        }
    }

    fn check_unchecked_calls_in_statement(&self, stmt: &Statement, result: &mut AnalysisResult) {
        match stmt {
            Statement::Block { statements, .. } => {
                for stmt in statements {
                    self.check_unchecked_calls_in_statement(stmt, result);
                }
            }
            Statement::Expression(_, expr) => {
                self.check_unchecked_calls_in_expression(expr, result);
            }
            Statement::If(_, cond, then_stmt, else_stmt) => {
                self.check_unchecked_calls_in_expression(cond, result);
                self.check_unchecked_calls_in_statement(then_stmt, result);
                if let Some(else_stmt) = else_stmt {
                    self.check_unchecked_calls_in_statement(else_stmt, result);
                }
            }
            // Add other statement types as needed
            _ => {}
        }
    }

    fn check_unchecked_calls_in_expression(&self, expr: &Expression, result: &mut AnalysisResult) {
        match expr {
            Expression::FunctionCall(loc, func, args) => {
                if let Expression::MemberAccess(_, _, member) = &**func {
                    if member.name == "call" || member.name == "delegatecall" {
                        result
                            .warnings
                            .push(format!("Unchecked external call at {:?}", loc));
                    }
                }
                for arg in args {
                    self.check_unchecked_calls_in_expression(arg, result);
                }
            }
            // Add other expression types as needed
            _ => {}
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
                        result.warnings.push(format!(
                            "Use of deprecated function '{}' at {:?}",
                            id.name, loc
                        ));
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
                        result
                            .warnings
                            .push(format!("Use of '{}' at {:?}", id.name, loc));
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
            | Expression::Multiply(_, _, _) => {
                result.warnings.push(format!(
                    "Potential integer overflow at {:?}. Consider using SafeMath.",
                    loc
                ));
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
                result.warnings.push(format!(
                    "Use of tx.origin at {:?}. Consider using msg.sender instead.",
                    loc
                ));
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
                    result.warnings.push(format!(
                        "Contract '{:?}' does not define any events. Consider adding events for important state changes.",
                        contract.name
                    ));
                }
            }
        }
    }

    fn static_analysis(&self, result: &mut AnalysisResult, pt: &SourceUnit) {
        let contracts: Vec<_> =
            pt.0.iter()
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
                                        "{:#?}::{:#?}",
                                        contract.name,
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
                                "{:#?}::{:#?}",
                                contract.name,
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
                result.warnings.push(format!(
                    "Contract '{:#?}' has {} nodes",
                    contract.name, contract_nodes
                ));

                for part in &contract.parts {
                    if let ContractPart::FunctionDefinition(func) = part {
                        let func_nodes = self.count_contract_part(part);
                        result.warnings.push(format!(
                            "Function '{:#?}' in contract '{:#?}' has {} nodes",
                            func.name.as_ref().map_or("unnamed", |n| &n.name),
                            contract.name,
                            func_nodes
                        ));
                    }
                }
            }
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

    fn estimate_gas_usage(&self, pt: &SourceUnit) -> GasUsage {
        let mut deployment_cost = 0;
        let mut function_costs = Vec::new();

        for part in &pt.0 {
            if let SourceUnitPart::ContractDefinition(contract) = part {
                deployment_cost += self.estimate_contract_deployment_cost(contract);
                for part in &contract.parts {
                    if let ContractPart::FunctionDefinition(func) = part {
                        let cost = self.estimate_function_cost(func);
                        if let Some(name) = &func.name {
                            function_costs.push((name.name.clone(), cost));
                        }
                    }
                }
            }
        }

        GasUsage {
            estimated_deployment_cost: deployment_cost,
            estimated_function_costs: function_costs,
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
}
