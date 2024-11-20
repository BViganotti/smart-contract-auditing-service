use solang_parser::pt::*;
use std::error::Error;
use crate::{Vulnerability, Location};
use super::{vulnerability_analyzer::VulnerabilityAnalyzer, BaseAnalyzer, ast_visitor::AstVisitor};

pub struct GasAnalyzer {
    base: BaseAnalyzer,
    current_function: Option<String>,
    current_function_cost: u64,
    current_contract_cost: u64,
}

impl GasAnalyzer {
    pub fn new() -> Self {
        Self {
            base: BaseAnalyzer::new(),
            current_function: None,
            current_function_cost: 0,
            current_contract_cost: 0,
        }
    }

    fn reset_state(&mut self) {
        self.current_function = None;
        self.current_function_cost = 0;
        self.current_contract_cost = 0;
    }

    fn estimate_statement_gas(&self, stmt: &Statement) -> u64 {
        match stmt {
            Statement::Block { statements, .. } => {
                statements.iter().map(|s| self.estimate_statement_gas(s)).sum()
            }
            Statement::If(_, condition, then_branch, else_branch) => {
                let mut cost = 300; // Base cost for if statement
                cost += self.estimate_expression_gas(condition);
                cost += self.estimate_statement_gas(then_branch);
                if let Some(else_stmt) = else_branch {
                    cost += self.estimate_statement_gas(else_stmt);
                }
                cost
            }
            Statement::While(_, condition, body) => {
                500 + self.estimate_expression_gas(condition) +
                self.estimate_statement_gas(body)
            }
            Statement::For(_, init, cond, post, body) => {
                let mut cost = 600; // Base cost for for loop
                if let Some(init_stmt) = init {
                    cost += self.estimate_statement_gas(init_stmt);
                }
                if let Some(cond_expr) = cond {
                    cost += self.estimate_expression_gas(cond_expr);
                }
                if let Some(post_expr) = post {
                    cost += self.estimate_expression_gas(post_expr);
                }
                if let Some(body) = body {
                    cost += self.estimate_statement_gas(body);
                }
                cost
            }
            Statement::Expression(_, expr) => self.estimate_expression_gas(expr),
            _ => 100 // Base cost for other statements
        }
    }

    fn estimate_expression_gas(&self, expr: &Expression) -> u64 {
        match expr {
            Expression::Add(..) | Expression::Subtract(..) => 3,
            Expression::Multiply(..) => 5,
            Expression::Divide(..) | Expression::Modulo(..) => 8,
            Expression::Power(..) => 10,
            Expression::BitwiseOr(..) | Expression::BitwiseAnd(..) |
            Expression::BitwiseXor(..) => 3,
            Expression::ShiftLeft(..) | Expression::ShiftRight(..) => 3,
            Expression::FunctionCall(_, _, args) => {
                2100 + // Base cost for function call
                args.iter().map(|arg| self.estimate_expression_gas(arg)).sum::<u64>()
            }
            Expression::ArraySubscript(..) => 100, // Array access
            Expression::MemberAccess(..) => 100,   // Member access
            Expression::New(..) => 200,            // Object creation
            _ => 3,                                // Other expressions
        }
    }

    fn check_gas_intensive_operations(&mut self, expr: &Expression, loc: &Loc) -> Result<(), Box<dyn Error>> {
        match expr {
            Expression::FunctionCall(_, func, _) => {
                if let Expression::MemberAccess(_, _, member) = &**func {
                    if member.name == "push" || member.name == "length" {
                        self.base.add_vulnerability(
                            "Medium",
                            "Gas-intensive array operation in loop",
                            &Location::from_loc(loc),
                            Some("Consider caching array length outside loop or using fixed size arrays".to_string()),
                            "Gas Optimization"
                        );
                    }
                }
            }
            Expression::ArraySubscript(_, ..) => {
                self.base.add_vulnerability(
                    "Low",
                    "Array access may be gas intensive",
                    &Location::from_loc(loc),
                    Some("Consider using mappings instead of arrays for O(1) access".to_string()),
                    "Gas Optimization"
                );
            }
            _ => {}
        }
        Ok(())
    }
}

impl VulnerabilityAnalyzer for GasAnalyzer {
    fn name(&self) -> &'static str {
        "Gas Usage Analyzer"
    }

    fn description(&self) -> &'static str {
        "Analyzes gas usage and identifies potential gas optimization opportunities"
    }

    fn analyze(&mut self, unit: &SourceUnit) -> Result<Vec<Vulnerability>, Box<dyn Error>> {
        self.reset_state();
        self.visit_source_unit(unit)?;
        Ok(self.base.get_vulnerabilities().to_vec())
    }
}

impl AstVisitor for GasAnalyzer {
    fn visit_contract(&mut self, contract: &ContractDefinition) -> Result<(), Box<dyn Error>> {
        self.current_contract_cost = 32000; // Base deployment cost

        // Add cost for contract storage
        for part in &contract.parts {
            match part {
                ContractPart::VariableDefinition(var) => {
                    self.current_contract_cost += 20000; // Base cost for storage variable
                    if let Some(expr) = &var.initializer {
                        self.current_contract_cost += self.estimate_expression_gas(expr);
                    }
                }
                _ => {}
            }
        }

        if self.current_contract_cost > 4_000_000 {
            self.base.add_vulnerability(
                "Medium",
                &format!("High contract deployment cost ({} gas)", self.current_contract_cost),
                &Location::from_loc(&contract.loc),
                Some("Consider optimizing contract size and initialization".to_string()),
                "Gas Optimization"
            );
        }

        Ok(())
    }

    fn visit_function(&mut self, func: &FunctionDefinition) -> Result<(), Box<dyn Error>> {
        self.current_function = func.name.as_ref().map(|n| n.name.clone());
        self.current_function_cost = 21000; // Base transaction cost

        // Add cost for parameters
        self.current_function_cost += (func.params.len() as u64) * 200;

        // Visit function body
        if let Some(body) = &func.body {
            if let Statement::Block { statements, .. } = body {
                for statement in statements {
                    self.current_function_cost += self.estimate_statement_gas(statement);
                    self.visit_statement(statement)?;
                }
            }
        }

        if self.current_function_cost > 100_000 {
            self.base.add_vulnerability(
                "Medium",
                &format!(
                    "Function '{}' has high gas cost ({} gas)", 
                    self.current_function.as_ref().unwrap_or(&"unnamed".to_string()),
                    self.current_function_cost
                ),
                &Location::from_loc(&func.loc),
                Some("Consider optimizing function logic or splitting into multiple functions".to_string()),
                "Gas Optimization"
            );
        }

        Ok(())
    }

    fn visit_statement(&mut self, stmt: &Statement) -> Result<(), Box<dyn Error>> {
        match stmt {
            Statement::Block { statements, .. } => {
                for stmt in statements {
                    self.visit_statement(stmt)?;
                }
            }
            Statement::If(_, condition, then_branch, else_branch) => {
                self.visit_expression(condition)?;
                self.visit_statement(then_branch)?;
                if let Some(else_stmt) = else_branch {
                    self.visit_statement(else_stmt)?;
                }
            }
            Statement::While(_, condition, body) => {
                self.visit_expression(condition)?;
                self.visit_statement(body)?;
            }
            Statement::For(_, init, cond, post, body) => {
                if let Some(init_stmt) = init {
                    self.visit_statement(init_stmt)?;
                }
                if let Some(cond_expr) = cond {
                    self.visit_expression(cond_expr)?;
                }
                if let Some(post_expr) = post {
                    self.visit_expression(post_expr)?;
                }
                if let Some(body) = body {
                    self.visit_statement(body)?;
                }
            }
            Statement::Expression(_, expr) => {
                self.visit_expression(expr)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn visit_expression(&mut self, expr: &Expression) -> Result<(), Box<dyn Error>> {
        self.check_gas_intensive_operations(expr, &expr.loc())?;
        Ok(())
    }
}
