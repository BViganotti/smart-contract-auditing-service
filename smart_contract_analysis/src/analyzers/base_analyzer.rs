use crate::{Vulnerability, Location};
use solang_parser::pt::*;
use std::collections::HashSet;
use std::error::Error;

use super::AstVisitor;

pub struct BaseAnalyzer {
    vulnerabilities: Vec<Vulnerability>,
    visited_nodes: HashSet<String>,
}

impl BaseAnalyzer {
    pub fn new() -> Self {
        Self {
            vulnerabilities: Vec::new(),
            visited_nodes: HashSet::new(),
        }
    }

    pub fn add_vulnerability(&mut self, severity: &str, description: &str, location: &Location, recommendation: Option<String>, category: &str) {
        self.vulnerabilities.push(Vulnerability {
            severity: severity.to_string(),
            description: description.to_string(),
            location: location.clone(),
            code_snippet: None,
            recommendation,
            category: category.to_string(),
        });
    }

    pub fn get_vulnerabilities(&self) -> &[Vulnerability] {
        &self.vulnerabilities
    }

    pub fn has_visited(&mut self, node_key: &str) -> bool {
        !self.visited_nodes.insert(node_key.to_string())
    }

    pub fn analyze_expression(&mut self, expr: &Expression) -> bool {
        match expr {
            Expression::FunctionCall(_, func, args) => {
                self.analyze_function_call(func, args)
            }
            Expression::MemberAccess(_, obj, member) => {
                self.analyze_member_access(obj, member)
            }
            _ => false
        }
    }

    pub fn analyze_function_call(&mut self, _func: &Box<Expression>, _args: &[Expression]) -> bool {
        false // Override in specific analyzers
    }

    pub fn analyze_member_access(&mut self, _obj: &Box<Expression>, _member: &Identifier) -> bool {
        false // Override in specific analyzers
    }
}

impl Default for BaseAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl AstVisitor for BaseAnalyzer {
    fn visit_source_unit(&mut self, unit: &SourceUnit) -> Result<(), Box<dyn Error>> {
        for part in &unit.0 {
            self.visit_source_unit_part(part)?;
        }
        Ok(())
    }

    fn visit_contract(&mut self, contract: &ContractDefinition) -> Result<(), Box<dyn Error>> {
        for part in &contract.parts {
            self.visit_contract_part(part)?;
        }
        Ok(())
    }

    fn visit_contract_part(&mut self, part: &ContractPart) -> Result<(), Box<dyn Error>> {
        match part {
            ContractPart::FunctionDefinition(func) => self.visit_function(func),
            ContractPart::EventDefinition(event) => Ok(()), // No need to analyze events
            ContractPart::VariableDefinition(var) => Ok(()), // Base analyzer doesn't analyze state variables
            _ => Ok(()),
        }
    }

    fn visit_function(&mut self, func: &FunctionDefinition) -> Result<(), Box<dyn Error>> {
        if let Some(body) = &func.body {
            self.visit_statement(body)?;
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
            Statement::Expression(_, expr) => {
                self.visit_expression(expr)?;
            }
            Statement::If(_, cond, then_stmt, else_stmt) => {
                self.visit_expression(cond)?;
                self.visit_statement(then_stmt)?;
                if let Some(else_stmt) = else_stmt {
                    self.visit_statement(else_stmt)?;
                }
            }
            Statement::While(_, cond, body) => {
                self.visit_expression(cond)?;
                self.visit_statement(body)?;
            }
            Statement::For(_, init, cond, post, body) => {
                if let Some(init) = init {
                    self.visit_statement(init)?;
                }
                if let Some(cond) = cond {
                    self.visit_expression(cond)?;
                }
                if let Some(post) = post {
                    self.visit_expression(post)?;
                }
                if let Some(body) = body {
                    self.visit_statement(body)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn visit_expression(&mut self, expr: &Expression) -> Result<(), Box<dyn Error>> {
        self.analyze_expression(expr);
        match expr {
            Expression::FunctionCall(_, func, args) => {
                self.visit_expression(func)?;
                for arg in args {
                    self.visit_expression(arg)?;
                }
            }
            Expression::MemberAccess(_, obj, _) => {
                self.visit_expression(obj)?;
            }
            Expression::ArraySubscript(_, array, index) => {
                self.visit_expression(array)?;
                if let Some(index) = index {
                    self.visit_expression(index)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}
