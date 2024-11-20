use solang_parser::pt::*;
use std::error::Error;
use crate::{Vulnerability, Location};
use super::{vulnerability_analyzer::VulnerabilityAnalyzer, BaseAnalyzer, ast_visitor::AstVisitor};

pub struct UncheckedCallsAnalyzer {
    base: BaseAnalyzer,
    current_function: Option<String>,
    in_require_block: bool,
    in_if_condition: bool,
    has_return_check: bool,
    last_call: Option<(String, Loc)>,
}

impl UncheckedCallsAnalyzer {
    pub fn new() -> Self {
        Self {
            base: BaseAnalyzer::new(),
            current_function: None,
            in_require_block: false,
            in_if_condition: false,
            has_return_check: false,
            last_call: None,
        }
    }

    fn reset_state(&mut self) {
        self.current_function = None;
        self.in_require_block = false;
        self.in_if_condition = false;
        self.has_return_check = false;
        self.last_call = None;
    }

    fn check_call(&mut self, expr: &Expression, loc: &Loc) -> Result<(), Box<dyn Error>> {
        if let Expression::FunctionCall(_, func, _) = expr {
            if let Expression::MemberAccess(_, _, member) = &**func {
                let call_type = member.name.as_str();
                if ["send", "call", "delegatecall", "staticcall"].contains(&call_type) {
                    self.last_call = Some((call_type.to_string(), loc.clone()));
                    
                    if !self.in_require_block && !self.in_if_condition && !self.has_return_check {
                        let func_context = self.current_function.as_deref()
                            .unwrap_or("unnamed function");

                        self.base.add_vulnerability(
                            "High",
                            &format!("Unchecked return value from {} call", call_type),
                            &Location::from_loc(loc),
                            Some(format!(
                                "In function '{}': The return value of {} should be checked. Consider using require() or if statement",
                                func_context, call_type
                            )),
                            "Unchecked Call"
                        );
                    }
                }
            }
        }
        Ok(())
    }
}

impl VulnerabilityAnalyzer for UncheckedCallsAnalyzer {
    fn name(&self) -> &'static str {
        "Unchecked Calls"
    }

    fn description(&self) -> &'static str {
        "Detects unchecked return values from external calls"
    }

    fn analyze(&mut self, unit: &SourceUnit) -> Result<Vec<Vulnerability>, Box<dyn Error>> {
        self.visit_source_unit(unit)?;
        Ok(self.base.get_vulnerabilities().to_vec())
    }
}

impl AstVisitor for UncheckedCallsAnalyzer {
    fn visit_function(&mut self, func: &FunctionDefinition) -> Result<(), Box<dyn Error>> {
        self.reset_state();
        self.current_function = func.name.as_ref().map(|n| n.name.clone());
        
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
                if let Expression::FunctionCall(_, func, _) = expr {
                    if let Expression::Variable(id) = &**func {
                        if id.name == "require" {
                            self.in_require_block = true;
                            self.visit_expression(expr)?;
                            self.in_require_block = false;
                            return Ok(());
                        }
                    }
                }
                self.visit_expression(expr)?;
            }
            Statement::If(_, cond, then_stmt, else_stmt) => {
                self.in_if_condition = true;
                self.visit_expression(cond)?;
                self.in_if_condition = false;
                
                self.visit_statement(then_stmt)?;
                if let Some(else_stmt) = else_stmt {
                    self.visit_statement(else_stmt)?;
                }
            }
            Statement::Return(_, expr) => {
                if let Some(expr) = expr {
                    if let Some((_, _)) = &self.last_call {
                        self.has_return_check = true;
                    }
                    self.visit_expression(expr)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn visit_expression(&mut self, expr: &Expression) -> Result<(), Box<dyn Error>> {
        self.check_call(expr, &expr.loc())?;
        
        match expr {
            Expression::FunctionCall(_, func, args) => {
                self.visit_expression(func)?;
                for arg in args {
                    self.visit_expression(arg)?;
                }
            }
            Expression::MemberAccess(_, expr, _) => {
                self.visit_expression(expr)?;
            }
            _ => {}
        }
        Ok(())
    }
}
