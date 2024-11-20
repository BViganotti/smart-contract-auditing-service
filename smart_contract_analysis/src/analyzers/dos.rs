use solang_parser::pt::*;
use std::error::Error;
use crate::{Vulnerability, Location};
use super::{vulnerability_analyzer::VulnerabilityAnalyzer, BaseAnalyzer, ast_visitor::AstVisitor};

pub struct DosAnalyzer {
    base: BaseAnalyzer,
    current_function: Option<String>,
    loop_stack: Vec<(bool, bool, Option<Loc>)>, // (has_external_call, has_unbounded_operation, location)
}

impl DosAnalyzer {
    pub fn new() -> Self {
        Self {
            base: BaseAnalyzer::new(),
            current_function: None,
            loop_stack: Vec::new(),
        }
    }

    fn reset_state(&mut self) {
        self.current_function = None;
        self.loop_stack.clear();
    }

    fn check_loop_operations(&mut self, loc: &Loc) -> Result<(), Box<dyn Error>> {
        if let Some((has_external_call, has_unbounded_operation, _)) = self.loop_stack.last() {
            if *has_external_call || *has_unbounded_operation {
                let risk_type = if *has_external_call {
                    "external calls"
                } else {
                    "unbounded operations"
                };

                let func_context = self.current_function.as_deref()
                    .unwrap_or("unnamed function");

                self.base.add_vulnerability(
                    "High",
                    &format!("Potential DoS via unbounded loop with {}", risk_type),
                    &Location::from_loc(loc),
                    Some(format!(
                        "In function '{}': Loop contains {} which could lead to DoS. Consider implementing limits or batching",
                        func_context, risk_type
                    )),
                    "Denial of Service"
                );
            }
        }
        Ok(())
    }

    fn check_external_call(&mut self, expr: &Expression) -> Result<(), Box<dyn Error>> {
        if let Some((ref mut has_external_call, _, _)) = self.loop_stack.last_mut() {
            match expr {
                Expression::FunctionCall(_, func, _) => {
                    if let Expression::MemberAccess(_, _, member) = &**func {
                        if ["call", "send", "transfer", "delegatecall"].contains(&member.name.as_str()) {
                            *has_external_call = true;
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn check_unbounded_operation(&mut self, expr: &Expression) -> Result<(), Box<dyn Error>> {
        if let Some((_, ref mut has_unbounded_operation, _)) = self.loop_stack.last_mut() {
            match expr {
                Expression::ArraySubscript(..) |
                Expression::ArraySlice(..) => {
                    *has_unbounded_operation = true;
                }
                Expression::MemberAccess(_, obj, member) => {
                    // Check for common mapping or array operations
                    if let Expression::Variable(id) = &**obj {
                        if id.name == "push" || id.name == "length" || 
                           member.name == "push" || member.name == "length" ||
                           member.name == "keys" || member.name == "values" {
                            *has_unbounded_operation = true;
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}

impl VulnerabilityAnalyzer for DosAnalyzer {
    fn name(&self) -> &'static str {
        "Denial of Service"
    }

    fn description(&self) -> &'static str {
        "Detects potential denial of service vulnerabilities in loops and operations"
    }

    fn analyze(&mut self, unit: &SourceUnit) -> Result<Vec<Vulnerability>, Box<dyn Error>> {
        self.visit_source_unit(unit)?;
        Ok(self.base.get_vulnerabilities().to_vec())
    }
}

impl AstVisitor for DosAnalyzer {
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
            Statement::For(loc, init, cond, post, body) => {
                // Push new loop state
                self.loop_stack.push((false, false, Some(loc.clone())));
                
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
                
                // Check for vulnerabilities before popping state
                self.check_loop_operations(loc)?;
                
                // Pop loop state
                self.loop_stack.pop();
            }
            Statement::While(loc, cond, body) => {
                // Push new loop state
                self.loop_stack.push((false, false, Some(loc.clone())));
                
                    self.visit_expression(cond)?;
                    self.visit_statement(body)?;
                // Check for vulnerabilities before popping state
                self.check_loop_operations(loc)?;
                
                // Pop loop state
                self.loop_stack.pop();
            }
            Statement::Expression(_, expr) => {
                self.visit_expression(expr)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn visit_expression(&mut self, expr: &Expression) -> Result<(), Box<dyn Error>> {
        // Only check for vulnerabilities if we're in a loop
        if !self.loop_stack.is_empty() {
            self.check_external_call(expr)?;
            self.check_unbounded_operation(expr)?;
        }
        
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
