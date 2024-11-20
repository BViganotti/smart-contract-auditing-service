use solang_parser::pt::*;
use std::error::Error;
use crate::{Vulnerability, Location};
use super::{vulnerability_analyzer::VulnerabilityAnalyzer, BaseAnalyzer, ast_visitor::AstVisitor};

pub struct TimestampAnalyzer {
    base: BaseAnalyzer,
    current_function: Option<String>,
    uses_timestamp: bool,
    uses_block_number: bool,
    has_time_constraint: bool,
}

impl TimestampAnalyzer {
    pub fn new() -> Self {
        Self {
            base: BaseAnalyzer::new(),
            current_function: None,
            uses_timestamp: false,
            uses_block_number: false,
            has_time_constraint: false,
        }
    }

    fn reset_state(&mut self) {
        self.current_function = None;
        self.uses_timestamp = false;
        self.uses_block_number = false;
        self.has_time_constraint = false;
    }

    fn check_timestamp_dependency(&mut self, expr: &Expression, loc: &Loc) -> Result<(), Box<dyn Error>> {
        match expr {
            Expression::MemberAccess(_, obj, member) => {
                if let Expression::Variable(id) = &**obj {
                    if id.name == "block" {
                        match member.name.as_str() {
                            "timestamp" => self.uses_timestamp = true,
                            "number" => self.uses_block_number = true,
                            _ => {}
                        }
                    }
                }
            }
            Expression::Less(_, _, _) |
            Expression::More(_, _, _) |
            Expression::LessEqual(_, _, _) |
            Expression::MoreEqual(_, _, _) => {
                self.has_time_constraint = true;
            }
            _ => {}
        }

        if (self.uses_timestamp || self.uses_block_number) && self.has_time_constraint {
            let time_source = if self.uses_timestamp { "block.timestamp" } else { "block.number" };
            let func_context = self.current_function.as_deref().unwrap_or("unnamed function");

            self.base.add_vulnerability(
                "Medium",
                &format!("Timestamp dependency in time constraint using {}", time_source),
                &Location::from_loc(loc),
                Some(format!(
                    "In function '{}': Miners can manipulate block timestamps. Consider using block numbers for time measurements or accepting small variations",
                    func_context
                )),
                "Timestamp Dependency"
            );
        }
        Ok(())
    }
}

impl VulnerabilityAnalyzer for TimestampAnalyzer {
    fn name(&self) -> &'static str {
        "Timestamp Dependency"
    }

    fn description(&self) -> &'static str {
        "Detects unsafe usage of block timestamps in time constraints"
    }

    fn analyze(&mut self, unit: &SourceUnit) -> Result<Vec<Vulnerability>, Box<dyn Error>> {
        self.visit_source_unit(unit)?;
        Ok(self.base.get_vulnerabilities().to_vec())
    }
}

impl AstVisitor for TimestampAnalyzer {
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
        self.check_timestamp_dependency(expr, &expr.loc())?;
        Ok(())
    }
}
