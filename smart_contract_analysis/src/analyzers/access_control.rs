use solang_parser::pt::*;
use std::error::Error;
use std::collections::HashSet;
use crate::{Vulnerability, Location};
use super::{vulnerability_analyzer::VulnerabilityAnalyzer, BaseAnalyzer, ast_visitor::AstVisitor};

pub struct AccessControlAnalyzer {
    base: BaseAnalyzer,
    current_function: Option<String>,
    access_modifiers: HashSet<String>,
    has_ownable: bool,
    has_access_control: bool,
}

impl AccessControlAnalyzer {
    pub fn new() -> Self {
        let mut access_modifiers = HashSet::new();
        access_modifiers.insert("onlyOwner".to_string());
        access_modifiers.insert("onlyAdmin".to_string());
        access_modifiers.insert("onlyRole".to_string());

        Self {
            base: BaseAnalyzer::new(),
            current_function: None,
            access_modifiers,
            has_ownable: false,
            has_access_control: false,
        }
    }

    fn reset_state(&mut self) {
        self.current_function = None;
    }

    fn check_critical_operation(&mut self, expr: &Expression, loc: &Loc) -> Result<(), Box<dyn Error>> {
        if !self.has_ownable && !self.has_access_control {
            let func_context = self.current_function.as_deref()
                .unwrap_or("unnamed function");

            // Check for critical operations
            let (is_critical, operation) = match expr {
                Expression::FunctionCall(_, func, _) => {
                    if let Expression::MemberAccess(_, _, member) = &**func {
                        match member.name.as_str() {
                            "selfdestruct" => (true, "contract destruction"),
                            "delegatecall" => (true, "delegatecall"),
                            _ => (false, ""),
                        }
                    } else {
                        (false, "")
                    }
                }
                _ => (false, ""),
            };

            if is_critical {
                self.base.add_vulnerability(
                    "Critical",
                    &format!("Unprotected {} operation", operation),
                    &Location::from_loc(loc),
                    Some(format!(
                        "In function '{}': Consider implementing access control using OpenZeppelin's Ownable or AccessControl",
                        func_context
                    )),
                    "Access Control"
                );
            }
        }
        Ok(())
    }
}

impl VulnerabilityAnalyzer for AccessControlAnalyzer {
    fn name(&self) -> &'static str {
        "Access Control"
    }

    fn description(&self) -> &'static str {
        "Detects missing or insufficient access control in critical operations"
    }

    fn analyze(&mut self, unit: &SourceUnit) -> Result<Vec<Vulnerability>, Box<dyn Error>> {
        self.visit_source_unit(unit)?;
        Ok(self.base.get_vulnerabilities().to_vec())
    }
}

impl AstVisitor for AccessControlAnalyzer {
    fn visit_contract(&mut self, contract: &ContractDefinition) -> Result<(), Box<dyn Error>> {
        // Check for Ownable or AccessControl inheritance
        for base in &contract.base {
            let name = &base.name.identifiers[0].name;
            if name == "Ownable" {
                self.has_ownable = true;
            } else if name == "AccessControl" {
                self.has_access_control = true;
            }
        }

        // Visit contract parts
        for part in &contract.parts {
            self.visit_contract_part(part)?;
        }
        Ok(())
    }

    fn visit_function(&mut self, func: &FunctionDefinition) -> Result<(), Box<dyn Error>> {
        self.reset_state();
        self.current_function = func.name.as_ref().map(|n| n.name.clone());

        // Check for access modifiers
        for attr in &func.attributes {
            if let FunctionAttribute::BaseOrModifier(_, base) = attr {
                if base.name.identifiers.iter().any(|id| 
                    self.access_modifiers.contains(&id.name)
                ) {
                    return Ok(());  // Function is protected
                }
            }
        }

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
            _ => {}
        }
        Ok(())
    }

    fn visit_expression(&mut self, expr: &Expression) -> Result<(), Box<dyn Error>> {
        self.check_critical_operation(expr, &expr.loc())?;
        Ok(())
    }
}
