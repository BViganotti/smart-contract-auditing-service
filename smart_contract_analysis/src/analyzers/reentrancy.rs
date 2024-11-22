use solang_parser::pt::*;
use std::error::Error;
use crate::{Vulnerability, Location, VulnerabilityType};
use super::{vulnerability_analyzer::VulnerabilityAnalyzer, BaseAnalyzer, ast_visitor::AstVisitor};

pub struct ReentrancyAnalyzer {
    base: BaseAnalyzer,
    has_external_call: bool,
    has_state_change: bool,
    has_reentrancy_guard: bool,
}

impl ReentrancyAnalyzer {
    pub fn new() -> Self {
        Self {
            base: BaseAnalyzer::new(),
            has_external_call: false,
            has_state_change: false,
            has_reentrancy_guard: false,
        }
    }

    fn reset_state(&mut self) {
        self.has_external_call = false;
        self.has_state_change = false;
        self.has_reentrancy_guard = false;
    }
}

impl VulnerabilityAnalyzer for ReentrancyAnalyzer {
    fn name(&self) -> &'static str {
        "Reentrancy"
    }

    fn description(&self) -> &'static str {
        "Detects potential reentrancy vulnerabilities in smart contracts"
    }

    fn analyze(&mut self, unit: &SourceUnit) -> Result<Vec<Vulnerability>, Box<dyn Error>> {
        self.visit_source_unit(unit)?;
        Ok(self.base.get_vulnerabilities().to_vec())
    }
}

impl AstVisitor for ReentrancyAnalyzer {
    fn visit_function(&mut self, func: &FunctionDefinition) -> Result<(), Box<dyn Error>> {
        self.reset_state();
        
        // Check for reentrancy guard modifier
        for attr in &func.attributes {
            if let FunctionAttribute::BaseOrModifier(_, base) = attr {
                if base.name.identifiers.iter().any(|id| 
                    id.name.contains("nonReentrant") || 
                    id.name.contains("noReentrant") ||
                    id.name.contains("reentrancyGuard")
                ) {
                    self.has_reentrancy_guard = true;
                }
            }
        }

        if let Some(body) = &func.body {
            self.visit_statement(body)?;
            
            if self.has_external_call && self.has_state_change && !self.has_reentrancy_guard {
                self.base.add_vulnerability(
                    VulnerabilityType::Reentrancy,
                    "Critical",
                    &format!("Potential reentrancy vulnerability in function '{}'", 
                            func.name.as_ref().map_or("unnamed", |n| &n.name)),
                    &Location::from_loc(&func.loc),
                    Some("Implement checks-effects-interactions pattern or use ReentrancyGuard".to_string()),
                    "Reentrancy"
                );
            }
        }
        
        Ok(())
    }

    fn visit_expression(&mut self, expr: &Expression) -> Result<(), Box<dyn Error>> {
        match expr {
            Expression::FunctionCall(_, func, _) => {
                if let Expression::MemberAccess(_, _, member) = &**func {
                    if ["call", "send", "transfer"].contains(&member.name.as_str()) {
                        self.has_external_call = true;
                    }
                }
            }
            Expression::Assign(..) => {
                self.has_state_change = true;
            }
            _ => {}
        }
        Ok(())
    }
}
