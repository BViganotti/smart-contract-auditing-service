use solang_parser::pt::*;
use std::error::Error;
use crate::{Vulnerability, Location};
use super::{vulnerability_analyzer::VulnerabilityAnalyzer, BaseAnalyzer, ast_visitor::AstVisitor};

pub struct IntegerOverflowAnalyzer {
    base: BaseAnalyzer,
    current_function: Option<String>,
    in_unchecked_block: bool,
    has_safe_math: bool,
    solidity_version: Option<String>,
}

impl IntegerOverflowAnalyzer {
    pub fn new() -> Self {
        Self {
            base: BaseAnalyzer::new(),
            current_function: None,
            in_unchecked_block: false,
            has_safe_math: false,
            solidity_version: None,
        }
    }

    fn reset_state(&mut self) {
        self.current_function = None;
        self.in_unchecked_block = false;
        // Don't reset has_safe_math and solidity_version as they are contract-level
    }

    fn check_arithmetic_operation(&mut self, expr: &Expression, loc: &Loc) -> Result<(), Box<dyn Error>> {
        // Skip if using SafeMath or Solidity >= 0.8.0 (unless in unchecked block)
        if (self.has_safe_math || self.is_safe_solidity_version()) && !self.in_unchecked_block {
            return Ok(());
        }

        let (op_type, severity) = match expr {
            Expression::Add(..) => ("addition", "Medium"),
            Expression::Subtract(..) => ("subtraction", "Medium"),
            Expression::Multiply(..) => ("multiplication", "High"),
            Expression::Divide(..) => ("division", "High"), // Division by zero
            Expression::Modulo(..) => ("modulo", "Medium"),
            Expression::BitwiseAnd(..) |
            Expression::BitwiseOr(..) |
            Expression::BitwiseXor(..) |
            Expression::ShiftLeft(..) |
            Expression::ShiftRight(..) => ("bitwise operation", "Medium"),
            _ => return Ok(()),
        };

        let func_context = self.current_function.as_deref()
            .unwrap_or("unnamed function");

        let mut recommendation = format!(
            "In function '{}': Consider using SafeMath or upgrading to Solidity >= 0.8.0",
            func_context
        );

        if self.in_unchecked_block {
            recommendation.push_str(". This operation is in an unchecked block, ensure this is intentional");
        }

        self.base.add_vulnerability(
            severity,
            &format!("Potential integer overflow/underflow in {} operation", op_type),
            &Location::from_loc(loc),
            Some(recommendation),
            "Integer Overflow"
        );

        Ok(())
    }

    fn is_safe_solidity_version(&self) -> bool {
        if let Some(ref version) = self.solidity_version {
            // Parse major and minor version numbers
            let parts: Vec<&str> = version.split('.').collect();
            if parts.len() >= 2 {
                if let (Ok(major), Ok(minor)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
                    return major > 0 || (major == 0 && minor >= 8);
                }
            }
        }
        false
    }

    fn report_vulnerability(&mut self, loc: &Loc, op_type: &str) -> Result<(), Box<dyn Error>> {
        if !self.has_safe_math && !self.is_safe_solidity_version() {
            self.base.add_vulnerability(
                "Medium",
                &format!("Potential integer overflow/underflow in compound {} operation", op_type),
                &Location::from_loc(loc),
                Some("Consider using SafeMath or upgrading to Solidity >= 0.8.0".to_string()),
                "Integer Overflow"
            );
        }
        Ok(())
    }

    fn check_compound_assignment(&mut self, expr: &Expression, loc: &Loc) -> Result<(), Box<dyn Error>> {
        match expr {
            Expression::AssignAdd(_, _, _) => {
                self.report_vulnerability(loc, "addition")?;
            }
            Expression::AssignSubtract(_, _, _) => {
                self.report_vulnerability(loc, "subtraction")?;
            }
            Expression::AssignMultiply(_, _, _) => {
                self.report_vulnerability(loc, "multiplication")?;
            }
            Expression::AssignDivide(_, _, _) => {
                self.report_vulnerability(loc, "division")?;
            }
            Expression::AssignModulo(_, _, _) => {
                self.report_vulnerability(loc, "modulo")?;
            }
            _ => {}
        }
        Ok(())
    }
}

impl VulnerabilityAnalyzer for IntegerOverflowAnalyzer {
    fn name(&self) -> &'static str {
        "Integer Overflow"
    }

    fn description(&self) -> &'static str {
        "Detects potential integer overflow vulnerabilities in arithmetic operations"
    }

    fn analyze(&mut self, unit: &SourceUnit) -> Result<Vec<Vulnerability>, Box<dyn Error>> {
        self.visit_source_unit(unit)?;
        Ok(self.base.get_vulnerabilities().to_vec())
    }
}

impl AstVisitor for IntegerOverflowAnalyzer {
    fn visit_source_unit(&mut self, unit: &SourceUnit) -> Result<(), Box<dyn Error>> {
        // Check Solidity version from pragma directive
        for part in &unit.0 {
            if let SourceUnitPart::PragmaDirective(pragma) = part {
                if let PragmaDirective::Version(_, _, version_comparators) = &**pragma {
                    // Check if any version comparator indicates a version >= 0.8.0
                    let is_safe_version = version_comparators.iter().any(|comp| {
                        match comp {
                            VersionComparator::Plain { version, .. } => {
                                // Check if version is >= 0.8.0
                                if version.len() >= 2 {
                                    let major: u32 = version[0].parse().unwrap_or(0);
                                    let minor: u32 = version[1].parse().unwrap_or(0);
                                    major > 0 || minor >= 8
                                } else {
                                    false
                                }
                            }
                            VersionComparator::Range { from, .. } => {
                                // Check if the range includes versions >= 0.8.0
                                if from.len() >= 2 {
                                    let major: u32 = from[0].parse().unwrap_or(0);
                                    let minor: u32 = from[1].parse().unwrap_or(0);
                                    major > 0 || minor >= 8
                                } else {
                                    false
                                }
                            }
                            VersionComparator::Operator { op, version, .. } => {
                                if version.len() >= 2 {
                                    let major: u32 = version[0].parse().unwrap_or(0);
                                    let minor: u32 = version[1].parse().unwrap_or(0);
                                    match op {
                                        VersionOp::Greater | VersionOp::GreaterEq => {
                                            major > 0 || minor >= 8
                                        }
                                        _ => false,
                                    }
                                } else {
                                    false
                                }
                            }
                            _ => false,
                        }
                    });

                    if is_safe_version {
                        self.solidity_version = Some("0.8.0".to_string());
                        break;
                    }
                }
            }
        }
        
        // Visit the rest of the source unit
        for part in &unit.0 {
            self.visit_source_unit_part(part)?;
        }
        Ok(())
    }

    fn visit_contract(&mut self, contract: &ContractDefinition) -> Result<(), Box<dyn Error>> {
        // Check for SafeMath usage in contract
        for part in &contract.parts {
            if let ContractPart::Using(using) = part {
                // Check if the using directive is for SafeMath
                let is_safemath = match &using.list {
                    UsingList::Library(id) => id.identifiers.iter().any(|id| id.name == "SafeMath"),
                    UsingList::Functions(func) => func.iter().any(|f| f.path.identifiers.iter().any(|id| id.name == "SafeMath")),
                    _ => false,
                };
                
                if is_safemath {
                    self.has_safe_math = true;
                    break;
                }
            }
        }

        // Visit all parts of the contract
        for part in &contract.parts {
            match part {
                ContractPart::FunctionDefinition(func) => self.visit_function(func)?,
                ContractPart::VariableDefinition(var) => {
                    if let Some(init) = &var.initializer {
                        self.visit_expression(init)?;
                    }
                },
                _ => (), // Skip other contract parts
            }
        }
        Ok(())
    }

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
            Statement::Block { unchecked, statements, .. } => {
                let prev_unchecked = self.in_unchecked_block;
                self.in_unchecked_block = *unchecked;
                
                for stmt in statements {
                    self.visit_statement(stmt)?;
                }
                
                self.in_unchecked_block = prev_unchecked;
            }
            Statement::Expression(loc, expr) => {
                self.check_compound_assignment(expr, loc)?;
                self.visit_expression(expr)?;
            }
            Statement::For(_, init, cond, post, body) => {
                // Check initialization
                if let Some(init_stmt) = init {
                    self.visit_statement(init_stmt)?;
                }
                
                // Check condition
                if let Some(cond_expr) = cond {
                    self.visit_expression(cond_expr)?;
                }
                
                // Check post-iteration expression
                if let Some(post_expr) = post {
                    self.visit_expression(post_expr)?;
                }
                
                // Check loop body
                if let Some(body_stmt) = body {
                    self.visit_statement(body_stmt)?;
                }
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
            Statement::DoWhile(_, body, cond) => {
                self.visit_statement(body)?;
                self.visit_expression(cond)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn visit_expression(&mut self, expr: &Expression) -> Result<(), Box<dyn Error>> {
        match expr {
            Expression::Add(_, left, right) |
            Expression::Multiply(_, left, right) |
            Expression::Subtract(_, left, right) => {
                // Skip check if we're using Solidity >= 0.8.0 (built-in overflow checks)
                if let Some(version) = &self.solidity_version {
                    if version == "0.8.0" {
                        return Ok(());
                    }
                }

                // Check if SafeMath is being used
                if !self.has_safe_math {
                    // Get operation type for the warning message
                    let op_type = match expr {
                        Expression::Add(_, _, _) => "addition",
                        Expression::Multiply(_, _, _) => "multiplication",
                        Expression::Subtract(_, _, _) => "subtraction",
                        _ => unreachable!(),
                    };

                    // Add warning about potential overflow
                    self.base.add_vulnerability(
                        "Medium",
                        &format!("Potential integer overflow in {} operation", op_type),
                        &Location::from_loc(&expr.loc()),
                        Some(format!("Consider using SafeMath or upgrading to Solidity >= 0.8.0")),
                        "Integer Overflow"
                    );
                }

                // Continue visiting child expressions
                self.visit_expression(&left)?;
                self.visit_expression(&right)?;
            }
            Expression::Assign(_, left, right) => {
                self.check_compound_assignment(expr, &left.loc())?;
                self.visit_expression(&left)?;
                self.visit_expression(&right)?;
            }
            _ => {}
        }

        // Visit child expressions
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
