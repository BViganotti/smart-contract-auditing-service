use solang_parser::pt::*;
use std::error::Error;
use crate::{Vulnerability, Location, VulnerabilityType};
use super::{vulnerability_analyzer::VulnerabilityAnalyzer, BaseAnalyzer, ast_visitor::AstVisitor};

pub struct ComplexityAnalyzer {
    base: BaseAnalyzer,
    complexity_threshold: u32,
    current_function_complexity: u32,
    current_function_name: Option<String>,
}

impl ComplexityAnalyzer {
    pub fn new() -> Self {
        Self {
            base: BaseAnalyzer::new(),
            complexity_threshold: 20,
            current_function_complexity: 0,
            current_function_name: None,
        }
    }

    fn reset_state(&mut self) {
        self.current_function_complexity = 0;
        self.current_function_name = None;
    }

    fn calculate_statement_complexity(&self, stmt: &Statement) -> u32 {
        match stmt {
            Statement::Block { statements, .. } => {
                statements.iter().map(|s| self.calculate_statement_complexity(s)).sum()
            }
            Statement::If(_, condition, then_branch, else_branch) => {
                let mut complexity = 1; // Base complexity for if statement
                complexity += self.calculate_expression_complexity(condition);
                complexity += self.calculate_statement_complexity(then_branch);
                if let Some(else_stmt) = else_branch {
                    complexity += self.calculate_statement_complexity(else_stmt);
                }
                complexity
            }
            Statement::While(_, condition, body) => {
                1 + self.calculate_expression_complexity(condition) + 
                self.calculate_statement_complexity(body)
            }
            Statement::For(_, init, cond, post, body) => {
                let mut complexity = 1; // Base complexity for for loop
                if let Some(init_stmt) = init {
                    complexity += self.calculate_statement_complexity(init_stmt);
                }
                if let Some(cond_expr) = cond {
                    complexity += self.calculate_expression_complexity(cond_expr);
                }
                if let Some(post_expr) = post {
                    complexity += self.calculate_expression_complexity(post_expr);
                }
                if let Some(body) = body {
                    complexity += self.calculate_statement_complexity(body);
                }
                complexity
            }
            Statement::Expression(_, expr) => self.calculate_expression_complexity(expr),
            _ => 0 // Base complexity for other statements
        }
    }

    fn calculate_expression_complexity(&self, expr: &Expression) -> u32 {
        match expr {
            Expression::Add(..) | Expression::Subtract(..) | Expression::Multiply(..) |
            Expression::Divide(..) | Expression::Modulo(..) | Expression::Power(..) |
            Expression::BitwiseOr(..) | Expression::BitwiseAnd(..) | Expression::BitwiseXor(..) |
            Expression::ShiftLeft(..) | Expression::ShiftRight(..) => 1,
            Expression::And(..) | Expression::Or(..) => 2, // Logical operations are slightly more complex
            Expression::ConditionalOperator(_, condition, true_expr, false_expr) => {
                1 + self.calculate_expression_complexity(condition) +
                self.calculate_expression_complexity(true_expr) +
                self.calculate_expression_complexity(false_expr)
            }
            Expression::FunctionCall(_, _, args) => {
                1 + args.iter().map(|arg| self.calculate_expression_complexity(arg)).sum::<u32>()
            }
            _ => 0,
        }
    }
}

impl VulnerabilityAnalyzer for ComplexityAnalyzer {
    fn name(&self) -> &'static str {
        "Complexity Analyzer"
    }

    fn description(&self) -> &'static str {
        "Analyzes function complexity and identifies functions that might be too complex"
    }

    fn analyze(&mut self, unit: &SourceUnit) -> Result<Vec<Vulnerability>, Box<dyn Error>> {
        self.reset_state();
        self.visit_source_unit(unit)?;
        Ok(self.base.get_vulnerabilities().to_vec())
    }
}

impl AstVisitor for ComplexityAnalyzer {
    fn visit_function(&mut self, func: &FunctionDefinition) -> Result<(), Box<dyn Error>> {
        self.current_function_name = func.name.as_ref().map(|n| n.name.clone());
        self.current_function_complexity = 1; // Base complexity

        // Add complexity for parameters
        self.current_function_complexity += func.params.len() as u32;

        // Add complexity for return parameters
        self.current_function_complexity += func.returns.len() as u32;

        // Visit function body
        if let Some(body) = &func.body {
            if let Statement::Block { statements, .. } = body {
                for statement in statements {
                    self.current_function_complexity += self.calculate_statement_complexity(statement);
                }
            }
        }

        if self.current_function_complexity > self.complexity_threshold {
            self.base.add_vulnerability(
                VulnerabilityType::HighComplexity,
                "Medium",
                &format!(
                    "Function '{}' has high cyclomatic complexity ({})", 
                    self.current_function_name.as_ref().unwrap_or(&"unnamed".to_string()),
                    self.current_function_complexity
                ),
                &Location::from_loc(&func.loc),
                Some("Consider breaking down the function into smaller, more manageable functions to improve readability and maintainability.".to_string()),
                "Complexity"
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

    fn visit_expression(&mut self, _expr: &Expression) -> Result<(), Box<dyn Error>> {
        // Expressions are handled in calculate_expression_complexity
        Ok(())
    }
}
