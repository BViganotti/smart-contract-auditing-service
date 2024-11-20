use solang_parser::pt::*;
use std::error::Error;

pub trait AstVisitor {
    fn visit_source_unit(&mut self, unit: &SourceUnit) -> Result<(), Box<dyn Error>> {
        for part in &unit.0 {
            self.visit_source_unit_part(part)?;
        }
        Ok(())
    }

    fn visit_source_unit_part(&mut self, part: &SourceUnitPart) -> Result<(), Box<dyn Error>> {
        match part {
            SourceUnitPart::ContractDefinition(contract) => self.visit_contract(contract),
            _ => Ok(()),
        }
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
            ContractPart::EventDefinition(event) => self.visit_event(event),
            ContractPart::VariableDefinition(var) => self.visit_variable(var),
            _ => Ok(()),
        }
    }

    fn visit_function(&mut self, func: &FunctionDefinition) -> Result<(), Box<dyn Error>> {
        if let Some(body) = &func.body {
            self.visit_statement(body)?;
        }
        Ok(())
    }

    fn visit_event(&mut self, _event: &EventDefinition) -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    fn visit_variable(&mut self, _var: &VariableDefinition) -> Result<(), Box<dyn Error>> {
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
            _ => {}
        }
        Ok(())
    }
}

pub fn walk_source_unit<V: AstVisitor>(visitor: &mut V, unit: &SourceUnit) -> Result<(), Box<dyn Error>> {
    visitor.visit_source_unit(unit)
}

pub fn walk_contract<V: AstVisitor>(visitor: &mut V, contract: &ContractDefinition) -> Result<(), Box<dyn Error>> {
    visitor.visit_contract(contract)
}

pub fn walk_contract_part<V: AstVisitor>(visitor: &mut V, part: &ContractPart) -> Result<(), Box<dyn Error>> {
    visitor.visit_contract_part(part)
}

pub fn walk_function<V: AstVisitor>(visitor: &mut V, func: &FunctionDefinition) -> Result<(), Box<dyn Error>> {
    visitor.visit_function(func)
}

pub fn walk_statement<V: AstVisitor>(visitor: &mut V, stmt: &Statement) -> Result<(), Box<dyn Error>> {
    visitor.visit_statement(stmt)
}

pub fn walk_expression<V: AstVisitor>(visitor: &mut V, expr: &Expression) -> Result<(), Box<dyn Error>> {
    visitor.visit_expression(expr)
}
