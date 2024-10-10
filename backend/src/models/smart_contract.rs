use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SmartContract {
    pub id: String,
    pub code: String,
}
