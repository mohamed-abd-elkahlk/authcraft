#[allow(unused)]
use core::fmt;
use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// Defines possible user roles.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]

pub struct RBACRole {
    pub name: String,
    pub permissions: HashSet<String>, // Example: ["read", "write", "delete"]
}

#[allow(dead_code)]
impl RBACRole {
    /// Creates a new role with a given name and permissions.
    pub fn define_role(name: String, permissions: HashSet<String>) -> Self {
        Self { name, permissions }
    }

    /// Checks if the role has a specific permission.
    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.contains(permission)
    }

    /// Adds a permission to the role.
    pub fn add_permission(&mut self, permission: String) {
        self.permissions.insert(permission);
    }

    /// Removes a permission from the role.
    pub fn remove_permission(&mut self, permission: &str) {
        self.permissions.remove(permission);
    }

    /// Checks if the role has all required permissions.
    pub fn has_all_permissions(&self, required_permissions: &[String]) -> bool {
        required_permissions
            .iter()
            .all(|p| self.permissions.contains(p))
    }

    /// Checks if the role has at least one required permission.
    pub fn has_any_permission(&self, required_permissions: &[String]) -> bool {
        required_permissions
            .iter()
            .any(|p| self.permissions.contains(p))
    }

    /// Merges permissions from another role.
    pub fn merge_permissions(&mut self, other: &RBACRole) {
        self.permissions.extend(other.permissions.clone());
    }

    /// Removes all permissions from the role.
    pub fn clear_permissions(&mut self) {
        self.permissions.clear();
    }
}
impl fmt::Display for RBACRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Role: {}, Permissions: {:?}",
            self.name, self.permissions
        )
    }
}
