//! Role-Based Access Control (RBAC) module.
//! This module defines the `Role` struct, which represents user roles
//! with associated permissions.
//!
//! ## Example Usage
//!
//! ```
//! use std::collections::HashSet;
//! use authcraft::rbac::Role;
//!
//! let mut permissions = HashSet::new();
//! permissions.insert("read".to_string());
//! permissions.insert("write".to_string());
//!
//! let mut role = Role::define_role("Admin".to_string(), permissions);
//!
//! // Check if the role has a permission
//! assert!(role.has_permission("read"));
//!
//! // Add a new permission
//! role.add_permission("delete".to_string());
//! assert!(role.has_permission("delete"));
//!
//! // Remove a permission
//! role.remove_permission("write");
//! assert!(!role.has_permission("write"));
//!
//! // Display the role
//! println!("{}", role);
//! ```

use core::fmt;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Defines possible user roles.
#[cfg(feature = "rbac")]
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Role {
    /// The name of the role.
    pub name: String,
    /// Set of permissions associated with the role (e.g., ["read", "write", "delete"]).
    pub permissions: HashSet<String>,
}

#[allow(dead_code)]
impl Role {
    /// Creates a new role with a given name and permissions.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the role.
    /// * `permissions` - A set of permissions assigned to the role.
    ///
    /// # Returns
    ///
    /// Returns a new `Role` instance.
    ///
    /// # Example
    ///
    /// ```
    /// use std::collections::HashSet;
    /// use authcraft::rbac::Role;
    ///
    /// let mut permissions = HashSet::new();
    /// permissions.insert("read".to_string());
    ///
    /// let role = Role::define_role("User".to_string(), permissions);
    ///
    /// assert!(role.has_permission("read"));
    /// ```
    pub fn define_role(name: String, permissions: HashSet<String>) -> Self {
        Self { name, permissions }
    }

    /// Checks if the role has a specific permission.
    ///
    /// # Arguments
    ///
    /// * `permission` - The permission to check.
    ///
    /// # Returns
    ///
    /// Returns `true` if the role has the permission, otherwise `false`.
    ///
    /// # Example
    ///
    /// ```
    /// use std::collections::HashSet;
    /// use authcraft::rbac::Role;
    ///
    /// let mut permissions = HashSet::new();
    /// permissions.insert("write".to_string());
    ///
    /// let role = Role::define_role("Editor".to_string(), permissions);
    ///
    /// assert!(role.has_permission("write"));
    /// assert!(!role.has_permission("delete"));
    /// ```
    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.contains(permission)
    }

    /// Adds a permission to the role.
    ///
    /// # Arguments
    ///
    /// * `permission` - The permission to add.
    ///
    /// # Example
    ///
    /// ```
    /// use std::collections::HashSet;
    /// use authcraft::rbac::Role;
    ///
    /// let mut permissions = HashSet::new();
    /// let mut role = Role::define_role("Manager".to_string(), permissions);
    ///
    /// role.add_permission("approve".to_string());
    /// assert!(role.has_permission("approve"));
    /// ```
    pub fn add_permission(&mut self, permission: String) {
        self.permissions.insert(permission);
    }

    /// Removes a permission from the role.
    ///
    /// # Arguments
    ///
    /// * `permission` - The permission to remove.
    ///
    /// # Example
    ///
    /// ```
    /// use std::collections::HashSet;
    /// use authcraft::rbac::Role;
    ///
    /// let mut permissions = HashSet::new();
    /// permissions.insert("delete".to_string());
    ///
    /// let mut role = Role::define_role("Admin".to_string(), permissions);
    /// role.remove_permission("delete");
    ///
    /// assert!(!role.has_permission("delete"));
    /// ```
    pub fn remove_permission(&mut self, permission: &str) {
        self.permissions.remove(permission);
    }

    /// Checks if the role has all required permissions.
    ///
    /// # Arguments
    ///
    /// * `required_permissions` - A slice of required permissions.
    ///
    /// # Returns
    ///
    /// Returns `true` if the role has all required permissions, otherwise `false`.
    ///
    /// # Example
    ///
    /// ```
    /// use std::collections::HashSet;
    /// use authcraft::rbac::Role;
    ///
    /// let mut permissions = HashSet::new();
    /// permissions.insert("read".to_string());
    /// permissions.insert("write".to_string());
    ///
    /// let role = Role::define_role("User".to_string(), permissions);
    ///
    /// assert!(role.has_all_permissions(&["read".to_string(), "write".to_string()]));
    /// assert!(!role.has_all_permissions(&["read".to_string(), "delete".to_string()]));
    /// ```
    pub fn has_all_permissions(&self, required_permissions: &[String]) -> bool {
        required_permissions
            .iter()
            .all(|p| self.permissions.contains(p))
    }

    /// Checks if the role has at least one required permission.
    ///
    /// # Arguments
    ///
    /// * `required_permissions` - A slice of required permissions.
    ///
    /// # Returns
    ///
    /// Returns `true` if the role has at least one required permission, otherwise `false`.
    ///
    /// # Example
    ///
    /// ```
    /// use std::collections::HashSet;
    /// use authcraft::rbac::Role;
    ///
    /// let mut permissions = HashSet::new();
    /// permissions.insert("edit".to_string());
    ///
    /// let role = Role::define_role("Editor".to_string(), permissions);
    ///
    /// assert!(role.has_any_permission(&["view".to_string(), "edit".to_string()]));
    /// assert!(!role.has_any_permission(&["delete".to_string()]));
    /// ```
    pub fn has_any_permission(&self, required_permissions: &[String]) -> bool {
        required_permissions
            .iter()
            .any(|p| self.permissions.contains(p))
    }

    /// Merges permissions from another role.
    ///
    /// # Arguments
    ///
    /// * `other` - The role from which permissions should be merged.
    ///
    /// # Example
    ///
    /// ```
    /// use std::collections::HashSet;
    /// use authcraft::rbac::Role;
    ///
    /// let mut role1 = Role::define_role("Editor".to_string(), HashSet::from(["edit".to_string()]));
    /// let role2 = Role::define_role("Viewer".to_string(), HashSet::from(["view".to_string()]));
    ///
    /// role1.merge_permissions(&role2);
    /// assert!(role1.has_permission("view"));
    /// ```
    pub fn merge_permissions(&mut self, other: &Role) {
        self.permissions.extend(other.permissions.clone());
    }

    /// Removes all permissions from the role.
    ///
    /// # Example
    ///
    /// ```
    /// use std::collections::HashSet;
    /// use authcraft::rbac::Role;
    ///
    /// let mut role = Role::define_role("Admin".to_string(), HashSet::from(["delete".to_string()]));
    /// role.clear_permissions();
    ///
    /// assert!(role.permissions.is_empty());
    /// ```
    pub fn clear_permissions(&mut self) {
        self.permissions.clear();
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Role: {}, Permissions: {:?}",
            self.name, self.permissions
        )
    }
}
