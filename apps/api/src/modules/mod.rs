pub mod authenticators;
pub mod authorization;
pub mod budget;
pub mod catalog;
pub mod credentials;
pub mod devices;
pub mod identity;
pub mod inference;
pub mod memberships;
pub mod organizations;
pub mod outbox;
pub mod policy;
pub mod policy_p04;
pub mod projects;
pub mod routing;
pub mod teams;

#[cfg(test)]
mod p04_domain_tests;
