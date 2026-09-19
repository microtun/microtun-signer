use std::sync::Arc;

use thiserror::Error;

use crate::{
    auth::AuthPrincipal,
    config::{PolicyAction, PolicyConfig},
};

#[derive(Clone)]
pub struct Authorizer {
    policies: Arc<Vec<PolicyConfig>>,
}

#[derive(Debug, Error)]
pub enum AuthorizationError {
    #[error("identity policy does not allow this operation on this key")]
    PolicyDenied,
}

impl Authorizer {
    pub fn new(policies: Vec<PolicyConfig>) -> Self {
        Self {
            policies: Arc::new(policies),
        }
    }

    pub fn authorize(
        &self,
        principal: &AuthPrincipal,
        action: PolicyAction,
        key_id: &str,
    ) -> Result<(), AuthorizationError> {
        let allowed = self.policies.iter().any(|policy| {
            policy.identity == principal.identity_id
                && policy.actions.contains(&action)
                && policy.keys.iter().any(|key| key == "*" || key == key_id)
        });

        if allowed {
            Ok(())
        } else {
            Err(AuthorizationError::PolicyDenied)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthSource, GithubAccountIdentity};

    fn account_principal() -> AuthPrincipal {
        AuthPrincipal {
            identity_id: "maintainer".into(),
            principal_key: "github-account:42".into(),
            auth_method: "github-oauth-session",
            issuer: "issuer".into(),
            audience: None,
            subject: "42".into(),
            jti: None,
            source: AuthSource::GithubAccount(GithubAccountIdentity {
                user_id: "42".into(),
                login: "octocat".into(),
            }),
        }
    }

    #[test]
    fn policy_is_scoped_to_identity_and_key() {
        let authorizer = Authorizer::new(vec![PolicyConfig {
            identity: "maintainer".into(),
            actions: vec![PolicyAction::Sign],
            keys: vec!["key-a".into()],
        }]);
        let principal = account_principal();

        assert!(
            authorizer
                .authorize(&principal, PolicyAction::Sign, "key-a")
                .is_ok()
        );
        assert!(
            authorizer
                .authorize(&principal, PolicyAction::Sign, "key-b")
                .is_err()
        );
    }

    #[test]
    fn wildcard_key_policy_is_supported() {
        let authorizer = Authorizer::new(vec![PolicyConfig {
            identity: "maintainer".into(),
            actions: vec![PolicyAction::Sign],
            keys: vec!["*".into()],
        }]);
        assert!(
            authorizer
                .authorize(&account_principal(), PolicyAction::Sign, "any-key")
                .is_ok()
        );
    }
}
