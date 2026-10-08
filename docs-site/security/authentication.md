# Authentication

Firewall Policy Manager supports Microsoft Entra ID, Cisco Duo Single Sign-On, and Generic OIDC through one server-side Authorization Code flow. The identity provider authenticates the person and applies its MFA policy; Firewall Policy Manager owns application authorization.

```text
OIDC issuer + subject
        ↓
Firewall Manager User
        ↓
Group memberships → selected Active Group → effective grants
```

IdP groups do not automatically become Firewall Policy Manager Groups. Login does not create Users, assign memberships, or grant firewall access automatically.

## First production sign-in

1. Register a confidential OIDC client with the exact callback URL `<APP_PUBLIC_URL>/api/v1/auth/<provider-id>/callback`.
2. Start the production stack and open its HTTPS URL.
3. In the guarded first-run screen, define the organization, initial Platform Admin, issuer, client ID, client secret, and claim mapping.
4. Complete **Test configuration** through the real provider before saving.
5. Sign out and verify the normal sign-in path before onboarding operators.

Discovery, issuer, audience, expiry, RS256 signature, state, and nonce are validated server-side. Client secrets are encrypted and write-only in the UI.

## API tokens

Administrators can issue scoped, expiring tokens for an existing User. The plaintext is returned once; only a hash is retained. Tokens inherit the User's current enabled state and grants, so revocation or authorization changes take effect without rotating provider credentials.

Use the bearer token only over HTTPS:

```http
Authorization: Bearer <token-shown-once>
```

Keep automation identities narrowly scoped, choose the shortest practical lifetime, and review issuance and revocation in Audit.
