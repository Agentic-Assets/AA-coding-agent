# Crypto Module

## Domain Purpose
Application secret encryption/decryption for database-backed secrets: OAuth tokens, API keys, and MCP credentials.

## Module Boundaries
- **Owns**: Symmetric encryption/decryption for app data
- **Note**: Different from `lib/jwe/` (which uses JWE for session tokens)

## Local Patterns
- **Primary algorithm**: AES-256-GCM for new encryptions
- **Backward compatibility**: decrypt supports legacy AES-256-CBC payloads
- **IV**: Random nonce per encryption; format varies by version
- **Format**: Versioned, parseable encrypted payload string
- **Key Format**: 32-byte hex string (NOT base64url like JWE_SECRET); 64 hex characters
- **Encryption**: Random IV generated per call, preventing pattern reuse

## Integration Points
- `lib/db/schema.ts` - OAuth tokens (users.accessToken), API keys (keys.value)
- `lib/sandbox/agents/claude.ts` - Decrypt user API keys before setting env vars
- `app/api/api-keys/` - Encrypt/decrypt user API keys
- `app/api/connectors/` - MCP server env vars encrypted

## Key Functions
- `encrypt(plaintext)` - Returns encrypted payload string for DB storage
- `decrypt(encrypted)` - Returns plaintext or `null` on failure
