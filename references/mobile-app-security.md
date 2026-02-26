# Mobile App Security Reference

## Table of Contents
- [Hardcoded Secrets](#hardcoded-secrets)
- [Certificate Pinning](#certificate-pinning)
- [Secure Storage](#secure-storage)
- [Deep Link Validation](#deep-link-validation)
- [Biometric Authentication](#biometric-authentication)
- [Transport Security](#transport-security)
- [Expo / React Native Specific](#expo--react-native-specific)
- [Build & Distribution](#build--distribution)

---

## Hardcoded Secrets

### Scan for Secrets in Source

```bash
# API keys, tokens, passwords in source files
grep -rn 'api[_-]?key\|apiKey\|secret\|password\|token' \
  --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  --include='*.swift' --include='*.kt' --include='*.java' \
  src/ app/ | grep -v 'node_modules\|\.test\.\|process\.env\|Config\.\|__tests__'

# AWS keys
grep -rn 'AKIA[0-9A-Z]\{16\}' --include='*.ts' --include='*.js' --include='*.swift' --include='*.kt' .

# Private keys
grep -rn 'BEGIN.*PRIVATE KEY\|BEGIN RSA' --include='*.ts' --include='*.js' --include='*.pem' .

# Base64-encoded secrets (long base64 strings assigned to variables)
grep -rn '[A-Za-z_]*[Ss]ecret\|[A-Za-z_]*[Kk]ey.*=.*[A-Za-z0-9+/]\{40,\}' \
  --include='*.ts' --include='*.js' src/

# Check app.json / app.config.js for secrets
grep -n 'key\|secret\|token\|password' app.json app.config.js app.config.ts 2>/dev/null
```

**Severity:** CRITICAL  

**Mobile-specific risk:** Unlike web apps, mobile app binaries can be decompiled. Any secret in source code will be extracted.

**Remediation:**
- Use environment variables loaded at build time
- Store runtime secrets in secure storage (see below)
- Use a secrets management service for sensitive config

---

## Certificate Pinning

### Check for SSL Pinning Implementation

```bash
# React Native — TrustKit or react-native-ssl-pinning
grep -rn 'ssl-pinning\|TrustKit\|certificate-pinning\|pinning' package.json
grep -rn 'sslPinning\|pinSSLCert\|certPin' --include='*.ts' --include='*.js' src/

# iOS — Info.plist TrustKit config or NSAppTransportSecurity
grep -rn 'TSKPinnedDomains\|TSKPublicKeyHashes' ios/ 2>/dev/null

# Android — network_security_config.xml
find android/ -name 'network_security_config.xml' 2>/dev/null
grep -rn 'pin-set\|pin digest' android/ 2>/dev/null
```

**Severity:** WARNING for production apps handling sensitive data  

**When to pin:**
- Apps handling financial data, health data, or PII
- Apps communicating with known backend servers
- NOT recommended for apps using many third-party APIs (pins break on cert rotation)

**Implementation options:**
- React Native: `react-native-ssl-pinning` or `rn-fetch-blob` with pinning
- iOS native: TrustKit framework
- Android native: Network Security Config XML

---

## Secure Storage

### Scan for Insecure Storage

```bash
# AsyncStorage for sensitive data (React Native)
grep -rn 'AsyncStorage.*token\|AsyncStorage.*secret\|AsyncStorage.*password\|AsyncStorage.*key' \
  --include='*.ts' --include='*.tsx' --include='*.js' src/

# General AsyncStorage usage (review what's stored)
grep -rn 'AsyncStorage\.setItem\|AsyncStorage\.getItem' --include='*.ts' --include='*.tsx' src/

# Check for expo-secure-store usage (GOOD)
grep -rn 'SecureStore\|expo-secure-store' --include='*.ts' --include='*.tsx' src/

# Check for react-native-keychain (GOOD)
grep -rn 'Keychain\|react-native-keychain' --include='*.ts' --include='*.tsx' src/

# Check for MMKV (needs encryption for sensitive data)
grep -rn 'MMKV' --include='*.ts' --include='*.tsx' src/
```

**Severity:** CRITICAL if tokens/secrets in AsyncStorage  

**Storage comparison:**

| Method | Platform | Encrypted | Use For |
|--------|----------|-----------|---------|
| `AsyncStorage` | RN | ❌ No | Non-sensitive preferences |
| `expo-secure-store` | Expo | ✅ Keychain/Keystore | Tokens, secrets |
| `react-native-keychain` | RN | ✅ Keychain/Keystore | Tokens, credentials |
| `MMKV` (encrypted) | RN | ✅ Optional | Fast key-value + secrets |
| `@react-native-async-storage/async-storage` | RN | ❌ No | Non-sensitive data only |

**Correct pattern (Expo):**
```typescript
import * as SecureStore from 'expo-secure-store';

// Store token securely
await SecureStore.setItemAsync('auth_token', token);

// Retrieve
const token = await SecureStore.getItemAsync('auth_token');
```

---

## Deep Link Validation

### Scan for Deep Link Configuration

```bash
# Expo deep linking config
grep -rn 'linking\|deepLink\|scheme' app.json app.config.js app.config.ts 2>/dev/null
grep -rn 'expo-linking\|Linking\.' --include='*.ts' --include='*.tsx' src/

# React Navigation deep link config
grep -rn 'linking.*config\|prefixes\|screens.*path' --include='*.ts' --include='*.tsx' src/

# Universal links / App Links
find ios/ -name '*.entitlements' -exec grep -l 'applinks' {} \; 2>/dev/null
find android/ -name 'AndroidManifest.xml' -exec grep -A3 'intent-filter.*VIEW' {} \; 2>/dev/null
```

**Severity:** WARNING  

**Vulnerabilities:**
- Deep links that auto-navigate to authenticated screens without re-validating auth
- Deep links that pass tokens or sensitive data as parameters
- Missing domain verification for universal links / app links

**Checklist:**
1. Validate all deep link parameters before use
2. Don't pass auth tokens via deep links
3. Re-check authentication state when handling deep links
4. Configure associated domains properly (iOS) / asset links (Android)

---

## Biometric Authentication

### Scan for Biometric Implementation

```bash
# Expo local authentication
grep -rn 'expo-local-authentication\|LocalAuthentication' --include='*.ts' --include='*.tsx' src/

# React Native biometrics
grep -rn 'react-native-biometrics\|TouchID\|FaceID\|BiometryType' --include='*.ts' --include='*.tsx' src/

# Check for fallback to PIN/password
grep -rn 'fallback\|passcode\|deviceCredentials' --include='*.ts' --include='*.tsx' src/
```

**Severity:** INFO  

**Implementation checklist:**
- [ ] Biometric auth protects access to secure storage, not just UI
- [ ] Has a fallback mechanism (device PIN/password)
- [ ] Doesn't store biometric data (use system APIs only)
- [ ] Re-authenticates for sensitive operations (transfers, password changes)
- [ ] Handles biometric enrollment changes (new fingerprint added)

---

## Transport Security

### iOS App Transport Security (ATS)

```bash
# Check Info.plist for ATS exceptions
find ios/ -name 'Info.plist' -exec grep -A5 'NSAppTransportSecurity\|NSAllowsArbitraryLoads' {} \; 2>/dev/null

# Expo app.json ATS config
grep -A10 'NSAppTransportSecurity\|ios.*infoPlist' app.json app.config.js 2>/dev/null
```

**Severity:** WARNING if `NSAllowsArbitraryLoads = true`  

**What to check:**
- `NSAllowsArbitraryLoads` should be `false` in production
- Only whitelist specific domains with `NSExceptionDomains` if absolutely necessary
- Each exception should have a documented reason

### Android Network Security Config

```bash
# Find network security config
find android/ -name 'network_security_config.xml' 2>/dev/null
cat android/app/src/main/res/xml/network_security_config.xml 2>/dev/null

# Check if cleartext traffic is allowed
grep -rn 'cleartextTrafficPermitted\|usesCleartextTraffic' android/ 2>/dev/null
```

**Severity:** WARNING if cleartext traffic permitted  

**Correct config (Android):**
```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    <!-- Only allow cleartext for local dev if needed -->
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">10.0.2.2</domain>
        <domain includeSubdomains="true">localhost</domain>
    </domain-config>
</network-security-config>
```

---

## Expo / React Native Specific

### OTA Update Security

```bash
# Check for expo-updates config
grep -rn 'expo-updates\|updates' app.json app.config.js app.config.ts 2>/dev/null

# Check if code signing is enabled for updates
grep -rn 'codeSigningCertificate\|codeSigningMetadata' app.json app.config.js 2>/dev/null

# Check update URL (should be HTTPS)
grep -rn 'url.*updates\|updateUrl' app.json app.config.js 2>/dev/null
```

**Severity:** WARNING if OTA updates enabled without code signing  

**Risks:**
- Man-in-the-middle could inject malicious updates
- Update server compromise could push malicious code to all users

**Mitigations:**
- Enable code signing for EAS Updates
- Pin the update server certificate
- Use HTTPS for update URLs

### Expo Secure Store Usage

```bash
# Check if sensitive data uses SecureStore vs AsyncStorage
grep -rn 'AsyncStorage' --include='*.ts' --include='*.tsx' src/ | \
  grep -i 'token\|auth\|secret\|password\|key\|credential'

# Verify SecureStore is used for auth
grep -rn 'SecureStore' --include='*.ts' --include='*.tsx' src/
```

### Expo Config Plugin Security

```bash
# Check for dangerous permissions
grep -rn 'permissions\|android\.permissions' app.json app.config.js 2>/dev/null

# Review custom native modules
grep -rn 'expo-modules-core\|requireNativeModule' --include='*.ts' src/
```

**Checklist:**
- [ ] Only request permissions actually needed
- [ ] Handle permission denial gracefully
- [ ] Don't request permissions at app launch (request in context)

---

## Build & Distribution

### Pre-Release Security Checklist

```bash
# Debug mode / dev flags
grep -rn '__DEV__\|DEBUG\|console\.log' --include='*.ts' --include='*.tsx' src/ | grep -v 'node_modules' | head -20

# Check for test/staging API URLs
grep -rn 'staging\|localhost\|127\.0\.0\.1\|\.local' --include='*.ts' --include='*.tsx' --include='*.env' src/

# Source maps in production
grep -rn 'sourceMap\|devtool.*source' webpack.config.* metro.config.* babel.config.* 2>/dev/null

# Expo publishedUrl check
grep -rn 'EXPO_PUBLIC_API_URL\|API_URL' .env .env.production 2>/dev/null
```

**Items to verify before release:**
- [ ] Debug logging removed or gated behind `__DEV__`
- [ ] Production API URLs configured
- [ ] Source maps not included in production builds (or uploaded to error service only)
- [ ] App signing keys secured and backed up
- [ ] ProGuard / R8 obfuscation enabled (Android)
- [ ] Hermes bytecode enabled (React Native — harder to reverse-engineer)
