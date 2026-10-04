# Credentials to create: Apple signing and notarisation

Status: **placeholders exist, values still to be created and set.** Delete this file once every row below is ticked and a signed, notarised release has shipped.

## Why these are needed
- **Core verifies modules.** weave-agent accepts a macOS module only if its binary is signed by the weaveplatform Developer ID team named in the module manifest (`signing.apple_team_id`).
- **Gatekeeper checks user-session modules.** It refuses unnotarised binaries launched into a user's session, such as the clipboard module.
- **Installers should be signed too.** `.pkg` installers should be signed and notarised so they install without warnings.

Every value below is set **at the organisation level**, scoped to **selected repositories**: `weaveplatform-agent-core` and `weaveplatform-agent-modules`.

- Variables: https://github.com/organizations/weaveplatform/settings/variables/actions
- Secrets: https://github.com/organizations/weaveplatform/settings/secrets/actions

The terminal commands assume:
```
REPOS=weaveplatform-agent-core,weaveplatform-agent-modules
gh auth refresh -h github.com -s admin:org   # once, so gh may manage org secrets
```
Run them yourself in a terminal so values never pass through a browser or a chat.

**Only the Account Holder** of the Apple Developer account can create Developer ID certificates and request App Store Connect API access.

---

## [ ] `APPLE_TEAM_ID` (variable)
1. Sign in at https://developer.apple.com/account.
2. Under **Membership details**, copy **Team ID** (10 characters).
3. Set it:
   ```
   gh variable set APPLE_TEAM_ID --org weaveplatform --repos $REPOS --body "<TEAM ID>"
   ```

## [ ] `APPLE_DEVELOPER_ID_APP_P12` (secret)
This is the Developer ID **Application** certificate plus its private key. It signs every macOS binary: core's `weaveboot`, `weave-agent`, `weavectl`, `weavemanifest` and every `weave-macos-*` module.

1. **Create it:**
   - Xcode → **Settings… → Accounts** → select the team → **Manage Certificates…** → **+** → **Developer ID Application**.
   - Or use the portal: in Keychain Access choose **Certificate Assistant → Request a Certificate From a Certificate Authority…** and save the CSR to disk. Then at https://developer.apple.com/account/resources/certificates/add choose **Developer ID Application**, then **G2 Sub-CA**, upload the CSR, download the `.cer` and double-click it.
2. **Export it:**
   - In Keychain Access (login → **My Certificates**), find **Developer ID Application: … (TEAMID)** and expand it. A private key must be listed underneath.
   - Right-click the certificate → **Export…** → **.p12** → save as `developer-id-application.p12`, with a strong password. That password is the next secret.
3. **Check it:** `security find-identity -v -p codesigning | grep "Developer ID Application"`.
4. **Set it:**
   ```
   base64 -i developer-id-application.p12 | gh secret set APPLE_DEVELOPER_ID_APP_P12 --org weaveplatform --repos $REPOS
   ```

## [ ] `APPLE_DEVELOPER_ID_APP_P12_PASSWORD` (secret)
The export password chosen for `developer-id-application.p12`.
```
gh secret set APPLE_DEVELOPER_ID_APP_P12_PASSWORD --org weaveplatform --repos $REPOS   # prompts for the value
```

## [ ] `APPLE_DEVELOPER_ID_INSTALLER_P12` (secret)
This is the Developer ID **Installer** certificate plus its private key. It signs `.pkg` installers: core's package and every module package.

1. **Create it:** Xcode → **Manage Certificates…** → **+** → **Developer ID Installer**. Or use the portal as above, choosing **Developer ID Installer** (the same CSR works).
2. **Export it:** in Keychain Access, find **Developer ID Installer: … (TEAMID)**, which must have its private key. **Export…** → **.p12** → `developer-id-installer.p12`, with its own strong password.
3. **Check it:** `security find-certificate -c "Developer ID Installer" -Z | head -3`.
4. **Set it:**
   ```
   base64 -i developer-id-installer.p12 | gh secret set APPLE_DEVELOPER_ID_INSTALLER_P12 --org weaveplatform --repos $REPOS
   ```

## [ ] `APPLE_DEVELOPER_ID_INSTALLER_P12_PASSWORD` (secret)
The export password chosen for `developer-id-installer.p12`.
```
gh secret set APPLE_DEVELOPER_ID_INSTALLER_P12_PASSWORD --org weaveplatform --repos $REPOS
```

## [ ] `APPLE_NOTARY_KEY_P8` (secret)
The App Store Connect API key used by `xcrun notarytool`.

1. **Open Team Keys:** https://appstoreconnect.apple.com → **Users and Access** → **Integrations** → **App Store Connect API** → **Team Keys**. The first time, the Account Holder clicks **Request Access** and accepts.
2. **Generate the key:** click **+**. Name it `weave-notary`, set Access to **Developer**, and click **Generate**.
3. **Download it:** click **Download** to get `AuthKey_<KEYID>.p8`. **It can only be downloaded once.**
4. **Set it:**
   ```
   base64 -i AuthKey_<KEYID>.p8 | gh secret set APPLE_NOTARY_KEY_P8 --org weaveplatform --repos $REPOS
   ```

## [ ] `APPLE_NOTARY_KEY_ID` (secret)
The **Key ID** column for `weave-notary` on the Team Keys page.
```
gh secret set APPLE_NOTARY_KEY_ID --org weaveplatform --repos $REPOS --body "<KEYID>"
```

## [ ] `APPLE_NOTARY_ISSUER_ID` (secret)
The **Issuer ID** shown above the Team Keys table.
```
gh secret set APPLE_NOTARY_ISSUER_ID --org weaveplatform --repos $REPOS --body "<ISSUER ID>"
```
Check the key before or after setting it (the history should be empty, not an authentication error):
```
xcrun notarytool history --key AuthKey_<KEYID>.p8 --key-id <KEYID> --issuer <ISSUER ID>
```

---

## [ ] Afterwards
- Store both `.p12` files, the `.p8` and both passwords in the team password manager. Delete the local copies from Downloads and the working folder. The certificates may stay in the login keychain for local signing.
- Confirm the names and their repository access, which shows no values:
  ```
  gh variable list --org weaveplatform | grep APPLE_
  gh secret list --org weaveplatform | grep APPLE_
  ```
- Then the engineering sequence follows:
  1. core's release signs and notarises its binaries and `.pkg`;
  2. every `weave-macos-*` manifest gains `signing.apple_team_id`, and module releases sign and notarise their binaries and packages;
  3. release core, then the macOS modules, then merge the channel promotion;
  4. a macOS guest installs only release packages, and core and Gatekeeper accept every module.

## Rotation
Developer ID certificates last five years. To rotate, create new certificates, update the four `.p12` secrets and release. Earlier releases keep verifying because they are timestamped. To rotate the notary key, generate a new Team Key, update the three `APPLE_NOTARY_*` secrets, and revoke the old key in App Store Connect.
