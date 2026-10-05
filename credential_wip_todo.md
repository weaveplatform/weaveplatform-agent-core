# Credentials to create: Windows code signing (self-signed, for now)

Status: **to create.** Delete this file once both rows are ticked and a signed Windows release has shipped.

## Why
- **Core checks signatures.** Before running a Windows module, core verifies its Authenticode signature with `WinVerifyTrust` and pins the signing certificate's **SHA-1 thumbprint** from the module manifest (`signing.authenticode_thumbprint`).
- **Self-signed means installing the certificate.** With a self-signed certificate, Windows only trusts the chain if the certificate is in the guest's **Trusted Root** and **Trusted Publishers** stores. core's Windows installer adds it there. That is an install-time, out-of-band trust step; nothing is changed over the channel.
- **Later:** replace it with a CA- or Azure Trusted Signing-issued certificate. Only the secrets, the thumbprint variable and the public certificate change.

All values are set at the **organisation** level, available to `weaveplatform-agent-core` and `weaveplatform-agent-modules` (or all repositories, as the Apple ones are).

## [ ] Create the certificate (on your Mac, in an empty folder)
```
openssl req -x509 -newkey rsa:3072 -sha256 -days 1825 -nodes \
  -keyout weave-codesign.key -out weave-codesign.crt \
  -subj "/CN=weaveplatform code signing/O=weaveplatform" \
  -addext "basicConstraints=critical,CA:false" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=codeSigning"

# PFX for signing; you will be asked for an export password: choose a strong one
openssl pkcs12 -export -inkey weave-codesign.key -in weave-codesign.crt \
  -out weave-codesign.pfx -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg SHA256

# The SHA-1 thumbprint core pins (40 hex characters, no colons)
openssl x509 -in weave-codesign.crt -noout -fingerprint -sha1 | cut -d= -f2 | tr -d ':'
```

## [ ] Set the values (run these yourself; the values never pass through a browser or a chat)
```
gh auth refresh -h github.com -s admin:org     # once, if needed

base64 -i weave-codesign.pfx | gh secret set WINDOWS_CODESIGN_PFX --org weaveplatform --visibility all
gh secret set WINDOWS_CODESIGN_PFX_PASSWORD --org weaveplatform --visibility all     # prompts for the export password
gh variable set WINDOWS_CODESIGN_THUMBPRINT --org weaveplatform --visibility all --body "<40-hex thumbprint>"
base64 -i weave-codesign.crt | gh variable set WINDOWS_CODESIGN_CERT --org weaveplatform --visibility all --stdin
```
`WINDOWS_CODESIGN_CERT` is the **public** certificate. It is not secret: core's Windows installer embeds it to trust the chain, and it can also be committed.

## [ ] Afterwards
- Put `weave-codesign.pfx`, `weave-codesign.key` and the export password in the team password manager, then delete the local copies. `weave-codesign.crt` is public.
- Confirm the names (no values are shown):
  ```
  gh secret list --org weaveplatform | grep WINDOWS_
  gh variable list --org weaveplatform | grep WINDOWS_
  ```

## Rotation
Create a new certificate, update the two secrets and the two variables, and release core and the Windows modules. Each module manifest's `authenticode_thumbprint` moves to the new thumbprint in the same release.
