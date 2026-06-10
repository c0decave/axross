# OAuth App Registration Guide

Axross supports cloud storage services that require OAuth2 authentication.
You need to register your own app with each provider to get Client IDs/Secrets.

## Google Drive

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project (or select existing)
3. Enable the **Google Drive API**:
   - Navigate to *APIs & Services > Library*
   - Search for "Google Drive API" and click **Enable**
4. Create OAuth credentials:
   - Go to *APIs & Services > Credentials*
   - Click **Create Credentials > OAuth client ID**
   - Application type: **Desktop app**
   - Name: `Axross` (or any name)
   - Click **Create**
5. Copy the **Client ID** and **Client Secret**
6. Configure the OAuth consent screen:
   - Go to *APIs & Services > OAuth consent screen*
   - User type: **External** (or Internal for Workspace)
   - Fill in app name, support email
   - Add scope: `https://www.googleapis.com/auth/drive`
   - Add your email as a test user (while in "Testing" status)

Enter the Client ID and Client Secret in the Axross connection dialog.

## Microsoft OneDrive / SharePoint

1. Go to [Azure Portal - App registrations](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade)
2. Click **New registration**
   - Name: `Axross`
   - Supported account types: **Accounts in any organizational directory and personal Microsoft accounts**
   - Redirect URI: **Public client/native (mobile & desktop)** → `http://localhost`
3. After creation, note the **Application (client) ID**
4. Set the **Tenant ID**:
   - For personal OneDrive: use `common`
   - For organization-only: use your Azure AD tenant ID
5. Configure API permissions:
   - Go to *API permissions > Add a permission > Microsoft Graph*
   - Delegated permissions:
     - `Files.ReadWrite.All`
     - `User.Read`
     - For SharePoint also add: `Sites.ReadWrite.All`
   - Click **Grant admin consent** (if you have admin rights)
6. Under *Authentication*:
   - Ensure **Allow public client flows** is set to **Yes**

Enter the Client ID and Tenant ID in the Axross connection dialog.
For SharePoint, also enter the Site URL (e.g. `https://company.sharepoint.com/sites/MySite`).

## Dropbox

1. Go to [Dropbox App Console](https://www.dropbox.com/developers/apps)
2. Click **Create app**
   - Choose **Scoped access**
   - Choose **Full Dropbox** access type
   - Name: `Axross` (must be unique)
3. In the app settings:
   - Note the **App key** and **App secret**
4. Under *Permissions* tab, enable:
   - `files.metadata.read`
   - `files.metadata.write`
   - `files.content.read`
   - `files.content.write`
   - `account_info.read`
5. Click **Submit** to save permissions

Enter the App Key and App Secret in the Axross connection dialog.

## Token Storage

OAuth tokens are cached locally at:
- Google Drive: `~/.config/axross/gdrive_token.json`
- OneDrive/SharePoint: `~/.config/axross/onedrive_token.json`
- Dropbox: `~/.config/axross/dropbox_token.json`

Tokens are automatically refreshed when they expire. Delete the token file to force re-authentication.

## Security Notes

- **Client IDs** (and Dropbox App Keys) live in your profile file at
  `~/.config/axross/profiles.json`. These are not secret on their own —
  Google / Microsoft / Dropbox treat them as public identifiers for the
  registered app. The profiles file is still written with `0o600`
  permissions via `tempfile.mkstemp` followed by `os.replace`, so only
  your user account can read it.
- **Client Secrets** (Google's `client_secret`, Dropbox's `app_secret`)
  plus Azure SAS tokens and Azure connection strings are **never** stored
  in the profiles file. They go to the OS keyring (GNOME Keyring / KDE
  Wallet / macOS Keychain / Windows Credential Manager) via the
  `SENSITIVE_PROFILE_FIELDS` mechanism in `core/profiles.py`. If no
  desktop keyring is available, axross logs a warning and does NOT
  persist them — you re-enter on next launch rather than risk a plaintext
  leak.
- **OAuth refresh tokens** are written atomically to
  `~/.config/axross/*_token.json` with `0o600` via
  `core.secure_storage.write_secret_file`. The file is 0o600 from birth
  (`fchmod` on the temp fd before the rename) — no TOCTOU window where
  a world-readable version exists.
- **What to protect from yourself and others:** the token files under
  `~/.config/axross/` and your OS keyring entries. Losing those → drop
  the file and re-auth. Leaking them → revoke the OAuth app's access in
  the provider's console immediately and regenerate.
