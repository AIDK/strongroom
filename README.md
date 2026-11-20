# Strongroom

A small, local-only password manager for keeping work credentials. It runs on your own machine at
`http://localhost:5245` (or `:47245` when installed as a service), stores everything encrypted in a SQLite file, and supports more than one user,
each with their own master password and vault.

> **Status:** the core features (capture, edit, delete, search, change master password) are done.
> This project has not had an independent security review.
>
> For how the pieces fit together (web app, Windows Service, deployment), see the
> [project overview](docs/PROJECT-OVERVIEW.md).

## Run it

Requires the [.NET 10 SDK](https://dotnet.microsoft.com/download).

```bash
dotnet run --project src/Strongroom.Web
```

Open <http://localhost:5245>, choose **Create a new account**, and pick a username and a master password
(at least 12 characters). **If you forget the master password, the vault cannot be recovered.**

Run the tests:

```bash
dotnet test
```

## Run it as a Windows Service (starts with Windows)

So you don't have to run `dotnet run` each time. From an **elevated** PowerShell in the repo root:

```powershell
powershell -ExecutionPolicy Bypass -File .\deploy\install.ps1 -ImportVault
```

This publishes a Release build to `C:\Apps\Strongroom`, installs a service called **Strongroom** that runs as the
low-privilege `LocalService` account and starts automatically, and checks that it answers on
<http://localhost:47245>. Then just open that address in your browser.

- **Your database:** the service uses `C:\ProgramData\Strongroom\strongroom.db` (outside the program folder, so
  updates never touch it). `-ImportVault` copies the vault you used with `dotnet run` (`data\strongroom.db`) there on
  first install; it refuses to overwrite a database that already exists. Choose a different location with
  `-DatabasePath "D:\somewhere\strongroom.db"` (a file path, not a folder).
- **Updating:** run the same script again after changing the code. It stops the service, replaces the program
  files, and starts it again. Your database and machine settings (`appsettings.Production.json`) are kept.
- **Port:** the service listens on **47245** (chosen to stay clear of ports used by .NET templates and common dev
  tools); `dotnet run` keeps using 5245, so both can run at the same time. To change the service's port, re-run the
  install script with `-Port <number>`; later runs keep whatever port is already set. The port is stored in
  `C:\Apps\Strongroom\appsettings.Production.json`. If the port is taken when you install or update, the script stops
  with a message naming the program that is using it.
- **Two vaults:** the `dotnet run` copy uses `data\strongroom.db` and the service uses its own database, so they hold
  different vaults. Use one or the other day to day. Browser cookies don't separate by port, so if you have both open
  you may be asked to unlock again when switching between them.
- **Logs:** Event Viewer > Windows Logs > Application (source "Strongroom"). The service restarts itself if it crashes.
- **Removing it:** `powershell -ExecutionPolicy Bypass -File .\deploy\uninstall.ps1` removes the service and never
  deletes your database. Add `-RemoveFiles` to also delete `C:\Apps\Strongroom`.

## Where your data lives

When run with `dotnet run`, the vault is `data/strongroom.db` in the repository root (`data/` is gitignored; never commit it).
When installed as a service it is `C:\ProgramData\Strongroom\strongroom.db` (see above).

To use a different location, set `Strongroom:DatabasePath` in `src/Strongroom.Web/appsettings.json` to a full
path **to the file** (not a folder), for example `"C:\\Vaults\\strongroom.db"`. Leave it empty for the default.

Changing the path does **not** move an existing vault. Stop the app and copy the old `strongroom.db` to the
new location first; otherwise the app starts with a new, empty database there.

You can also override it with an environment variable (`Strongroom__DatabasePath`) or a command-line
argument (`--Strongroom:DatabasePath=...`), which is handy for testing against a throwaway database.

## How it protects your data

| Piece | Design |
|---|---|
| Master password | Stretched with **Argon2id** (64 MiB, 3 passes, 2 lanes) using a random per-user salt. Never stored. |
| Vault key | A random 256-bit key, stored only **wrapped** (AES-256-GCM) by the key from your master password. A wrong password fails the authentication check, so no password hash exists. |
| Credentials | Each credential (name, URL, username, password, category, notes) is one **AES-256-GCM** blob under the vault key, bound to its owner and record id so blobs can't be swapped in the database. |
| Changing the master password | Only the vault key is re-wrapped under the new password; credentials are not re-encrypted. Other open sessions are locked. |
| Sessions | The unlocked key lives only in server memory and is wiped on lock, after 5 minutes idle, or when the app exits. The session cookie is HttpOnly and SameSite=Strict. |
| Network | Binds to localhost only and rejects requests for any other host name (DNS-rebinding protection). State-changing requests need a custom header (CSRF protection). Strict CSP and security headers. |
| Guessing | After 5 wrong passwords a username is locked out for 1, 2, 4... up to 15 minutes. This also applies to the change-password prompt. |

Known trade-offs:

- Anyone who can reach localhost can deliberately trigger the lockout for a username.
- Search runs in the browser on decrypted data, because the server only ever stores ciphertext.
- Decrypted values exist in server memory while a session is unlocked, and in the page while the vault is open.

## Project layout

```
src/Strongroom.Core/   Crypto (VaultCrypto), SQLite storage (VaultStore), VaultService / UnlockedVault
src/Strongroom.Web/    ASP.NET Core minimal API (Program.cs), sessions, login throttling, wwwroot/ UI
tests/Strongroom.Tests xUnit tests for the crypto and vault logic
deploy/                install.ps1 / uninstall.ps1 for the Windows Service
data/                  The vault database when run with dotnet run (gitignored)
```

The UI is plain HTML, CSS and JavaScript with no build step and no external requests.

## API (all under `/api`)

| Method and path | Purpose |
|---|---|
| `GET /status` | Is there an unlocked session? |
| `POST /register`, `POST /login`, `POST /logout` | Create an account, unlock, lock |
| `POST /account/change-password` | Change the master password (needs the current one) |
| `GET/POST /credentials`, `PUT/DELETE /credentials/{id}` | Manage credentials (unlocked session required) |

Non-GET requests must send the header `X-Strongroom: 1`.
