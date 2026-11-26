# Standard protection

The policy Heimdall gives every AI tool it finds on a computer (Claude Desktop, Claude Code, Cursor, Windsurf, VS Code and
their MCP tool servers). The same rules are applied on the computer itself when the Heimdall service can't be reached, so a
tool is held to the same lines either way. Source: `src/shared/standard-policy.ts`.

| | What | Examples |
|---|---|---|
| **Never** | Saved passwords, keys, browser logins, wallets | `~/.ssh/*`, `.aws`, Chrome/Edge `Login Data`, Windows Credential Manager, `wallet.dat`, KeePass |
| **Never** | Switching Heimdall off | editing `~/.claude/settings.json`, `claude_desktop_config.json`, Cursor/VS Code MCP settings, Heimdall's own folder |
| **Never** | Changing system folders and start-up | `C:\Windows`, `Program Files`, the Startup folder, `/etc` |
| **Never** | Wrecking the computer or hiding activity | `format`, `diskpart`, `bcdedit`, `vssadmin delete shadows`, `wevtutil cl`, turning off Defender or the firewall |
| **Never** | Downloaded or hidden scripts | `iwr … \| iex`, `curl … \| sh`, `powershell -enc …`, `certutil -urlcache` |
| **Ask first** | Deleting anything | `rm`, `del`, `Remove-Item`, `git reset --hard`, `DROP TABLE`, MCP `delete_*` tools |
| **Ask first** | Sending data out | uploads, `curl -X POST`, email/Slack tools, `git push`, `npm publish` |
| **Ask first** | Secret files in projects | `.env`, `*.pem`, `*.key`, `.npmrc`, `credentials.json` |
| **Ask first** | System changes | `reg`, `schtasks`, `sc`, `net user`, `netsh`, `icacls`, installers, running as administrator |
| **At once** | Ordinary work | reading and editing project files, `npm`, `git status`, `python`, builds and tests |

Commands are looked at the way the computer will run them: `powershell -Command "…"`, `cmd /c …` and `bash -c '…'` are
unwrapped, and a command that touches a protected file (for example `type %USERPROFILE%\.ssh\id_rsa`) is checked as that file.
File rules ignore letter case, as Windows does.

Organizations that still had the first automatic policy (which allowed nearly everything) are moved to Standard protection
when the server starts; the old version stays in the policy's history. A policy someone edited is never changed.

## It only works where the Heimdall app is running

Heimdall can only stop what is routed through it. On each computer the Heimdall app (companion) must be running: it sets the AI
tools up to ask Heimdall first, and answers them. Start everything with `START-HEIMDALL.bat`, click **Add** when the
computer's code appears in the dashboard, and restart Claude Desktop / Cursor once. The Overview page says plainly whether any
computer is protecting its AI tools. Programs that are not AI tools, and AI tools Heimdall cannot sit in front of, are listed
but not controlled (see KNOWN-LIMITATIONS.md).
