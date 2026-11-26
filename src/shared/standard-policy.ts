/**
 * The policy Heimdall applies to AI tools it finds on a computer ("Standard protection"), and decides with locally when the
 * Heimdall service can't be reached. Used by the server (automatic policy) and by the companion (offline fallback), so a tool
 * is held to the same lines whether or not Heimdall is online.
 *
 * Order of evaluation (see policy.ts): deny rules first, then approval rules, then allow rules.
 *   Never:      reading saved passwords, keys and wallets; changing Heimdall's own settings or an AI tool's protection settings;
 *               changing Windows / system folders or start-up locations; wiping disks, boot settings, backups and logs;
 *               turning off antivirus; running scripts downloaded straight from the internet or hidden (encoded) commands.
 *   Ask first:  deleting anything; sending data out of the computer; reading .env and key files; changing user accounts,
 *               the registry, scheduled tasks, services, firewall and file permissions; running as administrator.
 *   At once:    ordinary reading, writing and commands in your projects.
 */
import type { PolicyDocument } from "./policy.js";

const SECRET_STORES = [
  "files/**/.ssh/**", "files/**/.aws/**", "files/**/.azure/**", "files/**/.gnupg/**", "files/**/.kube/config", "files/**/.docker/config.json",
  "files/**/.git-credentials", "files/**/.netrc", "files/**/_netrc", "files/**/.config/gcloud/**", "files/**/.config/gh/hosts.yml",
  "files/**/AppData/Local/Google/Chrome/User Data/**", "files/**/AppData/Local/Microsoft/Edge/User Data/**",
  "files/**/AppData/Local/BraveSoftware/**", "files/**/AppData/Roaming/Opera Software/**", "files/**/AppData/Roaming/Mozilla/Firefox/Profiles/**",
  "files/**/AppData/Roaming/Microsoft/Credentials/**", "files/**/AppData/Local/Microsoft/Credentials/**", "files/**/AppData/Roaming/Microsoft/Protect/**",
  "files/**/AppData/Roaming/Microsoft/Vault/**", "files/**/AppData/Local/Microsoft/Vault/**",
  "files/**/Library/Keychains/**", "files/**/.local/share/keyrings/**", "files/**/.password-store/**",
  "files/**/wallet.dat", "files/**/AppData/Roaming/Bitcoin/**", "files/**/AppData/Roaming/Ethereum/keystore/**", "files/**/AppData/Roaming/Exodus/**",
  "files/**/AppData/Roaming/Electrum/**", "files/**/AppData/Local/Packages/*WhatsApp*/**", "files/**/AppData/Roaming/Telegram Desktop/tdata/**",
  "files/**/*.kdbx", "files/**/AppData/Roaming/KeePass/**", "files/**/AppData/Local/1Password/**", "files/**/AppData/Roaming/Bitwarden/**",
  "files/Windows/System32/config/**", "files/C/Windows/System32/config/**", "files/etc/shadow", "files/etc/sudoers",
];

/** Heimdall itself and the settings that route AI tools through it: an AI must not be able to switch its own guard off. */
const PROTECTION_SETTINGS = [
  "files/**/.claude/settings.json", "files/**/.claude/settings.local.json", "files/**/AppData/Roaming/Claude/claude_desktop_config.json",
  "files/**/Library/Application Support/Claude/claude_desktop_config.json", "files/**/.config/Claude/claude_desktop_config.json",
  "files/**/.cursor/mcp.json", "files/**/.codeium/windsurf/mcp_config.json", "files/**/AppData/Roaming/Code/User/mcp.json",
  "files/**/AppData/Roaming/Code/User/settings.json", "files/**/.vscode/mcp.json",
  "files/**/AppData/Local/KenuxaHeimdall/**", "files/**/.kenuxa-heimdall/**", "files/**/*.heimdall-backup",
  "files/**/AI Security Guardian/.env", "files/**/AI Security Guardian/.env.local", "files/**/AI Security Guardian/.data/**",
];

const SYSTEM_AREAS = [
  "files/C/Windows/**", "files/C/Program Files/**", "files/C/Program Files (x86)/**", "files/C/ProgramData/Microsoft/**",
  "files/**/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/**", "files/C/ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp/**",
  "files/C/Boot/**", "files/C/bootmgr", "files/etc/**", "files/usr/**", "files/bin/**", "files/sbin/**", "files/boot/**",
  "files/System/**", "files/Library/LaunchDaemons/**", "files/**/Library/LaunchAgents/**",
];

/** Commands (by the program they run) that wreck a computer or hide what is happening. */
const NEVER_COMMANDS = [
  "shell/format", "shell/format.com", "shell/diskpart", "shell/bcdedit", "shell/vssadmin", "shell/wbadmin", "shell/wevtutil", "shell/cipher",
  "shell/mkfs", "shell/mkfs.*", "shell/fdisk", "shell/shutdown", "shell/reboot", "shell/halt", "shell/poweroff",
  "shell/set-mppreference", "shell/add-mppreference", "shell/remove-mppreference", "shell/clear-eventlog", "shell/stop-computer", "shell/restart-computer",
  "shell/download-and-run", "shell/encoded-command", "shell/disable-protection",
];

/** Commands that change accounts, start-up, services, security settings or permissions: a person decides. */
const ASK_COMMANDS = [
  "shell/reg", "shell/reg.exe", "shell/regedit", "shell/set-itemproperty", "shell/new-itemproperty", "shell/remove-itemproperty",
  "shell/schtasks", "shell/register-scheduledtask", "shell/at", "shell/crontab", "shell/sc", "shell/sc.exe", "shell/new-service", "shell/set-service",
  "shell/systemctl", "shell/launchctl", "shell/net", "shell/net1", "shell/net.exe", "shell/new-localuser", "shell/add-localgroupmember", "shell/useradd",
  "shell/usermod", "shell/passwd", "shell/netsh", "shell/new-netfirewallrule", "shell/set-netfirewallprofile", "shell/ufw", "shell/iptables",
  "shell/icacls", "shell/takeown", "shell/cacls", "shell/chown", "shell/chmod", "shell/attrib", "shell/set-acl",
  "shell/sends-data", "shell/runas", "shell/sudo", "shell/start-process-elevated", "shell/set-executionpolicy", "shell/msiexec", "shell/winget", "shell/choco",
];

export const STANDARD_POLICY: PolicyDocument = {
  schema_version: 1,
  description: "Standard protection for AI tools found on your computers. Never: saved passwords and keys, Heimdall's own settings, system folders, disk wiping, antivirus changes, downloaded or hidden scripts. Ask first: deleting, sending data out, .env files, accounts, start-up, services and permissions. Ordinary work runs at once.",
  rules: [
    { id: "never-saved-passwords-keys-wallets", description: "AI tools may not read or change saved passwords, keys, browser logins or wallets.", effect: "deny", match: { resources: SECRET_STORES } },
    { id: "never-switch-off-heimdall", description: "AI tools may not change Heimdall or the settings that route them through Heimdall.", effect: "deny", match: { operations: ["create", "update", "delete", "command_execution", "external_transfer"], resources: PROTECTION_SETTINGS } },
    { id: "never-change-system-folders", description: "AI tools may not change Windows, program or start-up folders.", effect: "deny", match: { operations: ["create", "update", "delete"], resources: SYSTEM_AREAS } },
    { id: "never-dangerous-commands", description: "Wiping disks, boot settings, backups or logs, turning off antivirus, or running downloaded / hidden scripts.", effect: "deny", match: { resources: NEVER_COMMANDS } },
    { id: "ask-before-deleting", description: "Deleting anything.", effect: "require_approval", match: { operations: ["delete"] }, approval: { required_role: "admin", ttl_seconds: 900 } },
    { id: "ask-before-sending-data-out", description: "Sending data out of the computer: uploads, emails and messages, git push, publishing.", effect: "require_approval", match: { operations: ["external_transfer"] }, approval: { required_role: "admin", ttl_seconds: 900 } },
    { id: "ask-before-reading-secrets-files", description: ".env, key and certificate files.", effect: "require_approval", match: { resources: ["files/**/.env", "files/**/.env.*", "files/**/*.pem", "files/**/*.key", "files/**/*.pfx", "files/**/*.p12", "files/**/.npmrc", "files/**/.pypirc", "files/**/credentials.json", "files/**/service-account*.json", "files/**/secrets.*"] }, approval: { required_role: "admin", ttl_seconds: 900 } },
    { id: "ask-before-system-changes", description: "Accounts, registry, start-up tasks, services, firewall, permissions, installing software, running as administrator.", effect: "require_approval", match: { resources: ASK_COMMANDS }, approval: { required_role: "admin", ttl_seconds: 900 } },
    { id: "routine-work", description: "Ordinary reading, writing and commands in your projects.", effect: "allow", match: { tools: ["*"], operations: ["read", "create", "update", "command_execution"] } },
  ],
};

/** The first automatic policy (before Standard protection). Organizations still on it are moved to STANDARD_POLICY. */
export const LEGACY_AUTO_POLICY: PolicyDocument = {
  schema_version: 1,
  description: "Applied automatically to AI tools Heimdall finds. Reads, edits and ordinary commands run at once; deleting and sending data outside wait for approval.",
  rules: [
    { id: "deletes-need-approval", effect: "require_approval", match: { operations: ["delete"] }, approval: { required_role: "admin", ttl_seconds: 900 } },
    { id: "transfers-need-approval", effect: "require_approval", match: { operations: ["external_transfer"] }, approval: { required_role: "admin", ttl_seconds: 900 } },
    { id: "routine-work", effect: "allow", match: { tools: ["*"], operations: ["read", "create", "update", "command_execution"] } },
  ],
};

/** Earlier automatic policies Heimdall shipped. An organization still on one of these, unedited, is moved to STANDARD_POLICY. */
export const PREVIOUS_AUTO_POLICIES: PolicyDocument[] = [
  LEGACY_AUTO_POLICY,
  // Standard protection before its "ask first" and "at once" rules had descriptions
  { ...STANDARD_POLICY, rules: STANDARD_POLICY.rules.map((r) => (["ask-before-deleting", "ask-before-sending-data-out", "routine-work"].includes(r.id) ? (({ description: _d, ...rest }) => rest)(r) : r)) as PolicyDocument["rules"] },
];
