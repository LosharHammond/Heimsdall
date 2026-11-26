/**
 * Trusted file access. This module is the ONLY code that touches the protected folder.
 *
 * What it enforces (on a local filesystem it can actually inspect):
 *  - logical resource paths are validated (shared normalizer: traversal, absolute paths, encodings, Windows quirks);
 *  - every path component is checked with lstat + realpath, so symbolic links, NTFS junctions and any other redirection that
 *    leaves the protected root are refused;
 *  - case is canonicalized to the real on-disk spelling BEFORE authorization, so policy rules cannot be dodged with `DOCS/..`
 *    on a case-insensitive filesystem;
 *  - files with more than one hard link are refused (a hard link inside the root can alias a file outside it);
 *  - the identity (device, inode, creation time) of the file seen at authorization time is bound and re-checked at use time.
 *
 * What it cannot do: it is not an operating-system sandbox. A process with direct filesystem access (including the
 * agent itself, if it has any) can bypass it, and a very small race remains between the last check and the system call on
 * Windows, where O_NOFOLLOW does not exist. See docs/EXECUTOR-BOUNDARY.md.
 */
import { closeSync, constants, fstatSync, lstatSync, mkdirSync, openSync, readSync, readdirSync, realpathSync, unlinkSync, writeSync, ftruncateSync } from "node:fs";
import { join, sep } from "node:path";
import { normalizeResource } from "../shared/policy.js";

/**
 * A file's identity: device, inode and creation time (or, where the filesystem reports none, its last status change).
 * device:inode alone is not enough: Linux hands a deleted file's inode number straight to the next file created, so a file
 * swapped between authorization and use could otherwise look like the authorized one.
 */
function fileIdentity(st: { dev: bigint; ino: bigint; birthtimeNs: bigint; ctimeNs: bigint }): string {
  return `${st.dev}:${st.ino}:${st.birthtimeNs > 0n ? `b${st.birthtimeNs}` : `c${st.ctimeNs}`}`;
}

export class PathRefusal extends Error {
  constructor(
    public code: "PATH_INVALID" | "PATH_ESCAPES_ROOT" | "PATH_REDIRECTED" | "NOT_FOUND" | "NOT_A_FILE" | "ALREADY_EXISTS" | "HARDLINK" | "RESOURCE_CHANGED" | "TOO_LARGE",
    message: string,
  ) {
    super(message);
    this.name = "PathRefusal";
  }
}

export interface Resolved {
  /** Canonical, real-case logical path relative to the root. This is what gets authorized. */
  rel: string;
  abs: string;
  exists: boolean;
  /** Identity (device, inode, creation or change time) of the existing file, bound at authorization time. */
  identity: string | null;
  caseCorrected: boolean;
}

export type Mode = "existing" | "create";

const sameCase = (a: string, b: string, ci: boolean) => (ci ? a.toLowerCase() === b.toLowerCase() : a === b);

export class ProtectedFs {
  readonly root: string;
  private ci: boolean;
  private maxRead: number;

  constructor(rootDir: string, opts: { maxReadBytes?: number; caseInsensitive?: boolean } = {}) {
    mkdirSync(rootDir, { recursive: true });
    this.root = realpathSync.native(rootDir);
    this.ci = opts.caseInsensitive ?? (process.platform === "win32" || process.platform === "darwin");
    this.maxRead = opts.maxReadBytes ?? 256 * 1024;
  }

  resolve(resource: string, mode: Mode): Resolved {
    const n = normalizeResource(resource);
    if (!n.ok) throw new PathRefusal("PATH_INVALID", "Resource path is not a valid protected-folder path");
    const segs = n.value.split("/");
    let cur = this.root;
    const canon: string[] = [];
    let caseCorrected = false;
    let exists = true;
    for (let i = 0; i < segs.length; i++) {
      const last = i === segs.length - 1;
      let entries: string[];
      try {
        entries = readdirSync(cur);
      } catch {
        throw new PathRefusal("NOT_FOUND", "Parent folder does not exist");
      }
      const exact = entries.find((e) => e === segs[i]) ?? entries.find((e) => sameCase(e, segs[i], this.ci));
      if (!exact) {
        if (last && mode === "create") {
          exists = false;
          canon.push(segs[i]);
          cur = join(cur, segs[i]);
          break;
        }
        throw new PathRefusal("NOT_FOUND", "Resource does not exist");
      }
      if (exact !== segs[i]) caseCorrected = true;
      if (last && mode === "create") throw new PathRefusal("ALREADY_EXISTS", "Resource already exists");
      canon.push(exact);
      cur = join(cur, exact);
      const st = lstatSync(cur);
      if (st.isSymbolicLink()) throw new PathRefusal("PATH_REDIRECTED", "Symbolic links are not followed");
      // realpath catches junctions / mount points / any other redirection lstat does not flag.
      const real = realpathSync.native(cur);
      if (!(real === cur || (this.ci && real.toLowerCase() === cur.toLowerCase()))) {
        throw new PathRefusal(real.startsWith(this.root + sep) ? "PATH_REDIRECTED" : "PATH_ESCAPES_ROOT", "Path is redirected (junction/link)");
      }
      if (!last && !st.isDirectory()) throw new PathRefusal("NOT_FOUND", "Not a folder");
      if (last) {
        if (!st.isFile()) throw new PathRefusal("NOT_A_FILE", "Only regular files are supported");
        if (st.nlink > 1) throw new PathRefusal("HARDLINK", "Files with multiple hard links are refused");
      }
    }
    // Parent folder of a new file must itself be inside the root (already walked above); final containment check:
    const abs = join(this.root, ...canon);
    if (!(abs === this.root || abs.startsWith(this.root + sep))) throw new PathRefusal("PATH_ESCAPES_ROOT", "Path escapes the protected folder");
    let identity: string | null = null;
    if (exists) {
      const st = lstatSync(abs, { bigint: true });
      identity = fileIdentity(st);
    }
    return { rel: canon.join("/"), abs, exists, identity, caseCorrected };
  }

  /** Re-resolves at use time and refuses if the thing at this path is no longer the file that was authorized. */
  verify(resource: string, mode: Mode, expectedIdentity: string | null): Resolved {
    const r = this.resolve(resource, mode);
    if (mode === "existing" && r.identity !== expectedIdentity) throw new PathRefusal("RESOURCE_CHANGED", "The file changed between authorization and use");
    return r;
  }

  private openChecked(r: Resolved, flags: number, expectedIdentity: string | null): number {
    const fd = openSync(r.abs, flags);
    try {
      const st = fstatSync(fd, { bigint: true });
      if (fileIdentity(st) !== expectedIdentity) throw new PathRefusal("RESOURCE_CHANGED", "The opened file is not the file that was authorized");
      if (st.nlink > 1n) throw new PathRefusal("HARDLINK", "Files with multiple hard links are refused");
      const again = lstatSync(r.abs, { bigint: true });
      if (fileIdentity(again) !== expectedIdentity) throw new PathRefusal("RESOURCE_CHANGED", "The path now refers to a different file");
      return fd;
    } catch (e) {
      closeSync(fd);
      throw e;
    }
  }

  read(resource: string, identity: string | null): { bytes: number; text: string } {
    const r = this.verify(resource, "existing", identity);
    const fd = this.openChecked(r, constants.O_RDONLY, identity);
    try {
      const size = Number(fstatSync(fd).size);
      if (size > this.maxRead) throw new PathRefusal("TOO_LARGE", `File is larger than ${this.maxRead} bytes`);
      const buf = Buffer.alloc(size);
      let off = 0;
      while (off < size) {
        const n = readSync(fd, buf, off, size - off, off);
        if (n === 0) break;
        off += n;
      }
      return { bytes: off, text: buf.subarray(0, off).toString("utf8") };
    } finally {
      closeSync(fd);
    }
  }

  create(resource: string, text: string): { created: string } {
    const r = this.resolve(resource, "create");
    const fd = openSync(r.abs, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600); // exclusive: never overwrites
    try {
      writeSync(fd, text);
    } finally {
      closeSync(fd);
    }
    return { created: r.rel };
  }

  update(resource: string, text: string, identity: string | null): { updated: string } {
    const r = this.verify(resource, "existing", identity);
    const fd = this.openChecked(r, constants.O_RDWR, identity);
    try {
      ftruncateSync(fd, 0);
      writeSync(fd, text, 0);
    } finally {
      closeSync(fd);
    }
    return { updated: r.rel };
  }

  delete(resource: string, identity: string | null): { deleted: string } {
    const r = this.verify(resource, "existing", identity);
    const fd = this.openChecked(r, constants.O_RDONLY, identity); // identity + nlink re-checked on the open handle
    try {
      unlinkSync(r.abs);
    } finally {
      closeSync(fd);
    }
    return { deleted: r.rel };
  }
}
