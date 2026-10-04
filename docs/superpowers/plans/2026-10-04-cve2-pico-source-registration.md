# CVE2 and PicoRV32 Source Registration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the exact CV32E20/CVE2 and PicoRV32 RTL revisions used by generated local harnesses reproducible from a clean clone of this repository.

**Architecture:** Register the existing clean upstream checkouts as pinned Git submodules, preserving their contents and current commits. Verify the parent gitlinks, declared URLs and an isolated clone of only these two submodules. This is the source acquisition prerequisite for the five protocol design; component profiles, source locks and harness code are separate implementation plans.

**Tech Stack:** Git submodules, Bash, Python 3 standard library.

## Global Constraints

- Keep real CPU/IP RTL in separate local harnesses; do not generate a SoC fabric.
- CVE2 source revision is `d079e8c8e6a08b330940ae123876ba0612bec18d` from `https://github.com/openhwgroup/cve2.git`.
- PicoRV32 source revision is `ef203c2b0a3fb793280f5114941416c425c5b461` from `https://github.com/YosysHQ/picorv32.git`.
- Preserve both current checkout contents; both must be clean before converting them to gitlinks.
- Do not touch user owned untracked `agent.md`, `SoC内部数据流动与去向.docx:Zone.Identifier`, BOOM checkout or Ibex submodule state.
- This plan proves source acquisition only. It must not be reported as any protocol's Generated or RTL operational status.

---

## File Structure

- Modify `.gitmodules`: declare both upstream URLs and paths.
- Add gitlinks `third_party/cv32e20_upstream_reference` and `third_party/picorv32_upstream_reference`: pin exact revisions without copying source bytes into the parent repository.
- No production Python, SystemVerilog or profile files change in this plan.

### Task 1: Register both exact upstream revisions

**Files:**
- Modify: `.gitmodules`
- Add gitlink: `third_party/cv32e20_upstream_reference`
- Add gitlink: `third_party/picorv32_upstream_reference`

**Interfaces:**
- Consumes: the existing local upstream Git checkouts and their `origin` URLs.
- Produces: two parent repository gitlinks plus `.gitmodules` declarations usable by `git submodule update --init`.

- [ ] **Step 1: Assert the two source checkouts are pristine and at the approved commits**

```bash
test -z "$(git -C third_party/cv32e20_upstream_reference status --porcelain)"
test -z "$(git -C third_party/picorv32_upstream_reference status --porcelain)"
test "$(git -C third_party/cv32e20_upstream_reference rev-parse HEAD)" = d079e8c8e6a08b330940ae123876ba0612bec18d
test "$(git -C third_party/picorv32_upstream_reference rev-parse HEAD)" = ef203c2b0a3fb793280f5114941416c425c5b461
test "$(git -C third_party/cv32e20_upstream_reference remote get-url origin)" = https://github.com/openhwgroup/cve2.git
test "$(git -C third_party/picorv32_upstream_reference remote get-url origin)" = https://github.com/YosysHQ/picorv32.git
```

Expected: every command exits 0. Stop without modifying either checkout if any assertion fails.

- [ ] **Step 2: Register the existing checkouts as submodules**

```bash
git submodule add --force https://github.com/openhwgroup/cve2.git third_party/cv32e20_upstream_reference
git submodule add --force https://github.com/YosysHQ/picorv32.git third_party/picorv32_upstream_reference
```

Expected: `.gitmodules` has two new sections; both paths have mode `160000` in the index. The commands may move each checkout's Git metadata under `.git/modules`; source files and HEAD remain the same.

- [ ] **Step 3: Assert exact staged gitlinks and URLs**

```bash
git ls-files --stage third_party/cv32e20_upstream_reference third_party/picorv32_upstream_reference
git config -f .gitmodules --get submodule.third_party/cv32e20_upstream_reference.url
git config -f .gitmodules --get submodule.third_party/picorv32_upstream_reference.url
git diff --cached --check
```

Expected: two `160000` entries at the exact revisions above, expected HTTPS URLs, no whitespace errors. If the existing checkouts make `git submodule add` refuse, inspect its message and use `git -C <checkout> status` before a reversible repair; do not delete either directory.

- [ ] **Step 4: Commit only the acquisition change**

```bash
git add .gitmodules third_party/cv32e20_upstream_reference third_party/picorv32_upstream_reference
git commit -m "build: pin CVE2 and PicoRV32 source submodules"
```

Expected: one commit changing only `.gitmodules` and the two gitlinks.

### Task 2: Verify a clean repository can obtain both revisions

**Files:**
- Read: `.gitmodules` and the two gitlinks.
- Write outside repository: temporary clone under `/tmp`; remove it after verification.

**Interfaces:**
- Consumes: Task 1 committed parent repository.
- Produces: independently observed clean clone source acquisition evidence.

- [ ] **Step 1: Clone the parent locally without inheriting developer checkout state**

```bash
verify_dir="$(mktemp -d /tmp/myfuzz-source-check-XXXXXX)"
git clone --no-local --no-checkout . "$verify_dir"
git -C "$verify_dir" checkout HEAD
```

Expected: no untracked local CVE2/Pico source is copied into `verify_dir`.

- [ ] **Step 2: Fetch only the two pinned upstream submodules**

```bash
git -C "$verify_dir" submodule update --init third_party/cv32e20_upstream_reference third_party/picorv32_upstream_reference
test "$(git -C "$verify_dir/third_party/cv32e20_upstream_reference" rev-parse HEAD)" = d079e8c8e6a08b330940ae123876ba0612bec18d
test "$(git -C "$verify_dir/third_party/picorv32_upstream_reference" rev-parse HEAD)" = ef203c2b0a3fb793280f5114941416c425c5b461
```

Expected: both remote source revisions exist and are checked out at the parent pinned gitlinks. A transient network failure requires re-poll/retry of this command, not a weaker source claim.

- [ ] **Step 3: Verify pristine source trees and clean up the isolated clone**

```bash
test -z "$(git -C "$verify_dir/third_party/cv32e20_upstream_reference" status --porcelain)"
test -z "$(git -C "$verify_dir/third_party/picorv32_upstream_reference" status --porcelain)"
rm -rf "$verify_dir"
```

Expected: both clean; only the freshly created `/tmp/myfuzz-source-check-*` path is removed.

- [ ] **Step 4: Record the gate result in the next profile/source-lock implementation evidence**

```bash
git show --stat --oneline HEAD
git status --short
```

Expected: committed parent source pins remain; user owned untracked paths are unchanged. The next implementation plan must use these pins when it creates trusted component profiles and source lock closure records.
