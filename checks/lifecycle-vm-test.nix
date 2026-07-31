# checks/lifecycle-vm-test.nix
#
# THE ONE REAL RUNTIME TEST in this project. Everything else under checks/ is eval-only --
# renders-and-inspects, never boots anything. This is a `pkgs.testers.nixosTest` (ephemeral QEMU,
# nothing persists after the build, no standing VM infrastructure needed) that exercises the WHOLE
# lifecycle against a REAL LUKS container, on a REAL mounted f2fs filesystem, exactly the way an
# operator would -- never a stand-in, never mocked. Adoption of the house pattern nixram's own
# checks/swappiness-relief-vm-test.nix and nixrescue's checks/rescue-vm-test.nix already proved out
# (see either file's own header for the model this one copies), not invention.
#
# THE ONE DESIGN CHOICE WORTH EXPLAINING: the vault's LUKS container is a plain, pre-sized regular
# FILE inside the VM's own root (`/root/vault-test.img`), never a real or emulated block device.
# `nixvault.device`'s own option text already says cryptsetup treats a block device and a pre-sized
# regular file identically -- this test is the proof of that claim, and it is also the safest
# possible choice: nothing here ever touches `/dev/vdX`, `virtualisation.emptyDiskImages`, or any
# other block-device machinery, only a file that lives and dies with the VM.
#
# WHAT THIS PROVES, in the order it happens below -- the corrected lifecycle from
# nixrescue.md §7.3 (assemble/compare/alert unattended, commit attended), not the "no secret at
# all" claim that record's own earlier draft made and later retracted:
#
#   1. nixvault-create formats a REAL LUKS2 container with a random master key, then adds the
#      operator's own passphrase, then REFUSES to reformat that same container a second time.
#   2. nixvault-assemble stages a manifest with a real GENERATED category (a LUKS header backup
#      taken from a second, genuinely-formatted dummy volume -- proving that pipeline, not just the
#      static-source one) and real STATIC categories, needing no secret at all.
#   3. nixvault-verify, run before anything is ever committed, says so in as many words and fires
#      the alert path -- proving "unattended detection" actually detects something.
#   4. nixvault-update commits the staged manifest -- needing, and only working with, the
#      operator's passphrase -- after which nixvault-verify reports clean and stays silent.
#   5. The container is reopened cold (a fresh `cryptsetup open`, no state left over from having
#      just written it) with the SAME passphrase, its f2fs filesystem mounted, and the real staged
#      content read back byte-for-byte -- including the generated header backup.
#   6. THE FAILING DIRECTIONS, proven, not asserted: a WRONG passphrase fails cleanly against both
#      a raw `cryptsetup open` and `nixvault-update` itself, leaving no mapper behind either time.
#      Backdating the staleness timestamps (no content change) still trips the alert on age alone,
#      independent of the drift check.
#   7. Editing the source content and re-assembling is DETECTED as drift by nixvault-verify (the
#      staged-hash vs. committed-hash compare -- see modules/nixvault.nix's own header for why that
#      proxy exists at all: verify cannot open the container to look, that needs the passphrase),
#      the alert fires again, and committing the new content clears it -- proving the full
#      unattended-detection / attended-commit round trip, not just one half of it.
#   8. INCREMENTALITY, MEASURED, NOT ASSUMED -- the entire point of dropping squashfs for f2fs
#      (modules/nixvault.nix's own header). A large, incompressible "bulk" file sits in the
#      manifest throughout; the SECOND commit above (step 7) changes only a few bytes of the
#      runbook and leaves the bulk file untouched. This test measures the vault's LUKS container
#      -- a plain regular file, never a real or emulated block device -- by its ALLOCATED BLOCK
#      COUNT (`stat -c%b`, the kernel's own real-usage accounting for that file) immediately
#      before and after each commit, and asserts the second commit's delta is a small fraction of
#      the first's. `nodiscard` (in the shared recipe -- nixfs's lib/catalogue.nix,
#      filesystems.f2fs.compression) is exactly what makes this legible: without it, freed
#      blocks could be punched back to sparse holes and blur the
#      measurement; with it, an allocated-block delta is a faithful proxy for real bytes written
#      to the block layer for that commit, same as reading a real block device's own write
#      counters would be.
#
# NOT tested here: `nixvault-export-offsite` (a separate, opt-in offsite-copy concern with its own
# re-wrap/kill-slot lifecycle -- orthogonal to the create/assemble/commit/drift loop this test is
# about) and the system-manager backend (nixosTest is NixOS-only by construction; the
# backend-parity eval checks in checks/default.nix are what proves the two backends agree on what
# they RENDER, which is the only thing that differs between them -- see modules/nixvault.nix's own
# "ONE FILE, BOTH BACKENDS" header).

{ pkgs, nixvaultModule }:

let
  testPassphrase = "nixvault-test-passphrase-throwaway";
  wrongPassphrase = "definitely-the-wrong-passphrase";

  # Writes whatever nixvault-verify hands it to a plain file -- the simplest possible stand-in for
  # a real operator's paging channel, and exactly why `staleness.alertCommand` is a free-text escape
  # hatch rather than a hardcoded one (see the option's own description).
  alertScript = pkgs.writeShellScript "nixvault-test-alert" ''
    echo "ALERT: $1" >> /root/alert-log.txt
  '';
in
pkgs.testers.nixosTest {
  name = "nixvault-lifecycle";

  nodes.machine = { pkgs, lib, ... }: {
    imports = [ nixvaultModule ];

    nixvault = {
      enable = true;
      tier = "small";
      device = "/root/vault-test.img";

      # The "generated" category's live input -- a SECOND, genuinely-formatted LUKS volume this
      # vault is not itself, proving nixvault-assemble's `cryptsetup luksHeaderBackup` pipeline for
      # real rather than trusting it renders correctly and stopping there.
      luksVolumes = [
        { name = "test-volume"; device = "/root/dummy-encrypted.img"; }
      ];

      # One static category with real, checkable content -- enough to prove the manifest actually
      # reaches the f2fs filesystem unmodified; the other small-tier categories (besides
      # recoveryKeys below) are left empty (no error, see mkSourceOption) since this test's job is
      # the LIFECYCLE, not the manifest's breadth.
      sources.runbook = [ "/root/test-runbook.txt" ];

      # A large, incompressible "bulk" stand-in (random bytes, never touched again after it is
      # created) -- exists purely so the INCREMENTALITY subtest near the end of this file has a
      # deterministic, environment-independent baseline: commit 1 must write it in full, and commit
      # 2 (which only changes the small runbook file above) must NOT rewrite it at all. Deliberately
      # NOT sized off the dummy LUKS volume's own header-backup size, which cryptsetup may size
      # adaptively small on a tiny device and so cannot be relied on for this measurement.
      sources.recoveryKeys = [ "/root/test-bulk-file.bin" ];

      # Manual control over timing: this test drives create/assemble/verify/update itself, in a
      # precise order, and does not want a background timer racing it -- the exact combination
      # checks/default.nix's own "assemble/disabled-still-keeps-verify" eval test already proves is
      # supported.
      assemble.enable = false;

      # The smallest legal value (ints.positive) -- this test backdates timestamps by ten days to
      # prove the age check fires, and ten days comfortably clears any threshold above zero without
      # needing to wait for real time to pass.
      staleness.maxAgeDays = 1;
      staleness.alertCommand = "${alertScript}";
    };

    # nixvault itself never adds a bare `cryptsetup` binary to the system profile -- only its own
    # wrapped tools, which each carry their own runtimeInputs closure. This test drives cryptsetup
    # directly (reopening cold, proving a wrong passphrase, formatting the dummy volume), so it
    # needs the bare command too.
    environment.systemPackages = [ pkgs.cryptsetup ];

    # f2fs to format and mount the vault's own filesystem; dm-crypt and dm_mod for cryptsetup's own
    # device-mapper target. Same explicit list rescue-vm-test.nix uses, for the same reason: not
    # built into every kernel config profile, and a missing module here would fail this test for a
    # reason that has nothing to do with what it is actually checking.
    boot.kernelModules = [ "f2fs" "dm-crypt" "dm_mod" ];

    virtualisation.memorySize = 1024;
    virtualisation.cores = 2;
  };

  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target")

    with subtest("pre-size the vault's container as a plain regular FILE -- never a block device"):
        # Sized well above f2fs's own practical minimum (LUKS2's default header/keyslot area is
        # itself ~16 MiB) plus room for the incompressible "bulk" file the INCREMENTALITY subtest
        # needs near the end of this file -- generous headroom, never a real or emulated device.
        machine.succeed("truncate -s 160M /root/vault-test.img")

    with subtest("format a SECOND, real LUKS volume this vault is not itself, for the generated header-backup category"):
        machine.succeed("truncate -s 32M /root/dummy-encrypted.img")
        machine.succeed("echo 'dummy-volume-throwaway-key' | cryptsetup luksFormat --type luks2 --batch-mode /root/dummy-encrypted.img")

    with subtest("nixvault-create formats the vault with a random master key, then adds the operator's own passphrase"):
        machine.succeed("(echo '${testPassphrase}'; echo '${testPassphrase}') | nixvault-create")
        machine.succeed("cryptsetup isLuks /root/vault-test.img")

    with subtest("nixvault-create REFUSES to reformat an already-existing container"):
        machine.fail("nixvault-create")
        # still opens with the SAME passphrase as before -- refusing to reformat did not disturb it
        machine.succeed("echo '${testPassphrase}' | cryptsetup open --test-passphrase /root/vault-test.img")

    with subtest("nixvault-assemble stages the manifest -- no secret involved at all"):
        machine.succeed("echo 'runbook-content-v1' > /root/test-runbook.txt")
        # The incompressible "bulk" file the INCREMENTALITY subtest measures against later --
        # created once, here, and never touched again for the rest of this test.
        machine.succeed("dd if=/dev/urandom of=/root/test-bulk-file.bin bs=1M count=8 status=none")
        machine.succeed("nixvault-assemble")
        machine.succeed("test -d /var/lib/nixvault/stage")
        machine.succeed("test -e /var/lib/nixvault/stage/recoveryKeys/test-bulk-file.bin")
        machine.succeed("test -e /var/lib/nixvault/staged-hash")

    with subtest("nixvault-verify BEFORE any commit: says so plainly, and fires the alert"):
        machine.succeed("rm -f /root/alert-log.txt")
        out = machine.succeed("nixvault-verify")
        assert "never been committed" in out, out
        assert "ACTION REQUIRED" in out, out
        assert "nixvault-update" in out, out
        alert_out = machine.succeed("cat /root/alert-log.txt")
        assert "ALERT: nixvault:" in alert_out, alert_out

    with subtest("nixvault-update commits the staged manifest (COMMIT 1, the full manifest) -- needs, and only works with, the passphrase"):
        # Allocated-block count of the container's own backing FILE, immediately either side of
        # the commit -- see the INCREMENTALITY subtest near the end of this file for what this
        # measures and why. Captured here, used there.
        blocks_before_commit_1 = int(machine.succeed("stat -c%b /root/vault-test.img").strip())
        machine.succeed("echo '${testPassphrase}' | nixvault-update")
        blocks_after_commit_1 = int(machine.succeed("stat -c%b /root/vault-test.img").strip())
        commit_1_bytes = (blocks_after_commit_1 - blocks_before_commit_1) * 512
        machine.succeed("test -e /var/lib/nixvault/committed-hash")
        # cryptsetup close already ran inside nixvault-update -- confirm it really did, nothing left open
        machine.fail("test -e /dev/mapper/vault")

    with subtest("nixvault-verify AFTER a clean commit: reports match, stays silent, no alert"):
        machine.succeed("rm -f /root/alert-log.txt")
        out = machine.succeed("nixvault-verify")
        assert "PASS: assembled content matches" in out, out
        assert "ACTION REQUIRED" not in out, out
        machine.fail("test -e /root/alert-log.txt")

    with subtest("reopen the container COLD, with the passphrase, mount the f2fs filesystem, and read real content back"):
        machine.succeed("echo '${testPassphrase}' | cryptsetup open /root/vault-test.img nixvault-test-verify-1")
        machine.succeed("mkdir -p /mnt/nixvault-check")
        # A PLAIN mount, no compress_* options -- proving, incidentally, that f2fs decompression on
        # read needs none of them: the algorithm actually used is recorded per-file at write time
        # (see modules/nixvault.nix's own header), not re-derived from the CURRENT mount options.
        machine.succeed("mount -t f2fs -o ro /dev/mapper/nixvault-test-verify-1 /mnt/nixvault-check")
        machine.succeed("grep -q runbook-content-v1 /mnt/nixvault-check/runbook/test-runbook.txt")
        machine.succeed("test -e /mnt/nixvault-check/luksHeaderBackups/test-volume.img")
        machine.succeed("grep -q test-volume /mnt/nixvault-check/deviceRoleMap/device-role-map.txt")
        machine.succeed("cmp -s /root/test-bulk-file.bin /mnt/nixvault-check/recoveryKeys/test-bulk-file.bin")
        machine.succeed("umount /mnt/nixvault-check")
        machine.succeed("cryptsetup close nixvault-test-verify-1")

    with subtest("THE FAILING DIRECTION: a WRONG passphrase fails cleanly, leaves no mapper behind"):
        machine.fail("echo '${wrongPassphrase}' | cryptsetup open /root/vault-test.img nixvault-test-wrong-1")
        machine.fail("test -e /dev/mapper/nixvault-test-wrong-1")
        machine.fail("echo '${wrongPassphrase}' | nixvault-update")
        machine.fail("test -e /dev/mapper/vault")

    with subtest("THE FAILING DIRECTION: age alone (no content change) still trips the staleness alert"):
        machine.succeed("rm -f /root/alert-log.txt")
        machine.succeed("touch -d '10 days ago' /var/lib/nixvault/last-written-timestamp")
        machine.succeed("touch -d '10 days ago' /var/lib/nixvault/last-assembled-timestamp")
        out = machine.succeed("nixvault-verify")
        assert "over the 1-day limit" in out, out
        alert_out = machine.succeed("cat /root/alert-log.txt")
        assert "ALERT: nixvault:" in alert_out, alert_out

    with subtest("re-assembling with CHANGED content is DETECTED as drift, and the alert fires again"):
        machine.succeed("rm -f /root/alert-log.txt")
        machine.succeed("echo 'runbook-content-v2-CHANGED' > /root/test-runbook.txt")
        machine.succeed("nixvault-assemble")
        out = machine.succeed("nixvault-verify")
        assert "DRIFTED" in out, out
        assert "ACTION REQUIRED" in out, out
        alert_out = machine.succeed("cat /root/alert-log.txt")
        assert "ALERT: nixvault:" in alert_out, alert_out

    with subtest("committing the new content clears the drift warning, and the NEW content is really there (COMMIT 2 -- only the runbook changed)"):
        machine.succeed("rm -f /root/alert-log.txt")
        # Same measurement as COMMIT 1 above, around the SAME tool, for the SAME container --
        # the only thing that differs is how much of the manifest actually changed since the last
        # commit. See the INCREMENTALITY subtest below for the comparison this sets up.
        blocks_before_commit_2 = int(machine.succeed("stat -c%b /root/vault-test.img").strip())
        machine.succeed("echo '${testPassphrase}' | nixvault-update")
        blocks_after_commit_2 = int(machine.succeed("stat -c%b /root/vault-test.img").strip())
        commit_2_bytes = (blocks_after_commit_2 - blocks_before_commit_2) * 512
        out = machine.succeed("nixvault-verify")
        assert "PASS: assembled content matches" in out, out
        assert "DRIFTED" not in out, out
        machine.fail("test -e /root/alert-log.txt")

        machine.succeed("echo '${testPassphrase}' | cryptsetup open /root/vault-test.img nixvault-test-verify-2")
        machine.succeed("mount -t f2fs -o ro /dev/mapper/nixvault-test-verify-2 /mnt/nixvault-check")
        machine.succeed("grep -q runbook-content-v2-CHANGED /mnt/nixvault-check/runbook/test-runbook.txt")
        # The untouched bulk file is still there, byte-for-byte, after a commit that never wrote it.
        machine.succeed("cmp -s /root/test-bulk-file.bin /mnt/nixvault-check/recoveryKeys/test-bulk-file.bin")
        machine.succeed("umount /mnt/nixvault-check")
        machine.succeed("cryptsetup close nixvault-test-verify-2")

    with subtest("INCREMENTALITY, MEASURED: commit 2 (one small changed file) wrote materially less than commit 1 (the whole manifest)"):
        # Concrete, kernel-verified measurement, not an assumption -- see this file's own header
        # point 8 for the full reasoning. The vault's LUKS container is a plain regular file
        # (never a real or emulated block device, per this test's own house rule); `stat -c%b`
        # reports that file's REAL allocated block count, which only grows when bytes are
        # actually written to previously-sparse regions -- `nodiscard` (the shared recipe, nixfs's
        # lib/catalogue.nix filesystems.f2fs.compression) ensures freed blocks are never punched
        # back to holes and blurring this signal. Commit 1
        # had to write the whole manifest (including the 8 MiB incompressible bulk file) into a
        # freshly-formatted, entirely-sparse filesystem; commit 2 changed only a few bytes of the
        # runbook and left that bulk file untouched, so its real write footprint should be a small
        # fraction of commit 1's -- proving the incremental-commit design change actually works,
        # not merely that it was implemented.
        detail = (
            f"commit 1 wrote {commit_1_bytes} bytes, commit 2 wrote {commit_2_bytes} bytes "
            f"(container allocated-block delta, 512-byte units)"
        )
        assert commit_1_bytes > 4 * 1024 * 1024, f"commit 1 (the full manifest, including the 8 MiB bulk file) wrote suspiciously little -- {detail}"
        assert commit_2_bytes < commit_1_bytes // 3, f"commit 2 (one small changed file) should write a small fraction of commit 1's bytes, but did not -- {detail}"
        assert commit_2_bytes < 3 * 1024 * 1024, f"commit 2 (one small changed file) wrote more than 3 MiB -- {detail}"
        print(f"nixvault incrementality proof: {detail}")

    with subtest("a FAILED assemble leaves the live staging tree intact -- it is never populated in place"):
        # THE REGRESSION. Every cp in the populate is unguarded and the script is `set -e`, so a
        # source that stops existing (a repo renamed out from under the manifest is the real-world
        # shape) aborts it partway through. When the populate target WAS the live tree -- which had
        # already been rm -rf'd before the first copy -- that abort left the only copy of the
        # manifest truncated at whichever source failed. nixvault-update then mirrors that tree with
        # --delete, so the next commit deleted every category after the failure from the container.
        good_hash = machine.succeed("cat /var/lib/nixvault/staged-hash").strip()
        machine.succeed("mv /root/test-runbook.txt /root/test-runbook.txt.gone")
        machine.fail("nixvault-assemble")

        # The last SUCCESSFUL assemble's tree is still there, whole -- both the category that would
        # have been rebuilt before the failure and the one that would have come after it.
        machine.succeed("grep -q runbook-content-v2-CHANGED /var/lib/nixvault/stage/runbook/test-runbook.txt")
        machine.succeed("cmp -s /root/test-bulk-file.bin /var/lib/nixvault/stage/recoveryKeys/test-bulk-file.bin")
        # ...and still matches its recorded hash, so it is still a committable manifest.
        assert machine.succeed("cat /var/lib/nixvault/staged-hash").strip() == good_hash
        # The scratch tree the failed run was building is cleaned up, not left as debris.
        machine.fail("test -e /var/lib/nixvault/stage.new")

    with subtest("nixvault-update REFUSES a staging tree that does not match staged-hash"):
        # The second, independent guard: whatever truncated the tree, the committer must not mirror
        # it. Deleting a category by hand reproduces exactly what the committer would have seen.
        machine.succeed("rm -rf /var/lib/nixvault/stage/recoveryKeys")
        out = machine.fail("echo '${testPassphrase}' | nixvault-update 2>&1")
        assert "REFUSING TO COMMIT" in out, out

        # It refuses BEFORE opening the container, so the category the truncated tree was missing is
        # still in the vault, byte-for-byte. This is the assertion the bug would have failed.
        machine.succeed("echo '${testPassphrase}' | cryptsetup open /root/vault-test.img nixvault-test-verify-3")
        machine.succeed("mount -t f2fs -o ro /dev/mapper/nixvault-test-verify-3 /mnt/nixvault-check")
        machine.succeed("cmp -s /root/test-bulk-file.bin /mnt/nixvault-check/recoveryKeys/test-bulk-file.bin")
        machine.succeed("umount /mnt/nixvault-check")
        machine.succeed("cryptsetup close nixvault-test-verify-3")

    with subtest("and the POSITIVE direction: restore the source, and assemble/commit work again"):
        # A guard that never lets anything through is not a guard, it is an outage.
        machine.succeed("mv /root/test-runbook.txt.gone /root/test-runbook.txt")
        machine.succeed("nixvault-assemble")
        machine.succeed("echo '${testPassphrase}' | nixvault-update")
        out = machine.succeed("nixvault-verify")
        assert "PASS: assembled content matches" in out, out
        assert "DRIFTED" not in out, out
  '';
}
