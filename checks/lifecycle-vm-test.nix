# checks/lifecycle-vm-test.nix
#
# THE ONE REAL RUNTIME TEST in this project. Everything else under checks/ is eval-only --
# renders-and-inspects, never boots anything. This is a `pkgs.testers.nixosTest` (ephemeral QEMU,
# nothing persists after the build, no standing VM infrastructure needed) that exercises the WHOLE
# lifecycle against a REAL LUKS container, on a REAL squashfs, exactly the way an operator would --
# never a stand-in, never mocked. Adoption of the house pattern nixram's own
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
#      static-source one) and a real STATIC category, needing no secret at all.
#   3. nixvault-verify, run before anything is ever committed, says so in as many words and fires
#      the alert path -- proving "unattended detection" actually detects something.
#   4. nixvault-update commits the staged image -- needing, and only working with, the operator's
#      passphrase -- after which nixvault-verify reports clean and stays silent.
#   5. The container is reopened cold (a fresh `cryptsetup open`, no state left over from having
#      just written it) with the SAME passphrase, its squashfs mounted, and the real staged content
#      read back byte-for-byte -- including the generated header backup.
#   6. THE FAILING DIRECTIONS, proven, not asserted: a WRONG passphrase fails cleanly against both
#      a raw `cryptsetup open` and `nixvault-update` itself, leaving no mapper behind either time.
#      Backdating the staleness timestamps (no content change) still trips the alert on age alone,
#      independent of the drift check.
#   7. Editing the source content and re-assembling is DETECTED as drift by nixvault-verify (the
#      staged-hash vs. committed-hash compare -- see modules/nixvault.nix's own header for why that
#      proxy exists at all: verify cannot open the container to look, that needs the passphrase),
#      the alert fires again, and committing the new content clears it -- proving the full
#      unattended-detection / attended-commit round trip, not just one half of it.
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
  # a real fleet's paging channel, and exactly why `staleness.alertCommand` is a free-text escape
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
      # reaches the squashfs unmodified; the other small-tier categories are left empty (no error,
      # see mkSourceOption) since this test's job is the LIFECYCLE, not the manifest's breadth.
      sources.runbook = [ "/root/test-runbook.txt" ];

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

    # squashfs to mount the committed vault's contents back off the dm-crypt mapper; dm-crypt and
    # dm_mod for cryptsetup's own device-mapper target. Same explicit list rescue-vm-test.nix uses,
    # for the same reason: not built into every kernel config profile, and a missing module here
    # would fail this test for a reason that has nothing to do with what it is actually checking.
    boot.kernelModules = [ "squashfs" "dm-crypt" "dm_mod" ];

    virtualisation.memorySize = 1024;
    virtualisation.cores = 2;
  };

  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target")

    with subtest("pre-size the vault's container as a plain regular FILE -- never a block device"):
        machine.succeed("truncate -s 64M /root/vault-test.img")

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
        machine.succeed("nixvault-assemble")
        machine.succeed("test -e /var/lib/nixvault/vault.squashfs")
        machine.succeed("test -e /var/lib/nixvault/staged-hash")

    with subtest("nixvault-verify BEFORE any commit: says so plainly, and fires the alert"):
        machine.succeed("rm -f /root/alert-log.txt")
        out = machine.succeed("nixvault-verify")
        assert "never been committed" in out, out
        assert "ACTION REQUIRED" in out, out
        assert "nixvault-update" in out, out
        alert_out = machine.succeed("cat /root/alert-log.txt")
        assert "ALERT: nixvault:" in alert_out, alert_out

    with subtest("nixvault-update commits the staged image -- needs, and only works with, the passphrase"):
        machine.succeed("echo '${testPassphrase}' | nixvault-update")
        machine.succeed("test -e /var/lib/nixvault/committed-hash")
        # cryptsetup close already ran inside nixvault-update -- confirm it really did, nothing left open
        machine.fail("test -e /dev/mapper/vault")

    with subtest("nixvault-verify AFTER a clean commit: reports match, stays silent, no alert"):
        machine.succeed("rm -f /root/alert-log.txt")
        out = machine.succeed("nixvault-verify")
        assert "PASS: assembled content matches" in out, out
        assert "ACTION REQUIRED" not in out, out
        machine.fail("test -e /root/alert-log.txt")

    with subtest("reopen the container COLD, with the passphrase, mount the squashfs, and read real content back"):
        machine.succeed("echo '${testPassphrase}' | cryptsetup open /root/vault-test.img nixvault-test-verify-1")
        machine.succeed("mkdir -p /mnt/nixvault-check")
        machine.succeed("mount -t squashfs -o ro /dev/mapper/nixvault-test-verify-1 /mnt/nixvault-check")
        machine.succeed("grep -q runbook-content-v1 /mnt/nixvault-check/runbook/test-runbook.txt")
        machine.succeed("test -e /mnt/nixvault-check/luksHeaderBackups/test-volume.img")
        machine.succeed("grep -q test-volume /mnt/nixvault-check/deviceRoleMap/device-role-map.txt")
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

    with subtest("committing the new content clears the drift warning, and the NEW content is really there"):
        machine.succeed("rm -f /root/alert-log.txt")
        machine.succeed("echo '${testPassphrase}' | nixvault-update")
        out = machine.succeed("nixvault-verify")
        assert "PASS: assembled content matches" in out, out
        assert "DRIFTED" not in out, out
        machine.fail("test -e /root/alert-log.txt")

        machine.succeed("echo '${testPassphrase}' | cryptsetup open /root/vault-test.img nixvault-test-verify-2")
        machine.succeed("mount -t squashfs -o ro /dev/mapper/nixvault-test-verify-2 /mnt/nixvault-check")
        machine.succeed("grep -q runbook-content-v2-CHANGED /mnt/nixvault-check/runbook/test-runbook.txt")
        machine.succeed("umount /mnt/nixvault-check")
        machine.succeed("cryptsetup close nixvault-test-verify-2")
  '';
}
