# lib/f2fs-vault-opts.nix -- the f2fs recipe this vault's LUKS container is formatted and
# mounted with, VENDORED from the sibling nixnas project's own field-proven recipe
# (`modules/lib/f2fs-store-mount-opts.nix` + `modules/boot/disk.nix`'s mkfs invocation,
# STORAGE.md §§4-6) rather than invented here. One file, so this vault's flags cannot quietly
# drift from the recipe that was actually field-validated -- see modules/nixvault.nix's own
# header for why f2fs is the right call for THIS container even though nixnas's sibling
# rescue SLOT deliberately rejected it for its own (opposite) shape of write.
#
# `mkfsFeatures` -- passed to `mkfs.f2fs -O <mkfsFeatures>` at nixvault-create time, ONCE,
# the same one-time act as the LUKS format it rides alongside:
#   extra_attr       -- required scaffolding the other three features build on
#   inode_checksum   -- per-inode metadata checksum (STORAGE.md §7's integrity posture)
#   sb_checksum      -- superblock checksum, same reasoning
#   compression      -- without this mkfs feature bit, EVERY compress_* mount option below is
#                       silently ignored -- the single most common way to "enable compression"
#                       and get none (STORAGE.md §4 step 1)
#
# `mountOptions` -- the trigger + the flash-friendly/RAM-cache flags (STORAGE.md §4 step 2 /
# OPTIMIZATIONS.md §3), used both by nixvault-create's post-mkfs sanity mount and by
# nixvault-update's commit mount:
#   compress_algorithm=zstd:22 -- alone compresses NOTHING; see compress_extension below
#   compress_log_size=2        -- cluster size (2^2 = 4 pages -> 16 KiB clusters)
#   compress_extension=*       -- the actual trigger: without this, compress_algorithm is inert
#   compress_chksum            -- checksums compressed clusters (STORAGE.md §7)
#   nocompress_extension=sqlite -- carried over UNCHANGED from the sibling recipe, and it matters
#                       MORE here than it did there: the sibling excluded it because the Nix
#                       store's own state DB happens to sit under the same mount; THIS vault has
#                       no Nix state DB at all, but a mutable, operator-populated vault can
#                       plausibly hold a SQLite file of its own (a password-manager export, an
#                       inventory db) as part of a curated knowledge tree or runbook payload, so
#                       the exclusion is carried forward defensively rather than dropped as
#                       "not applicable here". The f2fs extension match is exact-suffix, so this
#                       covers `*.sqlite` only.
#                       NOTE what is deliberately NOT carried: the sibling recipe's prose also
#                       lists `nocompress_extension=sqlite-wal`/`sqlite-shm`, but f2fs caps
#                       extension names at 8 characters (`F2FS_EXTENSION_LEN`) and BOTH of those
#                       are 10 -- mounting with either present fails outright ("invalid extension
#                       length"), which is exactly why the vendored mount-opts list itself (the
#                       actual flags, not the prose describing them) never included them either.
#                       A SQLite WAL/SHM sidecar landing in this vault gets fs-mode compression
#                       like any other file; that is an accepted, documented gap, not an oversight.
#   flush_merge       -- coalesce flushes on slow flash
#   checkpoint_merge  -- coalesce checkpoints on slow flash
#   compress_cache    -- cache compressed blocks in RAM
#   fsync_mode=nobarrier -- fewer barriers for non-atomic files (NEVER the bare `nobarrier`
#                       mount option -- see STORAGE.md §4 step 2's own warning)
#   noatime,lazytime  -- skip/defer atime writes, one more class of needless flash write
#   nodiscard         -- no TRIM chatter on a slow USB controller; see this project's own
#                       modules/nixvault.nix header for why leaving already-written blocks
#                       un-discarded is exactly what makes the incremental-commit measurement
#                       in checks/lifecycle-vm-test.nix legible (nothing punches old blocks back
#                       to sparse holes out from under the very delta this test measures)
{
  mkfsFeatures = "extra_attr,inode_checksum,sb_checksum,compression";

  mountOptions = [
    "compress_algorithm=zstd:22"
    "compress_log_size=2"
    "compress_extension=*"
    "compress_chksum"
    "nocompress_extension=sqlite"
    "flush_merge"
    "checkpoint_merge"
    "compress_cache"
    "fsync_mode=nobarrier"
    "noatime"
    "lazytime"
    "nodiscard"
  ];
}
