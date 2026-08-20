# Proves the cluster module resolves what it claims and REFUSES what it claims to refuse, both
# directions, through the real renderer and the real app grammar.
#
# Both halves matter and neither is enough alone. A guard nobody has watched fire is a comment; a
# guard that fires on everything is a wall. So every case below is a complete, otherwise-valid
# surface with exactly one thing wrong, and the `control` case is the same shape with nothing wrong
# and MUST render -- without it, a typo in the shared base would make every other case "pass" for the
# wrong reason.
#
# THREE OF THE REFUSALS ARE NOT GUARDS AT ALL. Naming software the catalogue does not hold, leaving
# out the version, and declaring an archive with no namespace anywhere fail as a type error and as
# missing required options -- not as assertions. That is the stronger kind: a boundary nobody has to
# remember, because it is unwritable rather than refused. `tryEval` cannot tell those apart from a
# guard, so the ones that ARE guards additionally have their message asserted by content.
{ pkgs, lib, nixidy, appsModule, clusterModule, values }:

let
  base = import values;

  mkEnv = v: nixidy.lib.mkEnv {
    inherit pkgs;
    modules = [ appsModule clusterModule v ];
  };

  # `tryEval` alone forces only WHNF. Forcing the derivation path is what actually runs the module
  # system's type checks and the assertions underneath.
  renders = v: (builtins.tryEval (builtins.seq (mkEnv v).environmentPackage.drvPath true)).success;

  # An assertion fired, AND it is the one meant: a refusal that happens for an unrelated reason is a
  # false pass, which is exactly the failure this repository's checks exist to make impossible.
  failsWith = infix: v:
    let r = builtins.tryEval (lib.any
      (a: !a.assertion && lib.hasInfix infix a.message)
      (mkEnv v).config.nixidy.assertions);
    in r.success && r.value;

  # A surface with nothing declared at all, to prove the module is inert until something asks.
  emptyCfg = (mkEnv {
    nixidy.target.repository = "https://example.com/example-org/example-gitops.git";
    nixidy.target.branch = "main";
  }).config;

  goodCfg = (mkEnv base).config;

  with' = f: lib.recursiveUpdate base f;

  # The pieces of a second, standalone surface -- used to prove that the ONE thing separating a
  # rendering declaration from a refused one is the namespace, rather than asserting a refusal that
  # could have come from anywhere.
  target = {
    nixidy.target.repository = "https://example.com/example-org/example-gitops.git";
    nixidy.target.branch = "main";
    nixk3s.appPlatform.identities.example-archivist = { uid = 4242; gid = 4242; };
  };
  standalonePages = {
    nixvault.archives.example-pages = {
      app = "archivebox";
      version = "0.0.0";
      createNamespace = true;
      identityRole = "example-archivist";
      state.data.hostPath = "/example/state/pages-index";
      state.snapshots.hostPath = "/example/archive/pages";
    };
  };
  aNamespace.nixvault.clusterPlatform = {
    namespace = "example-archive";
    project = "example-keeping";
  };

  pages = goodCfg.nixk3s.apps.example-pages;
  videos = goodCfg.nixk3s.apps.example-videos;

  results = {
    # ── The control, and the floor ────────────────────────────────────────────────────────────
    "the example surface renders -- without this every refusal below could pass for the wrong reason" =
      renders base;

    "an undeclared surface renders no archives at all, rather than a default one" =
      emptyCfg.nixk3s.apps == { };

    "both declared archives reach the grammar" =
      lib.sort (a: b: a < b) (lib.attrNames goodCfg.nixk3s.apps)
        == [ "example-pages" "example-videos" ];

    "the catalogue supplies the port, and the declaration never states one" =
      pages.ports.http.number == 8000 && videos.ports.http.number == 8000;

    "a version becomes the tag, and a whole reference overrides it" =
      pages.image == "ghcr.io/archivebox/archivebox:0.0.0"
      && lib.hasInfix "@sha256:" videos.image;

    "the catalogue supplies WHERE a directory lives and the declaration supplies WHAT BACKS IT" =
      pages.state.data.mountPath == "/data"
      && pages.state.data.claim == "example-pages-index"
      && pages.state.snapshots.mountPath == "/data/archive"
      && pages.state.snapshots.hostPath == "/example/archive/pages";

    "an archive nested inside another sorts after it, so the outer mount is written first" =
      lib.attrNames pages.state == [ "data" "snapshots" ];

    "a directory the cluster already had a name for reaches the grammar under THAT name" =
      videos.state ? videos
      && !(videos.state ? media)
      && videos.state.videos.mountPath == "/youtube"
      && videos.state.videos.hostPath == "/example/archive/videos";

    "and one that was never renamed keeps the catalogue's own name" =
      pages.state ? snapshots && videos.state ? cache;

    "the kubelet may own a bounded directory and is kept off the growing one" =
      pages.state.data.ownership == "kubelet"
      && pages.state.snapshots.ownership == "site-curated";

    "a directory is backed strictly by default, so an archive cannot come up against an empty one" =
      pages.state.snapshots.hostPathType == "Directory";

    "the catalogue names the variable a companion is reached through, the declaration names the URL" =
      videos.env.ES_URL == "http://example-index:9200"
      && videos.env.REDIS_CON == "redis://example-queue:6379";

    "an archive that must know its own address is told it, under the variable the catalogue names" =
      videos.env.TA_HOST == "https://videos.example.com";

    "what the software itself decides comes from the catalogue, not the declaration" =
      videos.env.TA_USERNAME == "admin";

    "a credential is named key by key and never carried" =
      videos.secrets.example-videos-credentials.secret == "example-videos-credentials"
      && videos.secrets.example-videos-credentials.env.ELASTIC_PASSWORD == "index-password"
      && videos.secrets.example-videos-credentials.env.TA_PASSWORD == "admin-password"
      && !videos.secrets.example-videos-credentials.envFrom;

    "an image that drops its own privileges takes a role and reads its ids from the environment" =
      pages.identity == "example-archivist"
      && pages.identityEnv.user == "PUID"
      && pages.identityEnv.group == "PGID";

    "an image that stays uid 0 says so in the grammar's reserved word instead" =
      videos.identity == "root" && videos.identityEnv.user == null;

    "the restrictions an archive tolerates come from the catalogue, and silence stays silence" =
      pages.security.seccomp == "RuntimeDefault"
      && pages.security.allowPrivilegeEscalation == false
      && pages.security.capabilitiesDrop == [ ]
      && videos.security.seccomp == null;

    "neither archive is probed, because the catalogue records no budget rather than guessing one" =
      pages.probes.readiness == null && videos.probes.readiness == null;

    "an archive is always resident" =
      pages.scaling == "always" && videos.scaling == "always";

    "whether the objects were already there is the declaration's to say, and reaches the grammar" =
      videos.adopt && !pages.adopt;

    # ── Unwritable, not merely refused ────────────────────────────────────────────────────────
    "software the catalogue does not hold is not a value this option has" =
      !renders (with' { nixvault.archives.example-pages.app = "nonesuch"; });

    "a workload with no version is refused, because a floating tag is not a default anyone can pick" =
      !renders (target // aNamespace // {
        nixvault.archives.x = { app = "archivebox"; };
      });

    "an archive with no namespace anywhere is refused" =
      !renders (lib.recursiveUpdate target standalonePages);

    "and the SAME surface renders once a namespace exists -- the namespace is the only difference" =
      renders (lib.recursiveUpdate (lib.recursiveUpdate target aNamespace) standalonePages);

    # ── The guards, each with its message asserted ────────────────────────────────────────────
    "backing a directory the archive does not keep is refused" =
      failsWith "must back every directory it keeps"
        (with' { nixvault.archives.example-pages.state.nope.hostPath = "/example/nope"; });

    "leaving a directory it DOES keep unbacked is refused" =
      failsWith "must back every directory it keeps"
        (with' { nixvault.archives.example-videos.state = lib.mkForce { }; });

    "a directory backed by both a claim and a node path is refused" =
      failsWith "never both and never neither"
        (with' { nixvault.archives.example-pages.state.snapshots.claim = "example-claim"; });

    "renaming two directories onto one volume name is refused" =
      failsWith "ONE name"
        (with' { nixvault.archives.example-videos.state.cache.volumeName = "videos"; });

    "handing a GROWING directory to the kubelet is refused" =
      failsWith "hands a GROWING directory"
        (with' { nixvault.archives.example-pages.state.snapshots.ownership = "kubelet"; });

    "leaving a workload it needs unnamed is refused" =
      failsWith "must say where every workload it needs"
        (with' { nixvault.archives.example-videos.requires = lib.mkForce { }; });

    "reaching a workload it needs over the wrong protocol is refused" =
      failsWith "wrong protocol"
        (with' { nixvault.archives.example-videos.requires.queue.endpoint = "http://example-queue:6379"; });

    "an endpoint that is a literal address is refused" =
      failsWith "at a literal ADDRESS"
        (with' { nixvault.archives.example-videos.requires.index.endpoint = "http://192.0.2.10:9200"; });

    "leaving a credential the software requires unsourced is refused" =
      failsWith "must source every credential"
        (with' {
          nixvault.archives.example-videos.credentials = lib.mkForce {
            ELASTIC_PASSWORD = { secret = "example-videos-credentials"; key = "index-password"; };
          };
        });

    "an archive that must be told its own URL and is not is refused" =
      failsWith "must be told the URL it is reached at"
        (with' { nixvault.archives.example-videos.publicUrl = lib.mkForce null; });

    "an archive that has no use for a URL and is given one is refused" =
      failsWith "has no use for one"
        (with' { nixvault.archives.example-pages.publicUrl = "https://pages.example.com"; });

    "an archive told it lives at a literal address is refused" =
      failsWith "told it lives at a literal ADDRESS"
        (with' { nixvault.archives.example-videos.publicUrl = lib.mkForce "https://198.51.100.7"; });

    "an image that reads its ids from the environment and is given no role is refused" =
      failsWith "must name the role whose ids it runs under"
        (with' { nixvault.archives.example-pages.identityRole = lib.mkForce null; });

    "an image that can only be uid 0 and is given a role is refused" =
      failsWith "has no way to be anyone else"
        (with' { nixvault.archives.example-videos.identityRole = "example-archivist"; });

    "an archive declared scale-to-zero is refused rather than warned about" =
      failsWith "does its real work"
        (with' { nixvault.archives.example-videos.scaling = "scale-to-zero"; });

    "two archives anchoring one namespace is refused" =
      failsWith "Exactly one workload may create a namespace"
        (with' { nixvault.archives.example-videos.createNamespace = true; });

    "two archives on one slot is refused" =
      failsWith "is claimed by 2 archives"
        (with' { nixvault.archives.example-videos.slot = 12; });

    # ── The warnings that are not refusals ────────────────────────────────────────────────────
    # A slot with nothing to range-check it, and a whole image reference that silently retires the
    # version beside it, are both real mistakes and neither is an eval error: the first is a fact
    # this repository cannot see, and the second is exactly what a digest pin is supposed to look
    # like.
    "a slot claimed with no origin warns rather than refuses" =
      lib.any (w: w.when && lib.hasInfix "by nothing for which RANGE" w.message) goodCfg.nixidy.warnings;

    "a whole image reference warns that the version beside it now chooses nothing" =
      lib.any (w: w.when && lib.hasInfix "documentation only" w.message) goodCfg.nixidy.warnings;

    # A rename that puts a nested pair in the wrong order is the one place this module warns about
    # something it would rather refuse. The order is a property of the RENDERED object and pinning it
    # belongs to whoever renders -- refusing here would make a live workload whose objects already
    # carry those names unadoptable, and the cure (delete and recreate a single-writer archive) is
    # worse than the disease it is guarding against.
    "renaming a directory so it sorts before the one that covers it warns, and still renders" =
      let v = with' { nixvault.archives.example-pages.state.snapshots.volumeName = "aaa-archive"; }; in
      renders v
      && lib.any
        (w: w.when && lib.hasInfix "sort the wrong way round" w.message)
        (mkEnv v).config.nixidy.warnings;

    "and the same declaration under a name that sorts correctly warns about nothing of the kind" =
      !(lib.any
        (w: w.when && lib.hasInfix "sort the wrong way round" w.message)
        goodCfg.nixidy.warnings);
  };

  failed = lib.filter (n: !results.${n}) (lib.attrNames results);
in
pkgs.runCommand "nixvault-cluster-eval" { } (
  if failed == [ ]
  then ''
    echo "nixvault: all ${toString (lib.length (lib.attrNames results))} cluster-eval properties hold"
    touch $out
  ''
  else ''
    echo "nixvault cluster-eval FAILED (${toString (lib.length failed)}/${toString (lib.length (lib.attrNames results))}):" >&2
    ${lib.concatMapStringsSep "\n" (n: ''echo "  - ${n}" >&2'') failed}
    exit 1
  ''
)
