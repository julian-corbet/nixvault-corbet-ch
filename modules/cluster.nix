#
# nixvault's cluster surface: declare which archives run in the cluster, and render them.
#
# ── THIS MODULE DOES NOT IMPLEMENT KUBERNETES, AND THAT IS THE DESIGN ──────────────────────────
#
# A sibling repository's whole subject is the app grammar: a workload declares WHAT IT NEEDS — an
# image, ports, an exposure class, which directories it keeps and what backs them — and that grammar
# renders the Argo CD Application, the Namespace, the Deployment and the Service. Everything
# expressible in those terms is expressed in them: this module DEFINES INTO `nixk3s.apps` and
# renders no Kubernetes object of its own.
#
# So it is a translator. What it adds is the one thing the grammar cannot know: what an ARCHIVE is.
# That a directory is the archive itself rather than a working copy, and therefore grows forever and
# must not be recursively chowned on every start. That a workload which does its real work between
# requests must not be idled away. That an application which drops privileges by itself takes its
# identity as environment rather than as a security context, because an image that must start as
# root cannot also be told not to.
#
# IMPORT THE GRAMMAR ALONGSIDE IT. `nixk3s.apps` is declared there, not here, and a render that
# composes this module without it fails with "the option `nixk3s.apps' does not exist".
#
# ── THE KNOWLEDGE/VALUE SPLIT, ENFORCED RATHER THAN TRUSTED ────────────────────────────────────
#
# `lib/archives.nix` holds what is true of the software anywhere. A declaration holds what is true of
# one cluster. Neither side can supply the other's half, and every guard below is one seam of that
# split made into an eval error:
#
#   the catalogue says WHERE a directory lives inside the container   — a declaration says WHAT BACKS IT
#   the catalogue says WHICH DIRECTORIES the software keeps           — a declaration says WHAT EACH ONE IS CALLED
#   the catalogue says WHICH VARIABLE a companion's URL is read from  — a declaration says WHAT THAT URL IS
#   the catalogue says WHICH VARIABLE must carry a credential         — a declaration says WHICH SECRET HOLDS IT
#   the catalogue says the image reads its ids from the environment   — a declaration says WHICH IDENTITY
#
# A workload declared with the other half missing is refused, rather than quietly rendered onto a
# pod's own filesystem, against a service that does not exist, or without the credential it needs.
{ config, lib, ... }:

let
  cfg = config.nixvault;
  platform = cfg.clusterPlatform;
  catalogue = (import ../lib/archives.nix { }).archives;

  declared = lib.filterAttrs (_: w: w.enable) cfg.archives;
  workloads = lib.mapAttrsToList (name: w: { inherit name w; entry = catalogue.${w.app}; }) declared;

  # A whole reference wins over a repository plus a tag, which is what pinning by digest looks like.
  # The catalogue never carries either: a version is a deployment's choice and a digest is one
  # deployment's proof of what it is running.
  imageOf = entry: w: if w.image != null then w.image else "${entry.image}:${w.version}";

  portsOf = entry: lib.mapAttrs (_: number: { inherit number; }) entry.ports;

  # WHAT A DIRECTORY IS CALLED once it is an object in a cluster. The catalogue's key is this
  # repository's name for a directory and it is what a declaration writes against; the name the
  # rendered volume carries is a fact about ONE cluster's objects, which is why a declaration may
  # say it and the catalogue may not. Left unsaid, the two are the same word.
  nameOf = w: key: if w.state.${key}.volumeName != null then w.state.${key}.volumeName else key;

  # The split in one function: WHERE inside the container comes from the catalogue, WHAT BACKS IT
  # and WHAT IT IS CALLED come from the declaration, and neither side can supply the other's half.
  stateOf = entry: w:
    lib.mapAttrs'
      (key: backing:
        lib.nameValuePair (nameOf w key) {
          inherit (entry.state.${key}) mountPath;
          inherit (backing) claim hostPath hostPathType readOnly ownership;
        })
      w.state;

  # Where a companion workload is. The VARIABLE is the catalogue's, the URL is the declaration's, and
  # the app never learns that either of them was assembled from two sources.
  requiresEnvOf = entry: w:
    lib.mapAttrs' (key: r: lib.nameValuePair entry.requires.${key}.env r.endpoint) w.requires;

  selfEnvOf = entry: w:
    lib.optionalAttrs (entry.selfUrlEnv != null && w.publicUrl != null) {
      ${entry.selfUrlEnv} = w.publicUrl;
    };

  # Credentials, grouped by the Secret that holds them. Nothing here can carry a secret's CONTENT,
  # which is what makes a declaration written against this module safe to publish — and they are
  # taken KEY BY KEY rather than wholesale, so a key added to that Secret later cannot land in the
  # process environment unannounced.
  credentialsOf = w:
    let
      entries = lib.mapAttrsToList (variable: c: { inherit variable; inherit (c) secret key; }) w.credentials;
      bySecret = lib.groupBy (c: c.secret) entries;
    in
    lib.mapAttrs
      (secretName: cs: {
        secret = secretName;
        env = lib.listToAttrs (map (c: lib.nameValuePair c.variable c.key) cs);
      })
      bySecret;

  # WHO THE POD IS, in the grammar's own terms rather than in numbers. An image that drops its own
  # privileges is handed a ROLE, whose ids the site's own registry resolves and which this module
  # delivers as environment because the image must still start as root. An image that stays root
  # says so out loud with the grammar's reserved word, so the exception is countable.
  identityOf = entry: w:
    if entry.identityEnv != null then { identity = w.identityRole; identityEnv = entry.identityEnv; }
    else if entry.rootStart then { identity = "root"; }
    else lib.optionalAttrs (w.identityRole != null) { identity = w.identityRole; };

  probesOf = entry:
    lib.optionalAttrs (entry.readiness != null) {
      readiness = { port = entry.primaryPort; } // entry.readiness;
    };

  # Handed to the band model only when the consumer says it is part of the render: `origin` and
  # `slot` are ITS terms, and defining them into a render that does not declare them is an eval
  # error rather than a graceful no-op.
  addressingOf = w:
    lib.optionalAttrs (platform.origin != null) {
      origin = platform.origin;
      inherit (w) slot;
    };

  mkApp = x:
    let inherit (x) entry w; in
    {
      inherit (w) namespace createNamespace project exposure scaling;
      image = imageOf entry w;
      ports = portsOf entry;
      state = stateOf entry w;
      secrets = credentialsOf w;
      env = entry.env // requiresEnvOf entry w // selfEnvOf entry w // w.env;
      args = entry.args ++ w.args;
      probes = probesOf entry;
      security = entry.security;
    }
    // identityOf entry w
    // addressingOf w;

  # ── The address test ──────────────────────────────────────────────────────────────────────────
  #
  # A URL in a declaration names a SERVICE. An address is a fact about one network on one day, and a
  # workload that has been handed one has been handed something that will be wrong later and wrong
  # silently — the connection simply stops being answered. Refusing the literal is also what keeps a
  # declaration written against this module publishable.
  authorityOf = url:
    lib.head (lib.splitString "/" (lib.last (lib.splitString "://" url)));
  hostOf = url: lib.head (lib.splitString ":" (lib.last (lib.splitString "@" (authorityOf url))));

  digits = lib.stringToCharacters "0123456789";
  isAddress = url:
    let host = hostOf url; in
    # A bracketed authority is IPv6 and nothing else; the rest is the dotted-quad test, which needs
    # the dot as well as the digits — a bare number is a name somebody is allowed to have.
    lib.hasPrefix "[" (authorityOf url)
    || (host != ""
        && lib.hasInfix "." host
        && lib.all (c: c == "." || lib.elem c digits) (lib.stringToCharacters host));

  # ── Assertions ────────────────────────────────────────────────────────────────────────────────

  # Keys BOTH sides know about. The guard that catches a directory only one side has is the first
  # one below; every guard after it indexes the catalogue by a declaration's key, so it must walk
  # the intersection or it throws a missing-attribute error while the assertion written to explain
  # the mistake is still being collected.
  sharedKeys = declaredSide: catalogueSide:
    lib.filter (k: catalogueSide ? ${k}) (lib.attrNames declaredSide);

  stateAssertions = lib.concatMap
    (x:
      let inherit (x) name w entry; in
      [
        {
          assertion = lib.attrNames w.state == lib.attrNames entry.state;
          message =
            "nixvault: archive `${name}` must back every directory it keeps, and backs "
            + (if w.state == { } then "none" else lib.concatMapStringsSep ", " (k: "`${k}`") (lib.attrNames w.state))
            + ". It keeps: "
            + (if entry.state == { } then "nothing"
               else lib.concatStringsSep ", " (lib.mapAttrsToList (k: s: "`${k}` at ${s.mountPath}") entry.state))
            + ".";
        }
        {
          assertion = lib.all
            (backing: (backing.claim == null) != (backing.hostPath == null))
            (lib.attrValues w.state);
          message =
            "nixvault: archive `${name}` must back each directory with EITHER an existing claim OR a "
            + "node path, never both and never neither. A directory with no backing is a pod's own "
            + "filesystem, which is discarded on the next restart — and an archive is the only copy "
            + "of what it holds.";
        }
        {
          assertion =
            lib.length (lib.unique (map (key: nameOf w key) (lib.attrNames w.state)))
              == lib.length (lib.attrNames w.state);
          message =
            "nixvault: archive `${name}` gives two of the directories it keeps ONE name ("
            + lib.concatMapStringsSep ", " (k: "`${k}` -> `${nameOf w k}`") (lib.attrNames w.state)
            + "). A volume name is the identity of the storage inside the pod, so two of them wearing "
            + "one name is not a merge — it is one directory rendered and the other silently gone, "
            + "and for an archive the one that vanishes is a copy nobody has anywhere else.";
        }
        {
          assertion = lib.all
            (key: !(entry.state.${key}.grows && w.state.${key}.ownership == "kubelet"))
            (sharedKeys w.state entry.state);
          message =
            "nixvault: archive `${name}` hands a GROWING directory to the kubelet to own. Taking "
            + "ownership means changing it recursively on every single pod start, over a tree that is "
            + "bigger every time — unbounded work in the startup path, and it overwrites whatever "
            + "ownership was set outside the cluster on a tree somebody curates there.";
        }
      ])
    workloads;

  # Every pair of directories where one is mounted INSIDE the other, read off the catalogue's mount
  # paths. The rendered mount list is emitted in attribute order, so the outer mount has to be
  # written first: lay the outer one on top of the inner one and the archive is still on the disk and
  # the application can no longer see it. Two things are checked against this — the catalogue's own
  # key names, and whatever a declaration renames them to.
  nestedPairs = entry:
    let
      keys = lib.attrNames entry.state;
      pathOf = k: entry.state.${k}.mountPath;
    in
    lib.concatMap
      (outer: lib.concatMap
        (inner:
          lib.optional
            (outer != inner && lib.hasPrefix "${pathOf outer}/" (pathOf inner))
            { inherit outer inner; })
        keys)
      keys;

  # THIS ONE READS THE CATALOGUE, not a declaration: it is a guard against a rename in THIS
  # repository, which is exactly the change that would look harmless. Nobody downstream asked for it
  # and nobody downstream can see it coming, so it is an error rather than a warning.
  nestingAssertions = lib.concatMap
    (x:
      let
        inherit (x) name entry;
        pathOf = k: entry.state.${k}.mountPath;
        covered = lib.filter (c: c.outer > c.inner) (nestedPairs entry);
      in
      map
        (c: {
          assertion = false;
          message =
            "nixvault: the catalogue mounts `${c.inner}` (${pathOf c.inner}) INSIDE `${c.outer}` "
            + "(${pathOf c.outer}) for `${x.w.app}`, and the names sort the wrong way round. Mounts "
            + "are rendered in attribute order, so `${c.inner}` would be written first and "
            + "`${c.outer}` laid on top of it — the archive is still on the disk and the application "
            + "can no longer see it. Rename the keys in lib/archives.nix so the outer one sorts "
            + "first (archive `${name}` is what surfaced it).";
        })
        covered)
    workloads;

  requiresAssertions = lib.concatMap
    (x:
      let inherit (x) name w entry; in
      [
        {
          assertion = lib.attrNames w.requires == lib.attrNames entry.requires;
          message =
            "nixvault: archive `${name}` must say where every workload it needs can be reached, and "
            + "gives "
            + (if w.requires == { } then "none" else lib.concatMapStringsSep ", " (k: "`${k}`") (lib.attrNames w.requires))
            + ". It needs: "
            + (if entry.requires == { } then "nothing"
               else lib.concatStringsSep ", " (lib.mapAttrsToList (k: r: "`${k}` (read from ${r.env})") entry.requires))
            + ".";
        }
        {
          assertion = lib.all
            (key: lib.hasPrefix "${entry.requires.${key}.scheme}://" w.requires.${key}.endpoint)
            (sharedKeys w.requires entry.requires);
          message =
            "nixvault: archive `${name}` reaches one of the workloads it needs over the wrong "
            + "protocol. Each endpoint must be a `<scheme>://` URL of the scheme the catalogue names "
            + "("
            + lib.concatStringsSep ", " (lib.mapAttrsToList (k: r: "`${k}` speaks ${r.scheme}") entry.requires)
            + "), because the client library is chosen by the software, not by the deployment.";
        }
        {
          assertion = lib.all (key: !(isAddress w.requires.${key}.endpoint)) (lib.attrNames w.requires);
          # (no catalogue lookup here, so every declared key is safe to walk)
          message =
            "nixvault: archive `${name}` reaches a workload it needs at a literal ADDRESS. An "
            + "endpoint names a service; an address is one network on one day, and a workload holding "
            + "a stale one fails silently rather than loudly.";
        }
      ])
    workloads;

  credentialAssertions = lib.concatMap
    (x:
      let inherit (x) name w entry; in
      [
        {
          assertion = lib.attrNames w.credentials == entry.credentials;
          message =
            "nixvault: archive `${name}` must source every credential the software requires, and "
            + "sources "
            + (if w.credentials == { } then "none" else lib.concatMapStringsSep ", " (k: "`${k}`") (lib.attrNames w.credentials))
            + ". It requires: "
            + (if entry.credentials == [ ] then "none"
               else lib.concatMapStringsSep ", " (v: "`${v}`") entry.credentials)
            + ".";
        }
      ])
    workloads;

  selfUrlAssertions = lib.concatMap
    (x:
      let inherit (x) name w entry; in
      [
        {
          assertion = (entry.selfUrlEnv != null) == (w.publicUrl != null);
          message =
            if entry.selfUrlEnv == null
            then
              "nixvault: archive `${name}` is given a `publicUrl` and has no use for one. The software "
              + "does not read its own address from anywhere, so the value would be dropped."
            else
              "nixvault: archive `${name}` must be told the URL it is reached at (it reads "
              + "`${entry.selfUrlEnv}`). It builds absolute links with that value, so an archive left "
              + "to guess is an archive whose links work nowhere a person actually browses it.";
        }
        {
          assertion = w.publicUrl == null || !(isAddress w.publicUrl);
          message =
            "nixvault: archive `${name}` is told it lives at a literal ADDRESS. A `publicUrl` is the "
            + "name people reach it by, and it ends up baked into links that outlive the network it "
            + "was written on.";
        }
      ])
    workloads;

  identityAssertions = lib.concatMap
    (x:
      let inherit (x) name w entry; in
      [
        {
          assertion = entry.identityEnv == null || w.identityRole != null;
          message =
            "nixvault: archive `${name}` takes its identity from the environment (the image reads "
            + "`${if entry.identityEnv == null then "" else entry.identityEnv.user}`), so the "
            + "declaration must name the role whose ids it runs under. WHICH identity that is, is a "
            + "fact about the site, and it is the one thing this repository cannot know.";
        }
        {
          assertion = !(entry.rootStart && entry.identityEnv == null) || w.identityRole == null;
          message =
            "nixvault: archive `${name}` is given an identity role and the image has no way to be "
            + "anyone else — it runs as uid 0 and stays there. Naming a role it cannot take renders "
            + "an identity the pod ignores, which is worse than none: the tree then says it runs as "
            + "somebody it does not.";
        }
      ])
    workloads;

  scalingAssertions = lib.concatMap
    (x:
      let inherit (x) name w entry; in
      [
        {
          assertion = entry.idleSafe || w.scaling == "always";
          message =
            "nixvault: archive `${name}` is declared scale-to-zero and this one does its real work "
            + "BETWEEN requests — the catalogue records that. A front that scales it away when the "
            + "last request finishes takes the running job with it, and what an archive was fetching "
            + "may not be there on the next attempt.";
        }
      ])
    workloads;

  # A namespace outlives every workload in it, so exactly one thing may own it. Two anchors is not a
  # merge, it is two Namespace objects Argo will fight over.
  anchorAssertions =
    let
      anchors = lib.filter (x: x.w.createNamespace) workloads;
      byNs = lib.groupBy (x: x.w.namespace) anchors;
    in
    lib.mapAttrsToList
      (ns: xs: {
        assertion = lib.length xs == 1;
        message =
          "nixvault: namespace `${ns}` is anchored by ${toString (lib.length xs)} archives ("
          + lib.concatMapStringsSep ", " (x: "`${x.name}`") xs
          + "). Exactly one workload may create a namespace.";
      })
      byNs;

  slotAssertions =
    let
      claimed = lib.filter (x: x.w.slot != null) workloads;
      bySlot = lib.groupBy (x: toString x.w.slot) claimed;
    in
    lib.mapAttrsToList
      (slot: xs: {
        assertion = lib.length xs == 1;
        message =
          "nixvault: slot ${slot} is claimed by ${toString (lib.length xs)} archives ("
          + lib.concatMapStringsSep ", " (x: "`${x.name}`") xs
          + "). A slot is one identity in several address spaces at once; two workloads on one number "
          + "is two workloads on one address.";
      })
      bySlot;

  # A warning is `{ when; message; }` — the renderer decides whether to print it, so the condition
  # travels with the text rather than being applied here.
  warnings = lib.concatMap
    (x:
      let
        inherit (x) name w entry;
        inverted = lib.filter (c: nameOf w c.outer > nameOf w c.inner) (nestedPairs entry);
      in
      map
        (c: {
          when = true;
          message =
            "nixvault: archive `${name}` calls `${c.inner}` (${entry.state.${c.inner}.mountPath}) "
            + "`${nameOf w c.inner}` and `${c.outer}` (${entry.state.${c.outer}.mountPath}) "
            + "`${nameOf w c.outer}`, and those names sort the wrong way round. Mounts are emitted in "
            + "attribute-name order, so the inner one is written FIRST and the outer one is laid on "
            + "top of it: the archive stays on the disk and the application stops being able to see "
            + "it. That is not refused here, because the order is a property of the rendered object "
            + "and pinning it is the consumer's — but an unpinned render of these names archives into "
            + "the wrong directory silently. Either pin the order where the objects are rendered, or "
            + "take the names the catalogue already sorts correctly.";
        })
        inverted
      ++ [
        {
          when = w.slot != null && platform.origin == null;
          message =
            "nixvault: archive `${name}` claims slot ${toString w.slot}, and "
            + "`nixvault.clusterPlatform.origin` is unset — so the number is checked for collisions "
            + "inside this repository and by nothing for which RANGE it may come from.";
        }
        {
          when = w.image != null;
          message =
            "nixvault: archive `${name}` carries a whole image reference, so its `version` chooses "
            + "nothing and is documentation only. Keeping the two in step is then a person's job, and "
            + "a version that disagrees with the digest beside it is how a tree comes to describe "
            + "software it is not running.";
        }
      ])
    workloads;

  commonOptions = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Whether to render this workload. Declaring the attribute is declaring the workload, so this
        defaults to true; set false to park a declaration without rendering it.
      '';
    };

    namespace = lib.mkOption {
      type = lib.types.str;
      default = platform.namespace;
      defaultText = lib.literalExpression "config.nixvault.clusterPlatform.namespace";
      description = "Namespace this archive lands in.";
    };

    createNamespace = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Whether this workload anchors its namespace. Defaults to false, because archives share one
        namespace by default and exactly one of them may own it.
      '';
    };

    project = lib.mkOption {
      type = lib.types.str;
      default = platform.project;
      defaultText = lib.literalExpression "config.nixvault.clusterPlatform.project";
      description = "Delivery project this workload's Application belongs to.";
    };

    slot = lib.mkOption {
      type = lib.types.nullOr lib.types.ints.unsigned;
      default = null;
      description = ''
        THE POSITION this workload holds in the fleet's ordered identity space. Not an address — the
        layers underneath map it into however many address spaces the fleet keeps, which is why
        nothing here moves one. The VALUE is a fleet fact and belongs to the consumer.
      '';
    };

    exposure = lib.mkOption {
      type = lib.types.enum [ "internal" "nb" "public" ];
      default = "internal";
      description = ''
        Who can reach it, as a CLASS rather than an address. Defaults to the closed answer, which for
        an archive is also the conservative one: what somebody chose to keep is a record of what they
        read, and it is not on the internet until somebody says so.
      '';
    };

    scaling = lib.mkOption {
      type = lib.types.enum [ "always" "scale-to-zero" ];
      default = "always";
      description = ''
        Whether the workload may idle to zero replicas.

        The catalogue records whether sleeping is SAFE for a given archive — whether it does work
        between requests, which is what makes zero replicas lossy rather than merely cold — and
        declaring the unsafe combination is refused rather than warned about. An interrupted archive
        run is not a slow request; it is a page that may not be there tomorrow.
      '';
    };

    identityRole = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "example-archivist";
      description = ''
        WHICH IDENTITY this workload runs as, named as a ROLE rather than as a number. The catalogue
        knows whether the image can be anybody at all; which user that is, is a fact about the site,
        and the numbers behind the name come from the renderer's own identity registry.

        Required for an image the catalogue says reads its ids from the environment, and refused for
        one it says runs as uid 0 and stays there.
      '';
    };

    state = lib.mkOption {
      default = { };
      description = ''
        What backs each directory the catalogue says this archive keeps, and what each one is called
        once it is an object in a cluster, keyed by the catalogue's OWN names. Backing a directory it
        does not keep, or leaving one it does keep unbacked, is an eval error rather than a surprise
        at runtime.
      '';
      type = lib.types.attrsOf (lib.types.submodule {
        options = {
          claim = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            default = null;
            description = "An existing PersistentVolumeClaim, by name. Nothing here creates one.";
          };
          hostPath = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            default = null;
            description = "A directory on the node. Pins the workload to whichever node holds it.";
          };
          hostPathType = lib.mkOption {
            type = lib.types.str;
            default = "Directory";
            description = ''
              The hostPath type, when a node path is what backs it. Defaults to the STRICT value:
              `DirectoryOrCreate` on an archive is how a workload comes up cheerfully against an
              empty directory and starts a second, empty archive beside the real one.
            '';
          };
          readOnly = lib.mkOption {
            type = lib.types.bool;
            default = false;
            description = "Whether the mount is read-only.";
          };
          ownership = lib.mkOption {
            type = lib.types.enum [ "site-curated" "kubelet" ];
            default = "site-curated";
            description = ''
              Who owns the files. `site-curated` (the default) means nothing in the cluster touches
              them; `kubelet` means the kubelet takes group ownership, which it does by changing the
              tree recursively on EVERY pod start. Asking for that on a directory the catalogue says
              grows without bound is refused.
            '';
          };
          volumeName = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            default = null;
            defaultText = lib.literalExpression "the catalogue's own name for the directory";
            example = "media";
            description = ''
              WHAT THIS DIRECTORY IS CALLED as an object in the cluster, when it is already called
              something. The catalogue's key is this repository's name for a directory — the word a
              declaration writes against — and by default it is also the name the rendered volume and
              its mount carry. They are not the same kind of fact: the application never learns
              either, and the second one is whatever somebody typed the day the workload was first
              created.

              THIS EXISTS TO ADOPT A RUNNING WORKLOAD WITHOUT MOVING IT. A volume name lives inside
              the pod template, so changing one is a new pod template, which for an archive — never
              two replicas, never a rolling update — means the running copy stops before its
              replacement starts. Somebody who already runs this software under other names can put
              them here and get the manifest they already have, byte for byte, instead of trading
              downtime for a spelling.

              Two directories may not resolve to one name, and a rename that makes a nested pair sort
              the wrong way round is warned about loudly: mounts are emitted in name order, and an
              inner mount written first is an archive the application cannot see.
            '';
          };
        };
      });
    };

    requires = lib.mkOption {
      default = { };
      description = ''
        Where each workload this archive needs can be reached, keyed by the SAME names the catalogue
        uses. The catalogue says which variable carries the URL and which protocol is spoken; this
        says what the URL is. Nothing here renders those workloads — they have their own lifecycles,
        their own storage and their own owners.
      '';
      type = lib.types.attrsOf (lib.types.submodule {
        options = {
          endpoint = lib.mkOption {
            type = lib.types.str;
            example = "http://example-index:9200";
            description = ''
              The URL, naming a service. A literal address is refused: an address is one network on
              one day, and a workload holding a stale one fails silently.
            '';
          };
        };
      });
    };

    credentials = lib.mkOption {
      default = { };
      description = ''
        Where each credential the software requires comes from, keyed by the environment variable
        name the catalogue lists. Sourced key by key rather than wholesale, so a key added to the
        Secret later cannot land in the process environment unannounced.

        Named rather than carried: nothing in this repository can hold a secret's contents, which is
        what makes a declaration written here publishable.
      '';
      type = lib.types.attrsOf (lib.types.submodule ({ name, ... }: {
        options = {
          secret = lib.mkOption {
            type = lib.types.str;
            description = "Name of an existing Secret. Nothing here creates one.";
          };
          key = lib.mkOption {
            type = lib.types.str;
            default = name;
            defaultText = lib.literalExpression "the variable's own name";
            description = "Which key inside that Secret holds the value.";
          };
        };
      }));
    };

    publicUrl = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "https://archive.example.com";
      description = ''
        The URL people reach this archive at, for software the catalogue says must be told its own
        address. Required for exactly those, refused for the rest, and refused as a literal address:
        it is baked into links that outlive the network it was written on.
      '';
    };

    env = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
      description = ''
        Environment this deployment adds, merged over whatever the catalogue sets. Values only —
        anything secret is named in `credentials` and arrives from a Secret.
      '';
    };

    args = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Arguments appended to whatever the catalogue sets.";
    };

    image = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        A whole image reference, overriding the catalogue's repository and this workload's version.
        This is where a digest pin goes, and pinning by digest is what makes two syncs of an
        identical rendered tree run identical code.
      '';
    };
  };
in
{
  options.nixvault.clusterPlatform = {
    namespace = lib.mkOption {
      type = lib.types.str;
      description = ''
        Namespace these archives share unless a declaration says otherwise. DEFAULTED NOWHERE: a
        namespace is one cluster's tenancy decision, and a repository that guesses one is a
        repository that puts somebody's archive next to something they never chose.
      '';
    };

    project = lib.mkOption {
      type = lib.types.str;
      description = "Delivery project their Applications belong to unless a declaration says otherwise.";
    };

    origin = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        THE IDENTITY THIS REPOSITORY'S APPS ARE ADDRESSED UNDER, when the render composes the band
        model. A repository naming itself is not a fleet fact; which band that name binds is, and it
        lives in whatever repository owns the fleet. Left null, slots are still checked for
        collisions here and by nothing for range.
      '';
    };
  };

  options.nixvault.archives = lib.mkOption {
    default = { };
    description = ''
      The archives that run in the cluster, keyed by a name of your choosing.

      THE ENUM IS THE HOUSE RULE. It is built from `lib/archives.nix`, so software this repository
      does not catalogue is not a refused value here — it is not a value. What belongs in that
      catalogue is archival: keeping a copy of something so it survives the original. A backup of a
      live system is a different promise and has a different owner.
    '';
    example = lib.literalExpression ''
      {
        example-pages = {
          app = "archivebox";
          version = "0.0.0";
          createNamespace = true;
          exposure = "nb";
          identityRole = "example-archivist";
          state.data.hostPath = "/example/state/pages";
          state.snapshots.hostPath = "/example/archive/pages";
        };
      }
    '';
    type = lib.types.attrsOf (lib.types.submodule ({ name, ... }: {
      options = commonOptions // {
        app = lib.mkOption {
          type = lib.types.enum (lib.attrNames catalogue);
          description = "Which archive, from the catalogue. Available: ${lib.concatStringsSep ", " (lib.attrNames catalogue)}.";
        };

        version = lib.mkOption {
          type = lib.types.str;
          description = "Which version this workload runs, used as the image tag. Required, and defaulted nowhere.";
        };
      };
    }));
  };

  # ── Computed, read-only ───────────────────────────────────────────────────────────────────────
  options.nixvault.clusterSlots = lib.mkOption {
    type = lib.types.attrsOf lib.types.ints.unsigned;
    readOnly = true;
    default = lib.listToAttrs
      (map (x: lib.nameValuePair x.name x.w.slot) (lib.filter (x: x.w.slot != null) workloads));
    defaultText = lib.literalExpression "every declared workload that claims a slot";
    description = ''
      workload -> the position it claims. Nothing is rendered from it here: what an address looks
      like is the private layer's business, and this is what that layer reads to build one.
    '';
  };

  config = {
    nixk3s.apps = lib.listToAttrs (map (x: lib.nameValuePair x.name (mkApp x)) workloads);
    nixidy.assertions =
      stateAssertions
      ++ nestingAssertions
      ++ requiresAssertions
      ++ credentialAssertions
      ++ selfUrlAssertions
      ++ identityAssertions
      ++ scalingAssertions
      ++ anchorAssertions
      ++ slotAssertions;
    nixidy.warnings = warnings;
  };
}
