# Placeholder values for the cluster module — the file that makes the render check real.
# `nix flake check` renders the whole surface from here, so a module that stops evaluating, or that
# grows a required value nobody supplies, fails in CI rather than in somebody's cluster.
#
# NOTHING HERE IS REAL. Every namespace, path, node, name, number, URL and image is invented for
# this file, and no credential appears in any form — only the NAME of a Secret that would hold one
# and the KEY inside it.
#
# The two declarations are chosen to cover the paths that differ in what gets RENDERED rather than
# merely in what evaluates:
#
#   - an archive that keeps one directory INSIDE another and drops its own privileges: it anchors
#     the shared namespace, names the role whose ids it is handed as environment, and lets the
#     kubelet own the small directory while keeping it off the growing one;
#   - an archive that is the front of a stack it does not render: it joins that namespace rather
#     than anchoring a second one, names where its index and its queue can be reached, sources two
#     credentials from a Secret key by key, is told the URL people reach it at, runs as uid 0 and is
#     pinned by digest — which is what the grammar asks for and what the first one deliberately does
#     not do.
{
  # Required by the nixidy environment itself, not by any module here.
  nixidy.target.repository = "https://example.com/example-org/example-gitops.git";
  nixidy.target.branch = "main";

  # The fleet facts the app grammar refuses to take from an app: which node holds the directories,
  # and what a role IS numerically. Both are invented here.
  nixk3s.appPlatform = {
    hostPathNodeSelector."kubernetes.io/hostname" = "example-node";
    identities.example-archivist = { uid = 4242; gid = 4242; };
  };

  nixvault.clusterPlatform = {
    namespace = "example-archive";
    project = "example-keeping";
  };

  # Keeps two directories, one nested in the other, and backs them differently on purpose: the index
  # on a claim the cluster manages, the snapshot tree on a path somebody curates outside it. Names
  # the role whose ids reach the image as PUID/PGID — the image still starts as root and drops
  # privileges itself, which is why no security context pins the user. The kubelet may own the
  # index, which is bounded; asking for the same on the snapshot tree is refused.
  nixvault.archives.example-pages = {
    app = "archivebox";
    version = "0.0.0";
    createNamespace = true;
    exposure = "nb";
    slot = 12;
    identityRole = "example-archivist";
    state.data = {
      claim = "example-pages-index";
      ownership = "kubelet";
    };
    state.snapshots.hostPath = "/example/archive/pages";
  };

  # The front of a three-workload stack this repository does not render: it names where the other two
  # are and nothing else about them. Joins the namespace above rather than anchoring a second one,
  # and carries a whole reference so two syncs of an identical tree run identical code.
  nixvault.archives.example-videos = {
    app = "tubearchivist";
    version = "0.0.0";
    image = "registry.example.com/example-org/example-videos:0.0.0@sha256:0000000000000000000000000000000000000000000000000000000000000000";
    exposure = "nb";
    slot = 13;
    publicUrl = "https://videos.example.com";
    requires.index.endpoint = "http://example-index:9200";
    requires.queue.endpoint = "redis://example-queue:6379";
    credentials.ELASTIC_PASSWORD = {
      secret = "example-videos-credentials";
      key = "index-password";
    };
    credentials.TA_PASSWORD = {
      secret = "example-videos-credentials";
      key = "admin-password";
    };
    state.media.hostPath = "/example/archive/videos";
    state.cache.hostPath = "/example/state/videos-cache";
  };
}
