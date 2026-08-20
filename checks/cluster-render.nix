# Reads the cluster half's promises back off the RENDERED BYTES, not off the options that produced
# them.
#
# The eval check proves the module resolves and refuses. This one proves the manifests that come out
# say what the module claims -- which is a different question, and the only one a cluster ever sees.
# An option can be correct and the rendering still wrong: MOUNT ORDER is the case that made this file
# necessary, because it is invisible in the options and decides whether an archive is visible at all.
{ pkgs, lib, nixidy, appsModule, clusterModule, values }:

let
  env = nixidy.lib.mkEnv {
    inherit pkgs;
    modules = [ appsModule clusterModule (import values) ];
  };
in
pkgs.runCommand "nixvault-cluster-render"
{
  nativeBuildInputs = [ pkgs.yq-go ];
  manifests = env.environmentPackage;
} ''
  set -euo pipefail
  fail=0
  check() { # name expected actual
    if [ "$2" = "$3" ]; then echo "  ok   $1: $3"
    else echo "  FAIL $1: expected '$2', got '$3'"; fail=1; fi
  }
  y() { yq -r "$1" "$2"; }

  echo "== the environment renders both archives and nothing else =="
  rendered=$(ls "$manifests" | sort | tr '\n' ' ' | sed 's/ $//')
  check "rendered archives" "apps example-pages example-videos" "$rendered"

  pages="$manifests/example-pages"
  videos="$manifests/example-videos"
  pagesd="$pages/Deployment-example-pages.yaml"
  videosd="$videos/Deployment-example-videos.yaml"

  echo "== the catalogue's port reaches the container, and the declaration never stated one =="
  check "pages port"  "8000" "$(y '.spec.template.spec.containers[0].ports[0].containerPort' $pagesd)"
  check "videos port" "8000" "$(y '.spec.template.spec.containers[0].ports[0].containerPort' $videosd)"

  echo "== an archive is a single writer over its own directories, so neither Deployment may roll =="
  check "pages strategy"  "Recreate" "$(y '.spec.strategy.type' $pagesd)"
  check "videos strategy" "Recreate" "$(y '.spec.strategy.type' $videosd)"
  check "pages replicas"  "1" "$(y '.spec.replicas' $pagesd)"
  check "videos replicas" "1" "$(y '.spec.replicas' $videosd)"

  # THE ONE THAT IS INVISIBLE IN THE OPTIONS. `/data/archive` is INSIDE `/data`, mounts are emitted
  # in attribute order, and the outer one has to be written first -- mount the inner first and the
  # outer lands on top of it, leaving the archive on the disk and out of the application's sight.
  # Nothing in the option tree shows the order, so it is asserted here on the bytes.
  echo "== the outer mount is written before the one nested inside it =="
  check "pages mount 0" "/data"         "$(y '.spec.template.spec.containers[0].volumeMounts[0].mountPath' $pagesd)"
  check "pages mount 1" "/data/archive" "$(y '.spec.template.spec.containers[0].volumeMounts[1].mountPath' $pagesd)"
  check "pages mounts"  "2"             "$(y '.spec.template.spec.containers[0].volumeMounts | length' $pagesd)"

  echo "== and where nothing nests, both mounts simply arrive =="
  check "videos mount 0" "/cache"   "$(y '.spec.template.spec.containers[0].volumeMounts[0].mountPath' $videosd)"
  check "videos mount 1" "/youtube" "$(y '.spec.template.spec.containers[0].volumeMounts[1].mountPath' $videosd)"

  echo "== what backs a directory comes from the declaration, and strictly by default =="
  check "pages index claim"   "example-pages-index"    "$(y '.spec.template.spec.volumes[] | select(.name=="data") | .persistentVolumeClaim.claimName' $pagesd)"
  check "pages archive path"  "/example/archive/pages" "$(y '.spec.template.spec.volumes[] | select(.name=="snapshots") | .hostPath.path' $pagesd)"
  check "pages archive type"  "Directory"              "$(y '.spec.template.spec.volumes[] | select(.name=="snapshots") | .hostPath.type' $pagesd)"

  echo "== a node path is a pin, and the platform stamps it rather than each archive =="
  for f in $pagesd $videosd; do
    check "$(basename $f) node pin" "example-node" "$(y '.spec.template.spec.nodeSelector."kubernetes.io/hostname"' $f)"
  done

  echo "== the image is a tag when a version was given and a whole reference when one was =="
  check "pages image" "ghcr.io/archivebox/archivebox:0.0.0" "$(y '.spec.template.spec.containers[0].image' $pagesd)"
  check "videos digest-pinned" "true" "$(y '.spec.template.spec.containers[0].image' $videosd | grep -q '@sha256:' && echo true || echo false)"

  # An image that must start as uid 0 and drops privileges itself cannot also be told not to: the
  # ids arrive as ENVIRONMENT and no user is pinned. The group the kubelet takes is rendered only
  # because one volume asked for it -- the growing one deliberately did not.
  echo "== an identity delivered as environment pins no user, and only the volume that asked gets a group =="
  check "pages PUID"       "4242" "$(y '.spec.template.spec.containers[0].env[] | select(.name=="PUID") | .value' $pagesd)"
  check "pages PGID"       "4242" "$(y '.spec.template.spec.containers[0].env[] | select(.name=="PGID") | .value' $pagesd)"
  check "pages runAsUser"  "null" "$(y '.spec.template.spec.securityContext.runAsUser' $pagesd)"
  check "pages fsGroup"    "4242" "$(y '.spec.template.spec.securityContext.fsGroup' $pagesd)"
  check "videos runAsUser" "null" "$(y '.spec.template.spec.securityContext.runAsUser' $videosd)"
  check "videos fsGroup"   "null" "$(y '.spec.template.spec.securityContext.fsGroup' $videosd)"

  echo "== the restrictions the catalogue records are on the object, and silence stays silent =="
  check "pages seccomp"      "RuntimeDefault" "$(y '.spec.template.spec.securityContext.seccompProfile.type' $pagesd)"
  check "pages no-escalate"  "false"          "$(y '.spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation' $pagesd)"
  check "pages caps kept"    "null"           "$(y '.spec.template.spec.containers[0].securityContext.capabilities' $pagesd)"
  check "videos no seccomp"  "null"           "$(y '.spec.template.spec.securityContext.seccompProfile' $videosd)"

  echo "== a companion workload arrives as a URL under the variable the catalogue names =="
  check "videos ES_URL"     "http://example-index:9200"  "$(y '.spec.template.spec.containers[0].env[] | select(.name=="ES_URL") | .value' $videosd)"
  check "videos REDIS_CON"  "redis://example-queue:6379" "$(y '.spec.template.spec.containers[0].env[] | select(.name=="REDIS_CON") | .value' $videosd)"
  check "videos TA_HOST"    "https://videos.example.com" "$(y '.spec.template.spec.containers[0].env[] | select(.name=="TA_HOST") | .value' $videosd)"
  check "videos TA_USERNAME" "admin"                     "$(y '.spec.template.spec.containers[0].env[] | select(.name=="TA_USERNAME") | .value' $videosd)"

  # The whole point of naming a credential rather than carrying one: the rendered tree holds a
  # reference to a key in a Secret and no value at all, which is what makes it committable.
  echo "== a credential is a reference to a key, and never a value =="
  check "videos elastic key"   "index-password"             "$(y '.spec.template.spec.containers[0].env[] | select(.name=="ELASTIC_PASSWORD") | .valueFrom.secretKeyRef.key' $videosd)"
  check "videos elastic from"  "example-videos-credentials" "$(y '.spec.template.spec.containers[0].env[] | select(.name=="ELASTIC_PASSWORD") | .valueFrom.secretKeyRef.name' $videosd)"
  check "videos admin key"     "admin-password"             "$(y '.spec.template.spec.containers[0].env[] | select(.name=="TA_PASSWORD") | .valueFrom.secretKeyRef.key' $videosd)"
  check "videos no plain value" "false" "$(y '[.spec.template.spec.containers[0].env[] | select(.name=="ELASTIC_PASSWORD") | has("value")] | .[0]' $videosd)"
  check "videos no envFrom"     "null"  "$(y '.spec.template.spec.containers[0].envFrom' $videosd)"

  echo "== no health signal is invented for either archive =="
  for f in $pagesd $videosd; do
    check "$(basename $f) readiness" "null" "$(y '.spec.template.spec.containers[0].readinessProbe' $f)"
    check "$(basename $f) liveness"  "null" "$(y '.spec.template.spec.containers[0].livenessProbe' $f)"
  done

  echo "== no address is invented here: the Service is a plain ClusterIP with nothing pinned =="
  for f in $pages/Service-example-pages.yaml $videos/Service-example-videos.yaml; do
    check "$(basename $f) type" "ClusterIP" "$(y '.spec.type' $f)"
    check "$(basename $f) no pinned IP" "null" "$(y '.spec.clusterIP' $f)"
    check "$(basename $f) no nodePort" "null" "$(y '.spec.ports[0].nodePort' $f)"
  done

  # `-L` is load-bearing: the rendered tree is SYMLINKS into the store, so a plain `-type f` matches
  # nothing and returns a confident zero. A count that can only ever be zero is worse than no check,
  # because it passes the moment somebody expects zero.
  echo "== exactly one archive anchors the shared namespace, and only one =="
  check "namespaces rendered" "1" "$(find -L $manifests -name 'Namespace-*.yaml' -type f | wc -l)"
  check "which namespace" "example-archive" "$(y '.metadata.name' $pages/Namespace-example-archive.yaml)"

  if [ "$fail" -ne 0 ]; then
    echo "rendered output does not match what the cluster half promises" >&2
    exit 1
  fi
  echo "nixvault: the rendered tree matches every promise asserted here"
  touch $out
''
