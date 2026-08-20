#
# The cluster catalogue: what nixvault's archives ARE.
#
# ── WHY A VAULT REPOSITORY HAS ARCHIVES IN IT ─────────────────────────────────────────────────
#
# An archive and a backup are not the same promise, and the difference is what puts these here
# rather than beside a backup tool. A backup is a copy of a live system, kept so the system can be
# restored to what it was; when the original comes back the copy has done its job and can be
# discarded. An archive is a copy kept so the thing survives the ORIGINAL — the page that goes
# behind a paywall, the video that is taken down, the site that stops paying for a domain. There is
# nothing left to restore to. That is the same promise the vault half of this repository makes about
# a LUKS header and an age key: hold the one copy that outlives the thing it came from.
#
# So the archives live with the vault, and everything in this file follows from the one property
# they share: THE COPY IS THE ONLY COPY. It cannot be reconstructed by re-running anything, which is
# why a directory here is never scratch, an archive is never safe to idle mid-job, and nothing in
# the cluster may take ownership of a tree somebody curates outside it.
#
# ── WHAT IS KNOWLEDGE AND WHAT IS A VALUE ─────────────────────────────────────────────────────
#
# Everything in this file is true of the software wherever anyone runs it: the port it listens on,
# the directories it keeps and which of them grows without bound, which environment variables must
# carry a credential rather than a value, what it must be told about itself, and what it needs from
# somebody else. Nothing here names an address, a node, a hostname, a namespace, a path on a disk,
# a person or a secret's contents — those are one deployment's facts and they arrive from the
# consumer.
#
# The split is enforced rather than trusted. `state` here is the path INSIDE the container and only
# a declaration can say what backs it; `requires` here is the VARIABLE a companion service's URL is
# read from and only a declaration can say what that URL is; `credentials` here is the NAME of a
# variable that must come from a Secret and only a declaration can say which Secret holds it.
{ }:
{
  archives = {
    archivebox = {
      image = "ghcr.io/archivebox/archivebox";
      ports.http = 8000; # web UI and REST API on one port
      primaryPort = "http";

      # TWO DIRECTORIES, AND ONE IS INSIDE THE OTHER. `/data` holds the index — an SQLite database
      # and the application's own config — and `/data/archive` holds the snapshot tree the index
      # points at. The app expects to see a single `/data`, so the second is a nested mount inside
      # the first, and that is what makes the KEY NAMES load-bearing rather than cosmetic.
      #
      # The renderer emits a container's mounts in ATTRIBUTE ORDER, which for an attribute set is
      # alphabetical. Mount the inner path first and the outer mount lands on top of it: the
      # snapshot tree is still on the disk and the application can no longer see it. `data` sorts
      # before `snapshots`, so the outer mount is written first and stays first. Renaming either key
      # is a real change, and `modules/cluster.nix` refuses a catalogue whose names sort the wrong
      # way rather than letting a rename quietly hide an archive.
      state = {
        data = {
          mountPath = "/data";
          # The index tracks how MANY things were archived, not how big they are, so walking it is
          # bounded work.
          grows = false;
        };
        snapshots = {
          mountPath = "/data/archive";
          # This is the archive itself — WARC, screenshots, DOM, extracted text. Its size is the
          # size of everything ever kept, and it only ever goes up.
          grows = true;
        };
      };

      # NOTHING IS TRUE OF EVERY DEPLOYMENT. The visibility switches (whether the index, the
      # snapshots and the add-URL form are readable without logging in) are policy, and a timezone
      # is a place; both belong to whoever runs it.
      env = { };
      args = [ ];

      # NOTHING EXTERNAL. It carries its own index and its own queue, which is the whole reason it
      # is the simpler of the two archives to run.
      requires = { };

      # NO CREDENTIAL IN ITS ENVIRONMENT. Accounts live in its own database; nothing is passed in.
      credentials = [ ];

      # IT DOES NOT NEED TO BE TOLD ITS OWN URL.
      selfUrlEnv = null;

      # IT MUST START AS UID 0, and then it stops being root by itself. The entrypoint does
      # root-only setup — moving its runtime user to the ids it was given, taking ownership of the
      # data directory — and only then drops privileges to run the application. Starting it as a
      # non-root user does not produce a permissions error: the entrypoint dies under `set -o
      # errexit` before any application code runs, with no log output at all, which is the
      # expensive way to learn this.
      rootStart = true;

      # SO THE IDENTITY ARRIVES AS ENVIRONMENT, NOT AS A SECURITY CONTEXT. These two variable names
      # are a fact about the IMAGE and are public; the numbers they carry are a fact about the
      # deployment and come from the role a declaration names. An image that must start as root
      # cannot also be told not to, which is why naming these suppresses the security context that
      # would otherwise pin the user.
      identityEnv = {
        user = "PUID";
        group = "PGID";
      };

      # WHAT IT TOLERATES. Both are restrictions, both are free for this workload, and both are
      # stated because a restriction nobody wrote down is a restriction nobody applies.
      #
      # THERE IS NO `capabilitiesDrop` HERE, AND THE ABSENCE IS THE DECISION. It archives a page by
      # driving a headless browser, which needs the capability set the image ships with. Dropping
      # them all is the usual hardening answer and it breaks this application.
      security = {
        seccomp = "RuntimeDefault";
        allowPrivilegeEscalation = false;
      };

      # NO READINESS BUDGET, and that is a decision rather than an omission. With the index kept
      # private — the ordinary configuration — `/` answers a redirect to a login page rather than a
      # success, so the obvious probe reports a healthy application as unhealthy; and an archive run
      # holds the process for minutes at a time, which is exactly how a guessed budget turns a slow
      # job into a restart loop. A budget belongs here the day somebody establishes one against a
      # path that answers plainly.
      readiness = null;

      # IT MAY NOT SLEEP. Archiving is started from the web interface and then continues on its own
      # for minutes; a front that scales the workload away when the last request finishes takes the
      # job with it, and the page it was fetching may not be there on the next attempt. Idling is
      # safe for a workload that does nothing between requests, and this one does its actual work
      # between them.
      idleSafe = false;

      note = ''
        A web archive: give it a URL and it keeps the page — the rendered DOM, a screenshot, the
        extracted text, a WARC — so the page survives the site.

        THE INDEX IS THE CONSTRAINT, NOT THE SIZE. The index is a single-file SQLite database, which
        makes it a single-writer resource: two copies of this application on one `/data` is
        corruption, not availability, so it can never roll and can never run two replicas. None of
        that follows from how much traffic it takes — it is a small application by every other
        measure.

        THE SNAPSHOT TREE IS SOMEBODY ELSE'S PROPERTY. It is the reason the archive exists, it is
        curated from outside the cluster, and it grows forever. Handing it to the kubelet to own
        means a recursive change of ownership on every single start, over a tree that is bigger
        every time — unbounded work in the startup path, fighting whatever ownership was set
        deliberately outside. The declaration may ask for that on the index; it is refused on the
        archive.
      '';
    };

    tubearchivist = {
      image = "bbilly1/tubearchivist";
      ports.http = 8000;
      primaryPort = "http";

      # TWO DIRECTORIES, SIDE BY SIDE — neither nested in the other. `/youtube` is the archive: the
      # downloaded videos, written once and kept. `/cache` is the working set: thumbnails and
      # derived files, which can be rebuilt from the archive and the index.
      state = {
        media = {
          mountPath = "/youtube";
          # The videos themselves. Large, written sequentially, never rewritten.
          grows = true;
        };
        cache = {
          mountPath = "/cache";
          grows = false;
        };
      };

      # THE ADMIN ACCOUNT IS NAMED BY THE SOFTWARE, not chosen by the deployment: it creates exactly
      # one account on first boot and that account is `admin`. The PASSWORD for it is a credential
      # and appears nowhere in this file.
      env = {
        TA_USERNAME = "admin";
      };
      args = [ ];

      # IT IS THE FRONT OF A THREE-WORKLOAD STACK, and this is the honest way to say so. The search
      # index and the task queue are separate workloads with their own lifecycles, their own storage
      # and their own restart schedules; they are not containers of this pod and stapling them into
      # one would tie an index rebuild to a web restart. The grammar this repository renders into
      # describes ONE workload per entry, so the other two are named as things this one NEEDS, by
      # the variable it reads each one's location from. Who runs them, and where, is a deployment's
      # business.
      requires = {
        index = {
          env = "ES_URL";
          scheme = "http";
          note = ''
            An Elasticsearch instance holding the searchable metadata — every channel, video,
            comment and playlist this archive knows about. It is the half that cannot be
            re-downloaded: lose the videos and they can be fetched again, lose the index and what
            is left is a directory of files.

            TWO THINGS ABOUT RUNNING IT. It needs a raised `vm.max_map_count` on the node it lands
            on or it refuses to start, and it will happily initialize an EMPTY index on top of an
            existing archive if it is pointed at an empty directory — so an existing index is moved
            into place BEFORE the application is allowed to talk to it, never after.
          '';
        };
        queue = {
          env = "REDIS_CON";
          scheme = "redis";
          note = ''
            A Redis holding the task queue and the application's transient state. Downloads,
            re-indexes and subscription checks are enqueued here and executed by the application
            process, which is what makes it a queue rather than a cache — losing it loses the work
            that had not started yet.
          '';
        };
      };

      # TWO VARIABLES THAT MUST CARRY A CREDENTIAL. Named here, sourced by the declaration, never
      # held anywhere in this repository.
      #
      #   the index password — the same value the search index itself is started with, which is why
      #                        it is a shared credential rather than this application's own.
      #   the admin password — the password of the one account named above.
      credentials = [ "ELASTIC_PASSWORD" "TA_PASSWORD" ];

      # IT MUST BE TOLD THE URL IT IS REACHED AT. It builds absolute links with it, so a value that
      # is merely reachable from inside the cluster produces an archive whose links do not work from
      # anywhere a person actually browses it.
      selfUrlEnv = "TA_HOST";

      # IT RUNS AS UID 0 AND STAYS THERE. Its Python environment is installed under root's own home
      # and it has no support for being handed a different user, so there is no id to give it and
      # nothing to drop to.
      rootStart = true;
      identityEnv = null;

      # NOTHING ESTABLISHED. The restrictions above are stated for the archive beside this one
      # because they were tried there; nothing here has been verified against this image, and a
      # hardening term asserted without evidence is worse than an absent one — it reads as a
      # measurement.
      security = { };

      # NO READINESS BUDGET, for the same reason it has no probe today: its first boot migrates the
      # search index, which takes as long as the index is big, and a probe with an ordinary failure
      # budget turns that into a restart loop that reads like the application's fault. A budget
      # belongs here once one is established against a real first boot.
      readiness = null;

      # IT MAY NOT SLEEP. It holds a task queue: work is enqueued and then carried out by this
      # process. A sleeping application is a queue nobody drains, and the videos it was about to
      # fetch are exactly the ones that may not be there tomorrow.
      idleSafe = false;

      note = ''
        A video archive: it subscribes to channels and playlists, downloads what they publish, and
        keeps the result with its metadata so the collection survives a takedown, a deleted channel
        or a platform that changes its mind.

        THE ARCHIVE AND THE INDEX ARE DIFFERENT KINDS OF LOSS. The media directory is bulk: big
        files, written once, sequential, and re-fetchable in principle for as long as the source
        still exists. The search index is not bulk and is not re-fetchable — it is the record of
        what was collected and why, and rebuilding it means re-deriving metadata for sources that
        may be gone. A deployment that treats the two the same is choosing the wrong thing to
        protect.

        IT IS A SINGLE WRITER over both of its own directories, so it can never roll and can never
        run two replicas. The two workloads it needs are single writers over their own storage for
        the same reason, which is a property of THEIR declarations, not of this one.
      '';
    };
  };
}
