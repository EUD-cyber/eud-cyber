# P11 artifact collisions

P11 Create checks the requested namespace before modifying the target. Any existing
artifact is reported as already existing, including an artifact from an earlier
MrNobody run. Create does not adopt, reconfigure, restart, repair, rename or delete it.
An owned same-method rerun also skips; use Inspect where supported to verify state.

Windows checks the shared ProgramData directory, root scheduled task and service
name under the existing per-name mutex. Linux checks the shared artifact directory,
cron references, user service/unit/drop-in paths, loaded user service and an orphan
worker with the exact worker path. Linux rechecks under a per-name create lock;
the existing cron lock still protects crontab read/modify/write. Control lock files
can remain in ~/.config/mrnobody; they are not persistence artifacts.

The receipt produces P11_ARTIFACT_EXISTS with target, method, requested_artifact,
reason=artifact_already_exists, action=not_attempted, ownership=not_assumed and
cleanup_required=false. This means this attempt created nothing. It says nothing
about whether an existing artifact needs cleanup or who owns it. Previous evidence
is preserved; Cleanup retains its existing ownership checks and must be requested
explicitly with the original target, user, method and suffix.

The phase emits PHASE_SKIPPED and returns 78. Standalone preserves that result in
the report while its wrapper completes normally. Full Campaign records skipped
and continues to subsequent configured phases. Neither reports creation success
nor assumes sensor detection. A separate target/transport error still makes the
phase fail. Technical failures and failures after writes start remain failures,
with cleanup potentially required; error text alone never becomes a skip.

Checks and writes across OS providers are not a single atomic transaction. The
locks serialize updated MrNobody instances using the same account/namespace, but
cannot serialize unrelated administrators or older versions. A user service
manager that cannot be queried is not evidence of a loaded service; systemd's own
manager/ownership validation still applies before its writes. Use target logs to
investigate failures or ambiguous interrupted runs.

After this change is merged into the branch used by the updater:

1. Run `mrnobody update` on the attacker VM yourself.
2. Use P11 Create with the same target, user, method and already-existing artifact.
   Expect P11_ARTIFACT_EXISTS, action=not_attempted and SKIPPED; compare the original
   files/task/service/cron/process identity and configuration before and after.
3. Repeat across methods sharing that name, including unknown-owner artifacts.
4. Run Standalone and inspect Ground Truth and the report. In Full Campaign verify
   P11 is skipped and the following configured phase runs.
5. For a fresh Create test, explicitly choose an unused artifact name; expect the
   normal verified success path. Run ownership-safe Cleanup only for artifacts
   whose original ownership/method is known. No VM deployment is part of this PR.
