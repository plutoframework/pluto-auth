#!/usr/bin/env python3
"""Bounded auth mutations in disposable copies; no comprehensive coverage claim."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent
MUTATIONS = [
    (
        "bearer enabled without opt in",
        "httpauth/http.go",
        "if !t.allowBearer || len(headers) != 1 {",
        "if false && !t.allowBearer || len(headers) != 1 {",
        "./httpauth",
        "TestBearerOptInAndAmbiguousCredentials",
    ),
    (
        "absolute expiry ignored",
        "session.go",
        "now.Before(session.CreatedAt) || !now.Before(session.ExpiresAt)",
        "now.Before(session.CreatedAt)",
        ".",
        "TestSessionDeadlines",
    ),
    (
        "idle expiry ignored",
        "session.go",
        "return idle == 0 || now.Before(session.LastSeenAt.Add(idle))",
        "return true || idle == 0 || now.Before(session.LastSeenAt.Add(idle))",
        ".",
        "TestSessionDeadlines",
    ),
    (
        "rotation token retained",
        "stores/memory/store.go",
        "delete(s.sessions, digest)\n\n\treturn item.session, nil",
        "// mutation: leave consumed session present\n\n\treturn item.session, nil",
        ".",
        "TestRotationSingleUse",
    ),
    (
        "untrusted origin allowed",
        "httpauth/http.go",
        "if _, trusted := t.origins[origins[0]]; !trusted {",
        "if _, trusted := t.origins[origins[0]]; false && !trusted {",
        "./httpauth",
        "TestRequireAndOrigin",
    ),
    (
        "disabled credential allowed",
        "methods/password/authenticator.go",
        "credential.Disabled ||",
        "false ||",
        "./methods/password",
        "TestSignInDecisions",
    ),
    (
        "password comparison inverted",
        "methods/password/hasher.go",
        "subtle.ConstantTimeCompare(key, parsed.key) == 1",
        "subtle.ConstantTimeCompare(key, parsed.key) != 1",
        "./methods/password",
        "TestHashRoundTrip",
    ),
    (
        "unbounded memory costs",
        "methods/password/hasher.go",
        "memory <= 256*1024",
        "memory <= ^uint32(0)",
        "./methods/password",
        "TestRejectMalformedCosts",
    ),
    (
        "unverified local password accepted",
        "methods/password/service.go",
        "!account.Verified || account.Disabled",
        "false || account.Disabled",
        "./methods/password",
        "TestServiceLifecycle",
    ),
    (
        "local password comparison ignored",
        "methods/password/service.go",
        "if !valid || lookupErr != nil ||",
        "if false && !valid || lookupErr != nil ||",
        "./methods/password",
        "TestServiceLifecycle",
    ),
    (
        "challenge purposes conflated",
        "methods/password/identifier.go",
        'string(purpose) + "\\x00" + token',
        '"\\x00" + token',
        "./methods/password",
        "TestChallengePurposeSeparation",
    ),
    (
        "credential fence ignored",
        "authentication.go",
        "session.CredentialVersion != account.Version",
        "false && session.CredentialVersion != account.Version",
        "./stores/postgres",
        "TestPostgresStaleSignInFence",
    ),
    (
        "reset session revocation omitted",
        "stores/postgres/local.go",
        "return q.DeleteSubjectSessions(ctx, id)",
        "return nil // mutation: skip revocation",
        "./stores/postgres",
        "TestPostgresLocalLifecycle",
    ),
    (
        "required factor ignored",
        "authentication.go",
        'requirement.SecondFactor && e.SecondFactor == ""',
        'false && requirement.SecondFactor && e.SecondFactor == ""',
        ".",
        "TestEvidenceRequirements",
    ),
    (
        "freshness ignored",
        "authentication.go",
        "!now.Before(e.PrimaryAt.Add(requirement.MaxAge))",
        "false && !now.Before(e.PrimaryAt.Add(requirement.MaxAge))",
        ".",
        "TestAuthenticatedRotationPreservesFreshness",
    ),
    (
        "rotation loses authentication time",
        "manager.go",
        "session.Authentication,",
        "Evidence{},",
        ".",
        "TestAuthenticatedRotationPreservesFreshness",
    ),
    (
        "legacy issuance ignores factor policy",
        "authentication.go",
        "session.Authentication.IsZero() && !account.SecondFactorRequired",
        "session.Authentication.IsZero()",
        "./stores/postgres",
        "TestPostgresAuthenticationEvidenceAndRequiredFactor",
    ),
    (
        "expired ceremony accepts factor",
        "ceremony.go",
        "!now.Before(c.expires)",
        "false && !now.Before(c.expires)",
        ".",
        "TestCeremonyRequiresVerifiedPrimaryAndFactor",
    ),
    (
        "database issuance deadline ignored",
        "stores/postgres/internal/db/local_queries.sql.go",
        "clock_timestamp() < $8::timestamptz",
        "true",
        "./stores/postgres",
        "TestPostgresExpiredIssuanceRollsBackSession",
    ),
]


def execute(args, cwd, timeout):
    return subprocess.run(
        args, cwd=cwd, capture_output=True, text=True, timeout=timeout,
    )


def main():
    if not os.environ.get("PLUTO_AUTH_TEST_DATABASE_URL"):
        raise SystemExit("Set PLUTO_AUTH_TEST_DATABASE_URL to a disposable DB; SQL mutants must run")
    baseline = execute(["./scripts/test.sh"], ROOT, 120)
    if baseline.returncode:
        raise SystemExit(baseline.stdout + baseline.stderr)

    counts = dict.fromkeys(["killed", "survived", "invalid", "timed-out"], 0)
    for name, filename, before, after, package, test in MUTATIONS:
        with tempfile.TemporaryDirectory(prefix="pluto-auth-mutation-") as temporary:
            checkout = Path(temporary) / "library"
            shutil.copytree(
                ROOT, checkout,
                ignore=shutil.ignore_patterns(".git", "bin", "*.test", "coverage.*"),
            )
            path = checkout / filename
            content = path.read_text()
            if content.count(before) != 1:
                raise SystemExit(f"Mutation target drifted: {name}")
            path.write_text(content.replace(before, after, 1))
            output = ""
            try:
                binary = Path(temporary) / "mutant.test"
                built = execute(
                    ["go", "test", "-c", "-o", str(binary), package], checkout, 60,
                )
                if built.returncode:
                    outcome = "invalid"
                    output = built.stdout + built.stderr
                else:
                    run = execute(
                        [str(binary), "-test.run", f"^{test}$", "-test.timeout", "15s"],
                        checkout, 20,
                    )
                    output = run.stdout + run.stderr
                    if "test timed out" in output:
                        outcome = "timed-out"
                    elif run.returncode:
                        outcome = "killed"
                    else:
                        outcome = "survived"
            except subprocess.TimeoutExpired:
                outcome = "timed-out"
            counts[outcome] += 1
            print(f"{outcome}: {name}", flush=True)
            if outcome != "killed":
                print(output, flush=True)

    print(counts)
    raise SystemExit(0 if counts["killed"] == len(MUTATIONS) else 1)


if __name__ == "__main__":
    main()
