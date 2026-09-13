use super::*;
use crate::{key_from_hex, PROTO_V};
use serde_json::json;

fn key(byte: &str) -> ed25519_dalek::SigningKey {
    key_from_hex(&byte.repeat(32)).unwrap()
}

fn job() -> GradingJob {
    GradingJob {
        v: PROTO_V,
        kind: JOB_TYPE.into(),
        aud: AUD_GRADER.into(),
        job_id: "job-1".into(),
        run_id: "run-1".into(),
        incarnation: "incarnation-1".into(),
        fencing_token: 7,
        issued_at: 100,
        expires_at: 200,
        submission_digest: sha256_hex(b"candidate"),
        task_id: TASK_ID.into(),
        input_version: INPUT_VERSION.into(),
        scorer_version: SCORER_VERSION.into(),
    }
}

fn result() -> GradingResult {
    let j = job();
    GradingResult {
        v: PROTO_V,
        kind: RESULT_TYPE.into(),
        aud: AUD_GRADING_RESULTS.into(),
        job_id: j.job_id,
        run_id: j.run_id,
        incarnation: j.incarnation,
        fencing_token: j.fencing_token,
        issued_at: 110,
        expires_at: j.expires_at,
        submission_digest: j.submission_digest.clone(),
        task_id: j.task_id,
        input_version: j.input_version,
        scorer_version: j.scorer_version,
        sandbox_id: "a1".repeat(16),
        launched_artifact_digest: j.submission_digest,
        captured_output_digest: sha256_hex(b"42\n"),
        score: Score::Correct,
        status: GradingStatus::Completed,
        observations: LifecycleObservations {
            started: true,
            exited: true,
            timed_out: false,
            teardown_confirmed: true,
            started_at: 101,
            exited_at: 105,
            frozen_at: 106,
            teardown_confirmed_at: 109,
        },
    }
}

#[test]
fn job_and_result_have_independent_pinned_signers_and_audiences() {
    let controller = key("01");
    let scorer = key("02");
    let signed_job = Signed::sign(&controller, "controller", &job());
    let signed_result = Signed::sign(&scorer, "scorer", &result());
    assert_eq!(
        verify_job(&signed_job, &controller.verifying_key(), 100).unwrap(),
        job()
    );
    assert_eq!(
        verify_result(&signed_result, &scorer.verifying_key(), &job(), 110).unwrap(),
        result()
    );
    assert!(verify_job(&signed_job, &scorer.verifying_key(), 100).is_err());
    assert!(verify_result(&signed_result, &controller.verifying_key(), &job(), 110).is_err());
    assert!(verify_job(&signed_result, &scorer.verifying_key(), 110).is_err());
    assert!(verify_result(&signed_job, &controller.verifying_key(), &job(), 110).is_err());
    let mut j = job();
    j.aud = "hostd".into();
    assert!(verify_job(
        &Signed::sign(&controller, "controller", &j),
        &controller.verifying_key(),
        100
    )
    .is_err());
    j.aud = AUD_GRADER.into();
    j.v = 2;
    assert!(verify_job(
        &Signed::sign(&controller, "controller", &j),
        &controller.verifying_key(),
        100
    )
    .is_err());
    let mut r = signed_result;
    r.payload = r.payload.replace("correct", "incorrect");
    assert!(verify_result(&r, &scorer.verifying_key(), &job(), 110).is_err());
}

#[test]
fn all_released_identities_and_artifact_versions_must_match_authorization() {
    let valid = serde_json::to_value(result()).unwrap();
    for (field, value) in [
        ("job_id", json!("job-2")),
        ("run_id", json!("another-run")),
        ("incarnation", json!("other-incarnation")),
        ("fencing_token", json!(8)),
        ("submission_digest", json!(sha256_hex(b"replacement"))),
        (
            "launched_artifact_digest",
            json!(sha256_hex(b"replacement")),
        ),
        ("task_id", json!("another-task")),
        ("input_version", json!("2")),
        ("scorer_version", json!("2")),
        ("expires_at", json!(201)),
        ("sandbox_id", json!("../../secrets")),
        ("captured_output_digest", json!("not-a-digest")),
    ] {
        let mut v = valid.clone();
        v[field] = value;
        let changed: GradingResult = serde_json::from_value(v).unwrap();
        assert!(changed.validate_for(&job(), 110).is_err(), "{field}");
    }
}

#[test]
fn no_free_text_fields_or_unbounded_score_vocabulary() {
    let scorer = key("02");
    for (field, value) in [
        ("evidence", json!("secret")),
        ("scorer_decision", json!("PASS")),
        ("callback_url", json!("https://example.invalid")),
        ("score", json!(100)),
        ("score", json!("PASS")),
        ("score", json!({"correct": "secret"})),
        ("status", json!("timeout")),
    ] {
        let mut v = serde_json::to_value(result()).unwrap();
        v[field] = value;
        assert!(
            verify_result(
                &Signed::sign(&scorer, "scorer", &v),
                &scorer.verifying_key(),
                &job(),
                110
            )
            .is_err(),
            "{field}"
        );
    }
    let mut v = serde_json::to_value(result()).unwrap();
    v["observations"]["guest_report"] = json!("PASS");
    assert!(serde_json::from_value::<GradingResult>(v).is_err());
    let mut v = serde_json::to_value(job()).unwrap();
    v["submission"] = json!("embedded-code");
    assert!(serde_json::from_value::<GradingJob>(v).is_err());
}

#[test]
fn submission_is_out_of_envelope_and_exact_bytes_are_bound() {
    let controller = key("01");
    let signed = Signed::sign(&controller, "controller", &job());
    let frame = encode_dispatch(&signed, b"candidate").unwrap();
    let (decoded, bytes) = decode_dispatch(&frame).unwrap();
    let authorized = verify_job(&decoded, &controller.verifying_key(), 100).unwrap();
    assert_eq!(decoded, signed);
    assert_eq!(bytes, b"candidate");
    authorized.bind_submission(&bytes).unwrap();
    assert!(!signed.payload.contains("candidate"));
    for replacement in [b"Candidate".as_slice(), b"candidate\n", b"candidate\0", b""] {
        assert!(authorized.bind_submission(replacement).is_err());
    }
    let mut changed = frame;
    *changed.last_mut().unwrap() ^= 1;
    let (signed, replacement) = decode_dispatch(&changed).unwrap();
    // A correctly signed envelope is not sufficient to authorize different artifact bytes.
    assert!(verify_job(&signed, &controller.verifying_key(), 100)
        .unwrap()
        .bind_submission(&replacement)
        .is_err());
    let mut oversized = vec![1; MAX_SUBMISSION_BYTES + 1];
    let mut j = job();
    j.submission_digest = sha256_hex(&oversized);
    assert!(j.bind_submission(&oversized).is_err());
    oversized.pop();
    j.submission_digest = sha256_hex(&oversized);
    j.bind_submission(&oversized).unwrap();
}

#[test]
fn framing_rejects_truncation_overflow_and_oversized_envelopes() {
    for bytes in [
        vec![],
        vec![0; 3],
        vec![0; 5],
        vec![255; 5],
        vec![0; MAX_DISPATCH_BYTES + 1],
    ] {
        assert!(decode_dispatch(&bytes).is_err());
    }
    let controller = key("01");
    let signed = Signed::sign(&controller, "controller", &job());
    let mut frame = encode_dispatch(&signed, b"a").unwrap();
    frame.pop();
    assert!(decode_dispatch(&frame).is_err());
    let mut large = signed.clone();
    large.payload = "a".repeat(MAX_GRADING_ENVELOPE_BYTES);
    assert!(encode_dispatch(&large, b"a").is_err());
    assert!(encode_dispatch(&signed, &vec![0; MAX_SUBMISSION_BYTES + 1]).is_err());
    let mut v = serde_json::to_value(signed).unwrap();
    v["relay"] = json!("untrusted text");
    let raw = serde_json::to_vec(&v).unwrap();
    let mut frame = (raw.len() as u32).to_be_bytes().to_vec();
    frame.extend(raw);
    frame.push(1);
    assert!(decode_dispatch(&frame).is_err());
}

#[test]
fn captured_output_digest_is_distinct_from_guest_status_and_artifact_digest() {
    let r = result();
    r.bind_captured_output(b"42\n").unwrap();
    for candidate in [b"PASS".as_slice(), b"candidate", b"42", b"42\nPASS", b""] {
        assert!(r.bind_captured_output(candidate).is_err());
    }
    let output = vec![0; MAX_CAPTURED_OUTPUT_BYTES + 1];
    let mut r = r;
    r.captured_output_digest = sha256_hex(&output);
    assert!(r.bind_captured_output(&output).is_err());
}

#[test]
fn no_result_without_complete_frozen_then_destroyed_lifecycle() {
    for field in ["started", "exited", "teardown_confirmed"] {
        let mut v = serde_json::to_value(result()).unwrap();
        v["observations"][field] = json!(false);
        assert!(serde_json::from_value::<GradingResult>(v)
            .unwrap()
            .validate_for(&job(), 110)
            .is_err());
    }
    for (field, value) in [
        ("timed_out", json!(true)),
        ("started_at", json!(0)),
        ("exited_at", json!(111)),
        ("frozen_at", json!(110)),
        ("teardown_confirmed_at", json!(105)),
    ] {
        let mut v = serde_json::to_value(result()).unwrap();
        v["observations"][field] = value;
        assert!(
            serde_json::from_value::<GradingResult>(v)
                .unwrap()
                .validate_for(&job(), 110)
                .is_err(),
            "{field}"
        );
    }
}

#[test]
fn grading_fencing_and_both_clocks_never_resurrect_execution() {
    let j = job();
    assert!(j.deadline(7, 100).is_err());
    assert!(
        j.deadline(6, 106).is_err(),
        "dispatch delayed more than trusted skew"
    );
    let d = j.deadline(6, 104).unwrap();
    assert_eq!(d.epoch, 0);
    assert_eq!(d.wall, 200);
    assert!(d.mono <= Instant::now() + Duration::from_secs(96));
    assert!(!d.expired(104));
    assert!(d.expired(200));
    let future = j.deadline(6, 95).unwrap();
    assert!(future.mono <= Instant::now() + Duration::from_secs(100));
    let rolled_back = Deadline {
        mono: Instant::now(),
        ..d
    };
    assert!(rolled_back.expired(50));
    assert!(j.validate(200).is_err());
    assert!(result().validate_for(&j, 200).is_err());
    let mut j = j;
    j.expires_at = j.issued_at + MAX_GRADING_TTL_S + 1;
    assert!(j.deadline(0, 100).is_err());
    j.expires_at = 99;
    assert!(j.validate(100).is_err());
    j.issued_at = u64::MAX;
    j.expires_at = u64::MAX;
    assert!(j.validate(u64::MAX).is_err());
}

#[test]
fn canonical_digest_and_bounded_identity_validation() {
    assert!(valid_digest(&sha256_hex(b"hi")));
    assert!(!valid_digest(&"AB".repeat(32)));
    assert!(!valid_digest(&"ff".repeat(31)));
    for value in ["", "../file", "url:7100", "newline\n", "a b", "λ"] {
        assert!(!valid_id(value));
    }
    assert!(valid_id("01HF4_TEST-run"));
    assert!(!valid_id(&"a".repeat(129)));
    for (field, value) in [
        ("job_id", "../file"),
        ("run_id", ""),
        ("incarnation", "x/y"),
        ("task_id", "unapproved"),
        ("input_version", "2"),
        ("scorer_version", "2"),
    ] {
        let mut v = serde_json::to_value(job()).unwrap();
        v[field] = json!(value);
        assert!(serde_json::from_value::<GradingJob>(v)
            .unwrap()
            .validate(100)
            .is_err());
    }
}
