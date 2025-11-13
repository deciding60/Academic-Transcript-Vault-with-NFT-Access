(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-INVALID-ACCESS (err u101))
(define-constant ERR-TRANSCRIPT-EXISTS (err u102))
(define-constant ERR-NO-TRANSCRIPT (err u103))
(define-constant ERR-EXPIRED (err u104))
(define-constant ERR-NO-METADATA (err u105))
(define-constant ERR-INSTITUTION-NOT-REGISTERED (err u106))
(define-constant ERR-ALREADY-VERIFIED-BY-INSTITUTION (err u107))
(define-constant ERR-INSUFFICIENT-VERIFICATIONS (err u108))
(define-constant ERR-TRANSCRIPT-REVOKED (err u109))
(define-constant ERR-NOT-REVOKED (err u110))
(define-constant ERR-APPEAL-EXISTS (err u111))
(define-constant ERR-NO-APPEAL (err u112))

(define-non-fungible-token access-key uint)

(define-map transcripts
    { student-id: (string-ascii 64) }
    {
        content: (string-ascii 1024),
        issuer: principal,
        timestamp: uint,
        verified: bool,
    }
)

(define-map access-grants
    { key-id: uint }
    {
        student-id: (string-ascii 64),
        granted-to: principal,
        expires-at: uint,
    }
)

(define-map transcript-metadata
    { student-id: (string-ascii 64) }
    {
        gpa: (optional uint),
        graduation-year: (optional uint),
        degree-type: (optional (string-ascii 64)),
        honors: (optional (string-ascii 128)),
        total-credits: (optional uint),
    }
)

(define-map registered-institutions
    { institution-id: (string-ascii 64) }
    {
        name: (string-ascii 128),
        principal-address: principal,
        verification-weight: uint,
        active: bool,
    }
)

(define-map institutional-verifications
    {
        student-id: (string-ascii 64),
        institution-id: (string-ascii 64),
    }
    {
        verifier-principal: principal,
        signature-hash: (buff 32),
        timestamp: uint,
        verification-level: uint,
    }
)

(define-map verification-summary
    { student-id: (string-ascii 64) }
    {
        total-weight: uint,
        verification-count: uint,
        last-verified: uint,
        verification-status: (string-ascii 32),
    }
)

(define-map revocations
    { student-id: (string-ascii 64) }
    {
        revoked-by: principal,
        revoked-at: uint,
        reason-code: (string-ascii 32),
        reason-detail: (string-ascii 256),
        is-permanent: bool,
        evidence-hash: (buff 32),
    }
)

(define-map revocation-appeals
    { student-id: (string-ascii 64) }
    {
        appellant: principal,
        appeal-timestamp: uint,
        appeal-reason: (string-ascii 512),
        supporting-evidence: (buff 32),
        status: (string-ascii 32),
        reviewed-by: (optional principal),
        reviewed-at: (optional uint),
        resolution-notes: (optional (string-ascii 256)),
    }
)

(define-data-var next-key-id uint u1)

(define-read-only (get-transcript (student-id (string-ascii 64)))
    (match (map-get? transcripts { student-id: student-id })
        transcript (ok transcript)
        (err ERR-NO-TRANSCRIPT)
    )
)

(define-read-only (get-transcript-metadata (student-id (string-ascii 64)))
    (match (map-get? transcript-metadata { student-id: student-id })
        metadata (ok metadata)
        (err ERR-NO-METADATA)
    )
)

(define-read-only (get-verification-summary (student-id (string-ascii 64)))
    (match (map-get? verification-summary { student-id: student-id })
        summary (ok summary)
        (ok {
            total-weight: u0,
            verification-count: u0,
            last-verified: u0,
            verification-status: "unverified",
        })
    )
)

(define-read-only (get-institutional-verification
        (student-id (string-ascii 64))
        (institution-id (string-ascii 64))
    )
    (map-get? institutional-verifications {
        student-id: student-id,
        institution-id: institution-id,
    })
)

(define-read-only (get-revocation-status (student-id (string-ascii 64)))
    (map-get? revocations { student-id: student-id })
)

(define-read-only (get-appeal-status (student-id (string-ascii 64)))
    (map-get? revocation-appeals { student-id: student-id })
)

(define-read-only (is-transcript-revoked (student-id (string-ascii 64)))
    (is-some (map-get? revocations { student-id: student-id }))
)

(define-public (add-transcript
        (student-id (string-ascii 64))
        (content (string-ascii 1024))
    )
    (let ((existing-transcript (map-get? transcripts { student-id: student-id })))
        (asserts! (is-eq tx-sender contract-caller) ERR-NOT-AUTHORIZED)
        (asserts! (is-none existing-transcript) ERR-TRANSCRIPT-EXISTS)
        (ok (map-set transcripts { student-id: student-id } {
            content: content,
            issuer: tx-sender,
            timestamp: burn-block-height,
            verified: true,
        }))
    )
)

(define-public (verify-transcript (student-id (string-ascii 64)))
    (let ((transcript (map-get? transcripts { student-id: student-id })))
        (asserts! (is-some transcript) ERR-NO-TRANSCRIPT)
        (asserts! (is-eq tx-sender contract-caller) ERR-NOT-AUTHORIZED)
        (ok (map-set transcripts { student-id: student-id }
            (merge (unwrap-panic transcript) { verified: true })
        ))
    )
)

(define-public (grant-access
        (student-id (string-ascii 64))
        (viewer principal)
        (duration uint)
    )
    (let (
            (key-id (var-get next-key-id))
            (expires-at (+ burn-block-height duration))
        )
        (asserts! (is-eq tx-sender contract-caller) ERR-NOT-AUTHORIZED)
        (try! (nft-mint? access-key key-id viewer))
        (map-set access-grants { key-id: key-id } {
            student-id: student-id,
            granted-to: viewer,
            expires-at: expires-at,
        })
        (var-set next-key-id (+ key-id u1))
        (ok key-id)
    )
)

(define-public (view-transcript (key-id uint))
    (let (
            (access-grant (unwrap! (map-get? access-grants { key-id: key-id })
                ERR-INVALID-ACCESS
            ))
            (transcript (unwrap!
                (map-get? transcripts { student-id: (get student-id access-grant) })
                ERR-NO-TRANSCRIPT
            ))
        )
        (asserts! (is-eq (nft-get-owner? access-key key-id) (some tx-sender))
            ERR-NOT-AUTHORIZED
        )
        (asserts! (< burn-block-height (get expires-at access-grant)) ERR-EXPIRED)
        (ok transcript)
    )
)

(define-public (revoke-access (key-id uint))
    (let ((access-grant (unwrap! (map-get? access-grants { key-id: key-id }) ERR-INVALID-ACCESS)))
        (asserts! (is-eq tx-sender contract-caller) ERR-NOT-AUTHORIZED)
        (try! (nft-burn? access-key key-id tx-sender))
        (ok (map-delete access-grants { key-id: key-id }))
    )
)

(define-public (update-transcript-metadata
        (student-id (string-ascii 64))
        (gpa (optional uint))
        (graduation-year (optional uint))
        (degree-type (optional (string-ascii 64)))
        (honors (optional (string-ascii 128)))
        (total-credits (optional uint))
    )
    (begin
        (asserts! (is-eq tx-sender contract-caller) ERR-NOT-AUTHORIZED)
        (asserts! (is-some (map-get? transcripts { student-id: student-id }))
            ERR-NO-TRANSCRIPT
        )
        (ok (map-set transcript-metadata { student-id: student-id } {
            gpa: gpa,
            graduation-year: graduation-year,
            degree-type: degree-type,
            honors: honors,
            total-credits: total-credits,
        }))
    )
)

(define-public (query-students-by-gpa
        (min-gpa uint)
        (max-gpa uint)
    )
    (begin
        (asserts! (is-eq tx-sender contract-caller) ERR-NOT-AUTHORIZED)
        (ok {
            min-gpa: min-gpa,
            max-gpa: max-gpa,
        })
    )
)

(define-public (register-institution
        (institution-id (string-ascii 64))
        (name (string-ascii 128))
        (principal-address principal)
        (verification-weight uint)
    )
    (begin
        (asserts! (is-eq tx-sender contract-caller) ERR-NOT-AUTHORIZED)
        (ok (map-set registered-institutions { institution-id: institution-id } {
            name: name,
            principal-address: principal-address,
            verification-weight: verification-weight,
            active: true,
        }))
    )
)

(define-public (institutional-verify-transcript
        (student-id (string-ascii 64))
        (institution-id (string-ascii 64))
        (signature-hash (buff 32))
        (verification-level uint)
    )
    (let (
            (institution (unwrap!
                (map-get? registered-institutions { institution-id: institution-id })
                ERR-INSTITUTION-NOT-REGISTERED
            ))
            (existing-verification (map-get? institutional-verifications {
                student-id: student-id,
                institution-id: institution-id,
            }))
            (current-summary (default-to {
                total-weight: u0,
                verification-count: u0,
                last-verified: u0,
                verification-status: "unverified",
            }
                (map-get? verification-summary { student-id: student-id })
            ))
        )
        (asserts! (is-some (map-get? transcripts { student-id: student-id }))
            ERR-NO-TRANSCRIPT
        )
        (asserts! (get active institution) ERR-INSTITUTION-NOT-REGISTERED)
        (asserts! (is-eq tx-sender (get principal-address institution))
            ERR-NOT-AUTHORIZED
        )
        (asserts! (is-none existing-verification)
            ERR-ALREADY-VERIFIED-BY-INSTITUTION
        )

        (map-set institutional-verifications {
            student-id: student-id,
            institution-id: institution-id,
        } {
            verifier-principal: tx-sender,
            signature-hash: signature-hash,
            timestamp: burn-block-height,
            verification-level: verification-level,
        })

        (let (
                (new-total-weight (+ (get total-weight current-summary)
                    (get verification-weight institution)
                ))
                (new-count (+ (get verification-count current-summary) u1))
            )
            (map-set verification-summary { student-id: student-id } {
                total-weight: new-total-weight,
                verification-count: new-count,
                last-verified: burn-block-height,
                verification-status: (if (>= new-total-weight u100)
                    "fully-verified"
                    "partially-verified"
                ),
            })
        )
        (ok true)
    )
)

(define-public (deactivate-institution (institution-id (string-ascii 64)))
    (let ((institution (unwrap!
            (map-get? registered-institutions { institution-id: institution-id })
            ERR-INSTITUTION-NOT-REGISTERED
        )))
        (asserts! (is-eq tx-sender contract-caller) ERR-NOT-AUTHORIZED)
        (ok (map-set registered-institutions { institution-id: institution-id }
            (merge institution { active: false })
        ))
    )
)

(define-public (verify-transcript-integrity
        (student-id (string-ascii 64))
        (minimum-weight uint)
    )
    (let ((summary (unwrap! (map-get? verification-summary { student-id: student-id })
            ERR-NO-TRANSCRIPT
        )))
        (asserts! (>= (get total-weight summary) minimum-weight)
            ERR-INSUFFICIENT-VERIFICATIONS
        )
        (ok {
            student-id: student-id,
            total-verification-weight: (get total-weight summary),
            verification-count: (get verification-count summary),
            status: (get verification-status summary),
            last-verified-at: (get last-verified summary),
        })
    )
)

(define-public (revoke-transcript
        (student-id (string-ascii 64))
        (reason-code (string-ascii 32))
        (reason-detail (string-ascii 256))
        (is-permanent bool)
        (evidence-hash (buff 32))
    )
    (let ((transcript (map-get? transcripts { student-id: student-id })))
        (asserts! (is-some transcript) ERR-NO-TRANSCRIPT)
        (asserts! (is-eq tx-sender contract-caller) ERR-NOT-AUTHORIZED)
        (asserts! (is-none (map-get? revocations { student-id: student-id }))
            ERR-TRANSCRIPT-REVOKED
        )
        (ok (map-set revocations { student-id: student-id } {
            revoked-by: tx-sender,
            revoked-at: burn-block-height,
            reason-code: reason-code,
            reason-detail: reason-detail,
            is-permanent: is-permanent,
            evidence-hash: evidence-hash,
        }))
    )
)

(define-public (reinstate-transcript (student-id (string-ascii 64)))
    (let ((revocation (unwrap! (map-get? revocations { student-id: student-id })
            ERR-NOT-REVOKED
        )))
        (asserts! (is-eq tx-sender contract-caller) ERR-NOT-AUTHORIZED)
        (asserts! (not (get is-permanent revocation)) ERR-TRANSCRIPT-REVOKED)
        (ok (map-delete revocations { student-id: student-id }))
    )
)

(define-public (submit-appeal
        (student-id (string-ascii 64))
        (appeal-reason (string-ascii 512))
        (supporting-evidence (buff 32))
    )
    (begin
        (asserts! (is-some (map-get? revocations { student-id: student-id }))
            ERR-NOT-REVOKED
        )
        (asserts! (is-eq tx-sender contract-caller) ERR-NOT-AUTHORIZED)
        (asserts!
            (is-none (map-get? revocation-appeals { student-id: student-id }))
            ERR-APPEAL-EXISTS
        )
        (ok (map-set revocation-appeals { student-id: student-id } {
            appellant: tx-sender,
            appeal-timestamp: burn-block-height,
            appeal-reason: appeal-reason,
            supporting-evidence: supporting-evidence,
            status: "pending",
            reviewed-by: none,
            reviewed-at: none,
            resolution-notes: none,
        }))
    )
)

(define-public (review-appeal
        (student-id (string-ascii 64))
        (approved bool)
        (resolution-notes (string-ascii 256))
    )
    (let ((appeal (unwrap! (map-get? revocation-appeals { student-id: student-id })
            ERR-NO-APPEAL
        )))
        (asserts! (is-eq tx-sender contract-caller) ERR-NOT-AUTHORIZED)
        (map-set revocation-appeals { student-id: student-id }
            (merge appeal {
                status: (if approved
                    "approved"
                    "rejected"
                ),
                reviewed-by: (some tx-sender),
                reviewed-at: (some burn-block-height),
                resolution-notes: (some resolution-notes),
            })
        )
        (if approved
            (begin
                (map-delete revocations { student-id: student-id })
                (ok true)
            )
            (ok false)
        )
    )
)

(define-public (get-transcript-with-status (student-id (string-ascii 64)))
    (let (
            (transcript (unwrap! (map-get? transcripts { student-id: student-id })
                ERR-NO-TRANSCRIPT
            ))
            (revocation (map-get? revocations { student-id: student-id }))
        )
        (ok {
            transcript: transcript,
            is-revoked: (is-some revocation),
            revocation-info: revocation,
        })
    )
)
