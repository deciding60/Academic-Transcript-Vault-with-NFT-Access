(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-INVALID-ACCESS (err u101))
(define-constant ERR-TRANSCRIPT-EXISTS (err u102))
(define-constant ERR-NO-TRANSCRIPT (err u103))
(define-constant ERR-EXPIRED (err u104))
(define-constant ERR-NO-METADATA (err u105))
(define-constant ERR-INSTITUTION-NOT-REGISTERED (err u106))
(define-constant ERR-ALREADY-VERIFIED-BY-INSTITUTION (err u107))
(define-constant ERR-INSUFFICIENT-VERIFICATIONS (err u108))

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
