(define-constant ERR-NOT-AUTHORIZED (err u200))
(define-constant ERR-EXPIRED (err u201))
(define-constant ERR-NO-ACCESS (err u202))

(define-data-var contract-owner principal tx-sender)

(define-map access-passes
    {
        resource-id: uint,
        user: principal,
    }
    {
        expires-at: uint,
        granted-by: principal,
        granted-at: uint,
    }
)

(define-read-only (get-owner)
    (ok (var-get contract-owner))
)

(define-read-only (has-access
        (resource-id uint)
        (user principal)
    )
    (let ((pass (map-get? access-passes {
            resource-id: resource-id,
            user: user,
        })))
        (match pass
            grant (ok (< burn-block-height (get expires-at grant)))
            (ok false)
        )
    )
)

(define-read-only (get-grant
        (resource-id uint)
        (user principal)
    )
    (ok (map-get? access-passes {
        resource-id: resource-id,
        user: user,
    }))
)

(define-public (grant-access
        (resource-id uint)
        (user principal)
        (expires-at uint)
    )
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (ok (map-set access-passes {
            resource-id: resource-id,
            user: user,
        } {
            expires-at: expires-at,
            granted-by: tx-sender,
            granted-at: burn-block-height,
        }))
    )
)

(define-public (revoke-access
        (resource-id uint)
        (user principal)
    )
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (ok (map-delete access-passes {
            resource-id: resource-id,
            user: user,
        }))
    )
)

(define-public (set-owner (new-owner principal))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (ok (var-set contract-owner new-owner))
    )
)
