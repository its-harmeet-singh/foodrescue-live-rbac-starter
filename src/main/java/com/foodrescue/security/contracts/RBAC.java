package com.foodrescue.security.contracts;

public interface RBAC {

    /* ========== Auth state ========== */
    String AUTHENTICATED = "isAuthenticated()";
    String ANONYMOUS     = "isAnonymous()";

    /* ========== Single roles ========== */
    String ADMIN    = "hasRole('ADMIN')";
    String USER     = "hasRole('USER')";
    String DONOR    = "hasRole('DONOR')";
    String RECEIVER = "hasRole('RECEIVER')";
    String COURIER  = "hasRole('COURIER')";

    /* ========== Common unions ========== */
    String USER_OR_ADMIN     = "hasAnyRole('USER','ADMIN')";
    String DONOR_OR_ADMIN    = "hasAnyRole('DONOR','ADMIN')";
    String RECEIVER_OR_ADMIN = "hasAnyRole('RECEIVER','ADMIN')";
    String COURIER_OR_ADMIN  = "hasAnyRole('COURIER','ADMIN')";
    String ANY_ROLE          = "hasAnyRole('USER','ADMIN','DONOR','RECEIVER','COURIER')";

    /* ========== Self checks (match your method param names) ========== */
    // The authenticated principal is the userId (via JwtAuthenticationConverter principalClaimName = "sub")
    String SELF_OR_ADMIN_BY_ID      = "hasRole('ADMIN') or #id == authentication.name";
    String SELF_OR_ADMIN_BY_USER_ID = "hasRole('ADMIN') or #userId == authentication.name";
    String SELF_ONLY_BY_ID          = "#id == authentication.name";
    String SELF_ONLY_BY_USER_ID     = "#userId == authentication.name";

    /* ========== Ownership checks (via @ownership bean) ========== */
    // Generic “owner or admin” patterns; you’ll implement methods in a bean named "ownership".
    // Example bean method signatures you might implement in each service:
    //   Mono<Boolean> isDonationOwner(String id, String userId)
    //   Mono<Boolean> isOrderOwner(String id, String userId)
    //   Mono<Boolean> isAddressOwner(String id, String userId)

    // Donation resource examples
    String DONATION_OWNER_OR_ADMIN_BY_ID = "hasRole('ADMIN') or @ownership.isDonationOwner(#id, authentication.name)";
    String DONATION_OWNER_ONLY_BY_ID     = "@ownership.isDonationOwner(#id, authentication.name)";

    // Order resource examples
    String ORDER_OWNER_OR_ADMIN_BY_ID = "hasRole('ADMIN') or @ownership.isOrderOwner(#id, authentication.name)";
    String ORDER_OWNER_ONLY_BY_ID     = "@ownership.isOrderOwner(#id, authentication.name)";

    // Generic placeholder (if you standardize a single method name)
    // e.g., Ownership#owns(resourceType, id, userId)
    String OWNER_OR_ADMIN_GENERIC = "hasRole('ADMIN') or @ownership.owns(#resourceType, #id, authentication.name)";
    String OWNER_ONLY_GENERIC     = "@ownership.owns(#resourceType, #id, authentication.name)";

    /* ========== Tenant / Organization boundaries (optional) ========== */
    // These assume you add "tenantId" or "orgId" to JWT claims and pass the resource's tenant/org id as a controller param.
    // JWT claim access via SpEL: #jwt.getClaim('tenantId') is not directly available; instead read from authentication.tokenAttributes['tenantId'].
    // With Spring Security JWT -> attributes are in authentication.tokenAttributes
    String SAME_TENANT_ONLY          = "#tenantId == authentication.tokenAttributes['tenantId']";
    String SAME_TENANT_OR_ADMIN      = "hasRole('ADMIN') or (#tenantId == authentication.tokenAttributes['tenantId'])";

    String SAME_ORG_ONLY             = "#orgId == authentication.tokenAttributes['orgId']";
    String SAME_ORG_OR_ADMIN         = "hasRole('ADMIN') or (#orgId == authentication.tokenAttributes['orgId'])";

    /* ========== Scopes / authorities (optional) ========== */
    // If you also mint OAuth2 scopes into authorities like "SCOPE_donation.read"
    String SCOPE_DONATION_READ  = "hasAuthority('SCOPE_donation.read')";
    String SCOPE_DONATION_WRITE = "hasAuthority('SCOPE_donation.write')";
    String SCOPE_ADMIN          = "hasAuthority('SCOPE_admin')";

    /* ========== Read vs write convenience (mix & match) ========== */
    // Example read access: any authenticated or same-tenant
    String READ_DEFAULT  = AUTHENTICATED;
    // Example write access: owner or admin
    String WRITE_DEFAULT = "hasRole('ADMIN') or #ownerId == authentication.name";

    /* ========== Post filters (collection filtering) ========== */
    // Example: only return items owned by the caller or all if ADMIN
    // Usage on methods returning collections: @PostFilter(RBAC.POST_FILTER_OWNER_OR_ADMIN)
    String POST_FILTER_OWNER_ONLY     = "filterObject.ownerId == authentication.name";
    String POST_FILTER_OWNER_OR_ADMIN = "hasRole('ADMIN') or filterObject.ownerId == authentication.name";

    /* ========== “Soft” defaults (update/patch rules) ========== */
    // Allow updates only if ADMIN or same tenant and owner
    String UPDATE_OWNER_SAME_TENANT_OR_ADMIN =
            "hasRole('ADMIN') or (#tenantId == authentication.tokenAttributes['tenantId'] and #ownerId == authentication.name)";
}

