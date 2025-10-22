package com.foodrescue.security.contracts;

public final class RbacExpr {

    private RbacExpr() {}

    /* ===== Self checks with custom parameter names ===== */
    public static String selfOrAdminBy(String paramName) {
        // e.g., paramName="userId" -> "hasRole('ADMIN') or #userId == authentication.name"
        return "hasRole('ADMIN') or #" + paramName + " == authentication.name";
    }

    public static String selfOnlyBy(String paramName) {
        return "#" + paramName + " == authentication.name";
    }

    /* ===== Owner checks via ownership bean (custom method name/params) ===== */
    public static String ownerOnly(String ownershipMethod, String idParam) {
        // ownership method signature: isXOwner(String id, String userId)
        return "@ownership." + ownershipMethod + "(#" + idParam + ", authentication.name)";
        // e.g., ownerOnly("isDonationOwner", "id")
    }

    public static String ownerOrAdmin(String ownershipMethod, String idParam) {
        return "hasRole('ADMIN') or " + ownerOnly(ownershipMethod, idParam);
    }

    /* ===== Generic resourceType owner checks ===== */
    public static String ownerOnlyGeneric(String resourceTypeParam, String idParam) {
        return "@ownership.owns(#" + resourceTypeParam + ", #" + idParam + ", authentication.name)";
    }

    public static String ownerOrAdminGeneric(String resourceTypeParam, String idParam) {
        return "hasRole('ADMIN') or " + ownerOnlyGeneric(resourceTypeParam, idParam);
    }

    /* ===== Tenant/org boundary helpers (claims in tokenAttributes) ===== */
    public static String sameTenantOnly(String tenantParam) {
        return "#" + tenantParam + " == authentication.tokenAttributes['tenantId']";
    }

    public static String sameTenantOrAdmin(String tenantParam) {
        return "hasRole('ADMIN') or " + sameTenantOnly(tenantParam);
    }

    public static String sameOrgOnly(String orgParam) {
        return "#" + orgParam + " == authentication.tokenAttributes['orgId']";
    }

    public static String sameOrgOrAdmin(String orgParam) {
        return "hasRole('ADMIN') or " + sameOrgOnly(orgParam);
    }

    /* ===== Combine with role unions ===== */
    public static String roleOrExpr(String roleName, String otherExpr) {
        return "hasRole('" + roleName + "') or (" + otherExpr + ")";
    }

    public static String anyRolesOrExpr(String commaSeparatedRoles, String otherExpr) {
        // e.g. "DONOR,ADMIN" -> "hasAnyRole('DONOR','ADMIN') or (...)"
        String roles = "'" + commaSeparatedRoles.replaceAll("\\s*,\\s*", "','") + "'";
        return "hasAnyRole(" + roles + ") or (" + otherExpr + ")";
    }
}
