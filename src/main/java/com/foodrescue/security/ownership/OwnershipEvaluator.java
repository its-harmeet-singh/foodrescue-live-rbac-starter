package com.foodrescue.security.ownership;

import reactor.core.publisher.Mono;

/**
 * SPI for per-service ownership checks.
 * Implement this in each microservice and declare it as a Spring bean.
 *
 * Example service impl:
 *   @Component
 *   public class DonationOwnership implements OwnershipEvaluator {
 *     private final DonationRepository repo;
 *     public Mono<Boolean> owns(String resourceType, String id, String userId) {
 *       if (!"DONATION".equals(resourceType)) return Mono.just(false);
 *       return repo.existsByIdAndDonorId(id, userId);
 *     }
 *   }
 */
public interface OwnershipEvaluator {
    /**
     * Return true if the given userId is considered the owner of the resource.
     * @param resourceType  A short code like "DONATION", "ORDER", "ADDRESS"
     * @param resourceId    The resource id (e.g., document id)
     * @param userId        The authenticated principal id (usually JWT sub)
     */
    Mono<Boolean> owns(String resourceType, String resourceId, String userId);
}
