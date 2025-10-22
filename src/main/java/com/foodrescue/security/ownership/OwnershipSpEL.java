package com.foodrescue.security.ownership;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * SpEL-friendly bean: exposed as "ownership".
 * Use in annotations:
 *   @PreAuthorize("hasRole('ADMIN') or @ownership.owns('DONATION', #id, authentication.name)")
 */
@Component("ownership")
@RequiredArgsConstructor
public class OwnershipSpEL {

    private final OwnershipEvaluator evaluator;

    /**
     * Generic ownership check usable directly from SpEL.
     */
    public Mono<Boolean> owns(String resourceType, String id, String userId) {
        return evaluator.owns(resourceType, id, userId).defaultIfEmpty(false);
    }
}
