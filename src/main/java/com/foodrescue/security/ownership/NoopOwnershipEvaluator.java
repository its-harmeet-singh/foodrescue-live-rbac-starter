package com.foodrescue.security.ownership;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * Fallback evaluator: always returns false.
 * Ensures @ownership SpEL never blows up even if a service forgets to implement OwnershipEvaluator.
 */
@Component
@ConditionalOnMissingBean(OwnershipEvaluator.class)
public class NoopOwnershipEvaluator implements OwnershipEvaluator {
    private static final Logger log = LoggerFactory.getLogger(NoopOwnershipEvaluator.class);

    @Override
    public Mono<Boolean> owns(String resourceType, String resourceId, String userId) {
        log.warn("No OwnershipEvaluator bean found. Denying ownership for {}:{}", resourceType, resourceId);
        return Mono.just(false);
    }
}
