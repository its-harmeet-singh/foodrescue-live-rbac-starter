package com.foodrescue.security.autoconfig;

import com.foodrescue.security.ownership.OwnershipEvaluator;
import com.foodrescue.security.ownership.OwnershipSpEL;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

/**
 * Ensures a SpEL bean named "ownership" is present.
 * If the app supplies an OwnershipEvaluator bean, we’ll use it.
 * Otherwise, NoopOwnershipEvaluator (Component) will kick in.
 */
@AutoConfiguration
public class OwnershipAutoConfiguration {

    @Bean("ownership")
    @ConditionalOnMissingBean(name = "ownership")
    public OwnershipSpEL ownershipSpEL(OwnershipEvaluator evaluator) {
        return new OwnershipSpEL(evaluator);
    }
}
