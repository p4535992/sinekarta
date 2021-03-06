package org.sinekartads.dto.formats;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface FlagDTOProperty { 
	String activated() default "true";
	String deactivated() default "false";
}
