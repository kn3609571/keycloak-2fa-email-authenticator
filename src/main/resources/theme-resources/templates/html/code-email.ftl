<#import "template.ftl" as layout>
<@layout.emailLayout>
${kcSanitize(msg("emailCodeBodyHtml", code, ttl))?no_esc}
</@layout.emailLayout>
