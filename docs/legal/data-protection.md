# Data Protection

Last updated: May 20, 2026

These terms describe operational data protection expectations for BreachScope.

## Roles

For account, product analytics, security, and site operations, the service operator generally acts as an independent controller. For scan data, findings, project records, integration metadata, and customer-supplied provider keys processed through the service, the operator generally acts as a processor or service provider on behalf of the customer.

## Processing Instructions

BreachScope processes customer data to provide the product, secure the service, troubleshoot issues, comply with law, and complete workflows the customer enables.

## Security Measures

- Scoped dashboard API keys for automation.
- Hashing for authentication API keys.
- AES-256-GCM encryption for saved provider keys.
- Payload validation and upload size limits.
- Audit logs for sensitive project activity.
- Sandbox defaults that exclude local environment files unless explicitly included.
- Rate limiting support through Upstash Redis configuration.

## Deletion

Scan records and findings can be deleted through available dashboard controls. Account, audit, security, and backup records may remain for a limited period where needed for legal, security, continuity, or dispute-resolution reasons.

## Incidents

If BreachScope becomes aware of unauthorized access to customer data, the operator should investigate, contain the issue, preserve relevant logs, and notify affected customers without undue delay where notification is required.
