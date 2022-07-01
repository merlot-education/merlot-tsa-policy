# GDPR Compliance Document
The objective of this document is to detail, the data being stored and proccessed by the Trust Service API.

## What information is stored
### Source User Information
The Open Id connect claims that MAY contain all sorts of personal data (like email, name, age and others), are received from any external source.

### Technical User Information (Public)

- Schema information (public)
- Credential/credential definition ids and states
- DID of issuer
- DID of holder
- Created/updated dates
- Offered credential attributes and attachments

## How is the information stored
### Source User Information
Source User Information is encrypted using the Private Key of the Organizations SSI Agent and stored until the issuance of credential in Organization's SSI Agent's PostgreSQL database.

### Technical User Information (Public)
Technical User Information is encrypted using the Private Key of the Organizations SSI Agent and stored internally (on the agent) on PostgreSQL and externally/ metadata (shared between the OCM services) on PostgreSQL of Organization.

## Who can access the information
The Source User Information and Technical User Information both are accessible only by the Organization specific SSI agent's private key.

## How long will the information stay 
### Source User Information
The Source User Information is wiped out once the credential is issued.

### Technical User Information (Public)
The Technical User Information is wiped out according to the retention periods (not defined yet).
