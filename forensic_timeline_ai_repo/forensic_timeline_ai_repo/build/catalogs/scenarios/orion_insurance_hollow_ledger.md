# Scenario: Operation Hollow Ledger

Orion Insurance is a hybrid-cloud healthcare insurer. An attacker password-sprays a backup service account, succeeds through MFA fatigue/social engineering, reuses that identity across Entra and AWS, enumerates S3 buckets, reads `claims-prod`, lands code execution on `APP01`, and triggers a CrowdStrike suspicious PowerShell download from `https://evil.example/path`. The attacker probes SaaS exports and poisons an internal RAG assistant to summarize restricted claim workflow notes.

## Investigation goals

1. Correlate Entra sign-in with AWS CloudTrail and Falcon
2. Extract IOCs from the verified timeline
3. Determine SaaS scope
4. Assess prompt injection, RAG poisoning, or tool abuse
5. Produce executive/analyst summaries without letting AI modify evidence
