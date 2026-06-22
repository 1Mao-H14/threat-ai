# tests/fixtures/entra_events.py
"""
Realistic Entra ID (Azure AD) log dicts for test injection.
These match the exact schema returned by Microsoft Graph API so
entraid_collector._parse_signin() and _parse_audit() work unchanged.
"""

# ── SIGN-IN LOGS ─────────────────────────────────────────────────────────

SIGNIN_SUCCESS_NORMAL = {
    "id": "aab11111-0000-0000-0000-000000000001",
    "createdDateTime": "2026-06-18T09:15:00Z",
    "userPrincipalName": "alice@marwanhamdaoui2020gmail.onmicrosoft.com",
    "status": {"errorCode": 0, "failureReason": None},
    "authenticationRequirement": "multiFactorAuthentication",
    "clientAppUsed": "Browser",
    "riskLevelAggregated": "none",
    "location": {"countryOrRegion": "MA", "city": "Fes"},
    "deviceDetail": {"isCompliant": True, "operatingSystem": "Windows 10"},
}

SIGNIN_FAILED_REPEATED = {
    "id": "aab22222-0000-0000-0000-000000000002",
    "createdDateTime": "2026-06-18T02:31:00Z",
    "userPrincipalName": "alice@marwanhamdaoui2020gmail.onmicrosoft.com",
    "status": {"errorCode": 50126, "failureReason": "Invalid username or password"},
    "authenticationRequirement": "singleFactorAuthentication",
    "clientAppUsed": "Browser",
    "riskLevelAggregated": "high",
    "location": {"countryOrRegion": "RU", "city": "Moscow"},
    "deviceDetail": {"isCompliant": False, "operatingSystem": "Unknown"},
}

SIGNIN_SUCCESS_AFTER_FAILURES = {
    "id": "aab33333-0000-0000-0000-000000000003",
    "createdDateTime": "2026-06-18T02:33:00Z",
    "userPrincipalName": "alice@marwanhamdaoui2020gmail.onmicrosoft.com",
    "status": {"errorCode": 0, "failureReason": None},
    "authenticationRequirement": "singleFactorAuthentication",  # MFA bypassed
    "clientAppUsed": "Browser",
    "riskLevelAggregated": "high",
    "location": {"countryOrRegion": "RU", "city": "Moscow"},
    "deviceDetail": {"isCompliant": False, "operatingSystem": "Unknown"},
}

SIGNIN_LEGACY_AUTH = {
    "id": "aab44444-0000-0000-0000-000000000004",
    "createdDateTime": "2026-06-18T02:30:00Z",
    "userPrincipalName": "alice@marwanhamdaoui2020gmail.onmicrosoft.com",
    "status": {"errorCode": 0},
    "authenticationRequirement": "singleFactorAuthentication",
    "clientAppUsed": "SMTP",   # Legacy auth — bypasses Conditional Access
    "riskLevelAggregated": "medium",
    "location": {"countryOrRegion": "RU", "city": "Moscow"},
    "deviceDetail": {"isCompliant": False},
}

# ── AUDIT LOGS ────────────────────────────────────────────────────────────

AUDIT_GROUP_CHANGE = {
    "id": "aud11111-0000-0000-0000-000000000001",
    "activityDateTime": "2026-06-18T02:41:00Z",
    "activityDisplayName": "Add member to group",
    "category": "GroupManagement",
    "initiatedBy": {
        "user": {
            "userPrincipalName": "alice@marwanhamdaoui2020gmail.onmicrosoft.com",
            "id": "usr-alice-001",
        }
    },
    "targetResources": [
        {"displayName": "Global Administrators", "type": "Group"}
    ],
    "result": "success",
}

AUDIT_MFA_CHANGED = {
    "id": "aud22222-0000-0000-0000-000000000002",
    "activityDateTime": "2026-06-18T02:42:00Z",
    "activityDisplayName": "User registered authentication method",
    "category": "UserManagement",
    "initiatedBy": {
        "user": {
            "userPrincipalName": "alice@marwanhamdaoui2020gmail.onmicrosoft.com",
            "id": "usr-alice-001",
        }
    },
    "targetResources": [
        {"displayName": "alice@marwanhamdaoui2020gmail.onmicrosoft.com", "type": "User"}
    ],
    "result": "success",
}

AUDIT_POLICY_CHANGED = {
    "id": "aud33333-0000-0000-0000-000000000003",
    "activityDateTime": "2026-06-18T02:43:00Z",
    "activityDisplayName": "Update policy",
    "category": "Policy",
    "initiatedBy": {
        "user": {
            "userPrincipalName": "alice@marwanhamdaoui2020gmail.onmicrosoft.com",
            "id": "usr-alice-001",
        }
    },
    "targetResources": [
        {"displayName": "Conditional Access — Require MFA", "type": "Policy"}
    ],
    "result": "success",
}


# ── SCENARIO BUNDLES ──────────────────────────────────────────────────────

SCENARIO_BRUTE_FORCE_TAKEOVER = [
    SIGNIN_LEGACY_AUTH,
    SIGNIN_FAILED_REPEATED,
    SIGNIN_FAILED_REPEATED,
    SIGNIN_FAILED_REPEATED,
    SIGNIN_FAILED_REPEATED,
    SIGNIN_FAILED_REPEATED,
    SIGNIN_FAILED_REPEATED,
    SIGNIN_FAILED_REPEATED,
    SIGNIN_FAILED_REPEATED,
    SIGNIN_FAILED_REPEATED,
    SIGNIN_FAILED_REPEATED,     # 10 failures → brute force threshold
    SIGNIN_SUCCESS_AFTER_FAILURES,
]

SCENARIO_DEFENSE_EVASION = [
    SIGNIN_SUCCESS_AFTER_FAILURES,
    AUDIT_MFA_CHANGED,
    AUDIT_POLICY_CHANGED,
]

SCENARIO_PRIVILEGE_ESCALATION = [
    SIGNIN_SUCCESS_AFTER_FAILURES,
    AUDIT_GROUP_CHANGE,
]

# Full APT chain — combines everything
SCENARIO_FULL_APT = (
    SCENARIO_BRUTE_FORCE_TAKEOVER
    + SCENARIO_DEFENSE_EVASION
    + SCENARIO_PRIVILEGE_ESCALATION
)
