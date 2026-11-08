"""Microsoft tenant / Autodiscover interrogation (TBHM KB §4.1).

TBHM explicitly shows `check_mdi.py` crossed out as **deprecated** because
Microsoft changed `GetFederationInformation`'s behavior -- recon-engine
does not reimplement that broken technique. Instead this implements the
same *goal* (enumerate every domain federated under the same Microsoft
tenant as a known domain) via the still-functioning public
`login.microsoftonline.com/getuserrealm.srf` endpoint, which is the same
public, unauthenticated, no-API-key-needed endpoint that current
community tools (the deck's named replacements: Micah Van Deusen's
Microsoft Tenant Domain Search tool, and tenant-domains.sh) are built on.
"""

from __future__ import annotations

import logging

from recon_engine.utils.http import get_json

logger = logging.getLogger("recon_engine.msft_tenant")

GETUSERREALM_URL = "https://login.microsoftonline.com/getuserrealm.srf"
OPENID_CONFIG_URL = "https://login.microsoftonline.com/{domain}/.well-known/openid-configuration"


def tenant_id_for_domain(domain: str) -> str | None:
    """Resolves a domain to its Azure AD / Entra ID tenant GUID via the
    public OpenID configuration endpoint -- no auth required."""
    data = get_json(OPENID_CONFIG_URL.format(domain=domain), timeout=15)
    if not data:
        return None
    issuer = data.get("issuer", "")
    # issuer looks like: https://sts.windows.net/<tenant-id>/
    parts = [p for p in issuer.split("/") if p]
    return parts[-1] if len(parts) >= 2 else None


def user_realm(domain: str) -> dict:
    """Confirms whether a domain is federated/managed under Microsoft 365
    and returns realm metadata (NameSpaceType: Managed/Federated,
    FederationBrandName, DomainName)."""
    data = get_json(GETUSERREALM_URL, params={"login": f"user@{domain}", "xml": "0"}, timeout=15)
    return data or {}

# NOTE: enumerating every OTHER domain sharing a tenant (the deck's actual
# end goal -- the tesla.com-family domain list the deprecated check_mdi.py
# used to produce) requires either an authenticated Microsoft Graph query
# or a maintained third-party brute-force-and-check tool, since Microsoft
# does not expose a public "list all domains in tenant X" endpoint for
# unauthenticated callers. `tenant_id_for_domain` above is the verification
# primitive: once you have candidate domains from other modules (GitHub,
# certs, permutation), confirm which ones share the SAME tenant ID as your
# target with this function, rather than trusting a name-pattern guess.
