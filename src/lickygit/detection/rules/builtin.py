"""Built-in detection rules for well-known secret formats."""

from __future__ import annotations

import re

from lickygit.core.finding import Severity
from lickygit.detection.patterns import PatternRule

_BUILTIN_RULES_CACHE: list[PatternRule] | None = None


def get_builtin_rules() -> list[PatternRule]:
    """Return the full set of built-in pattern rules.

    Each rule targets a specific, well-known secret format from cloud
    providers, SaaS APIs and common credential patterns.

    Rules are compiled once and cached for the lifetime of the process.
    """
    global _BUILTIN_RULES_CACHE
    if _BUILTIN_RULES_CACHE is not None:
        return list(_BUILTIN_RULES_CACHE)

    _BUILTIN_RULES_CACHE = [
        # ── AWS ────────────────────────────────────────────────────────
        PatternRule(
            id="aws-access-key-id",
            name="AWS Access Key ID",
            pattern=re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])"),
            severity=Severity.CRITICAL,
            description="AWS IAM access key identifier.",
        ),
        PatternRule(
            id="aws-mws-key",
            name="AWS MWS Key",
            pattern=re.compile(r"(?<![a-zA-Z0-9])amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![a-zA-Z0-9])"),
            severity=Severity.CRITICAL,
            description="Amazon Marketplace Web Service auth token.",
        ),

        # ── GitHub ─────────────────────────────────────────────────────
        PatternRule(
            id="github-pat-classic",
            name="GitHub Personal Access Token (classic)",
            pattern=re.compile(r"(?<![a-zA-Z0-9])ghp_[0-9a-zA-Z]{36}(?![a-zA-Z0-9])"),
            severity=Severity.CRITICAL,
            description="Classic GitHub personal access token.",
        ),
        PatternRule(
            id="github-pat-fine",
            name="GitHub Fine-Grained Token",
            pattern=re.compile(r"(?<![a-zA-Z0-9])github_pat_[0-9a-zA-Z_]{82}(?![a-zA-Z0-9_])"),
            severity=Severity.CRITICAL,
            description="Fine-grained GitHub personal access token.",
        ),
        PatternRule(
            id="github-oauth",
            name="GitHub OAuth Access Token",
            pattern=re.compile(r"(?<![a-zA-Z0-9])gho_[0-9a-zA-Z]{36}(?![a-zA-Z0-9])"),
            severity=Severity.CRITICAL,
            description="GitHub OAuth access token.",
        ),
        PatternRule(
            id="github-app-token",
            name="GitHub App Token",
            pattern=re.compile(r"(?<![a-zA-Z0-9])(?:ghu|ghs)_[0-9a-zA-Z]{36}(?![a-zA-Z0-9])"),
            severity=Severity.HIGH,
            description="GitHub App user-to-server or server-to-server token.",
        ),

        # ── GitLab ─────────────────────────────────────────────────────
        PatternRule(
            id="gitlab-pat",
            name="GitLab Personal Access Token",
            pattern=re.compile(r"(?<![a-zA-Z0-9])glpat-[0-9a-zA-Z_-]{20,}(?![a-zA-Z0-9_-])"),
            severity=Severity.CRITICAL,
            description="GitLab personal access token.",
        ),
        PatternRule(
            id="gitlab-runner-token",
            name="GitLab Runner Token",
            pattern=re.compile(r"(?<![a-zA-Z0-9])GR1348941[0-9a-zA-Z_-]{20}(?![a-zA-Z0-9_-])"),
            severity=Severity.HIGH,
            description="GitLab CI runner registration token.",
        ),

        # ── Slack ──────────────────────────────────────────────────────
        PatternRule(
            id="slack-bot-token",
            name="Slack Bot Token",
            pattern=re.compile(r"(?<![a-zA-Z0-9])xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}(?![a-zA-Z0-9])"),
            severity=Severity.HIGH,
            description="Slack bot user OAuth token.",
        ),
        PatternRule(
            id="slack-user-token",
            name="Slack User Token",
            pattern=re.compile(r"(?<![a-zA-Z0-9])xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-z0-9]{32}(?![a-zA-Z0-9])"),
            severity=Severity.HIGH,
            description="Slack user OAuth token.",
        ),
        PatternRule(
            id="slack-webhook",
            name="Slack Webhook URL",
            pattern=re.compile(
                r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"
            ),
            severity=Severity.MEDIUM,
            description="Slack incoming webhook URL.",
        ),

        # ── Stripe ─────────────────────────────────────────────────────
        PatternRule(
            id="stripe-secret-key",
            name="Stripe Secret Key",
            pattern=re.compile(r"(?<![a-zA-Z0-9])sk_live_[0-9a-zA-Z]{24,}(?![a-zA-Z0-9])"),
            severity=Severity.CRITICAL,
            description="Stripe live secret API key.",
        ),
        PatternRule(
            id="stripe-publishable-key",
            name="Stripe Publishable Key",
            pattern=re.compile(r"(?<![a-zA-Z0-9])pk_live_[0-9a-zA-Z]{24,}(?![a-zA-Z0-9])"),
            severity=Severity.LOW,
            description="Stripe live publishable key (public, but flagged).",
        ),
        PatternRule(
            id="stripe-restricted-key",
            name="Stripe Restricted Key",
            pattern=re.compile(r"(?<![a-zA-Z0-9])rk_live_[0-9a-zA-Z]{24,}(?![a-zA-Z0-9])"),
            severity=Severity.HIGH,
            description="Stripe restricted API key.",
        ),

        # ── Google / GCP ───────────────────────────────────────────────
        PatternRule(
            id="google-api-key",
            name="Google API Key",
            pattern=re.compile(r"(?<![a-zA-Z0-9])AIza[0-9A-Za-z_-]{35}(?![a-zA-Z0-9_-])"),
            severity=Severity.HIGH,
            description="Google Cloud / Maps / Firebase API key.",
        ),
        PatternRule(
            id="gcp-service-account",
            name="GCP Service Account JSON",
            pattern=re.compile(r'"type"\s*:\s*"service_account"'),
            severity=Severity.CRITICAL,
            description="Google Cloud service account credential file.",
        ),
        PatternRule(
            id="google-oauth-client-secret",
            name="Google OAuth Client Secret",
            pattern=re.compile(r'"client_secret"\s*:\s*"[a-zA-Z0-9_-]{24}"'),
            severity=Severity.HIGH,
            description="Google OAuth client secret value.",
        ),

        # ── Azure ──────────────────────────────────────────────────────
        PatternRule(
            id="azure-subscription-key",
            name="Azure Subscription Key",
            pattern=re.compile(r"(?i)(?:azure|subscription)[_-]?key\s*[=:]\s*['\"]?[0-9a-f]{32}['\"]?"),
            severity=Severity.HIGH,
            description="Azure cognitive services or subscription key.",
        ),
        PatternRule(
            id="azure-connection-string",
            name="Azure Connection String",
            pattern=re.compile(r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+;"),
            severity=Severity.CRITICAL,
            description="Azure Storage connection string.",
        ),

        # ── Twilio ─────────────────────────────────────────────────────
        PatternRule(
            id="twilio-account-sid",
            name="Twilio Account SID",
            pattern=re.compile(r"(?<![a-zA-Z0-9])AC[a-zA-Z0-9]{32}(?![a-zA-Z0-9])"),
            severity=Severity.MEDIUM,
            description="Twilio Account SID.",
        ),
        PatternRule(
            id="twilio-api-key",
            name="Twilio API Key",
            pattern=re.compile(r"(?<![a-zA-Z0-9])SK[a-zA-Z0-9]{32}(?![a-zA-Z0-9])"),
            severity=Severity.HIGH,
            description="Twilio API key SID.",
        ),

        # ── SendGrid ──────────────────────────────────────────────────
        PatternRule(
            id="sendgrid-api-key",
            name="SendGrid API Key",
            pattern=re.compile(r"(?<![a-zA-Z0-9])SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}(?![a-zA-Z0-9_-])"),
            severity=Severity.HIGH,
            description="SendGrid mail API key.",
        ),

        # ── Mailgun ────────────────────────────────────────────────────
        PatternRule(
            id="mailgun-api-key",
            name="Mailgun API Key",
            pattern=re.compile(r"(?<![a-zA-Z0-9])key-[0-9a-zA-Z]{32}(?![a-zA-Z0-9])"),
            severity=Severity.HIGH,
            description="Mailgun API key.",
        ),

        # ── npm / PyPI / Docker ────────────────────────────────────────
        PatternRule(
            id="npm-access-token",
            name="npm Access Token",
            pattern=re.compile(r"(?<![a-zA-Z0-9])npm_[a-zA-Z0-9]{36}(?![a-zA-Z0-9])"),
            severity=Severity.CRITICAL,
            description="npm registry access token.",
        ),
        PatternRule(
            id="pypi-api-token",
            name="PyPI API Token",
            pattern=re.compile(r"(?<![a-zA-Z0-9])pypi-[a-zA-Z0-9_-]{100,}(?![a-zA-Z0-9_-])"),
            severity=Severity.CRITICAL,
            description="PyPI package upload API token.",
        ),
        PatternRule(
            id="dockerhub-pat",
            name="Docker Hub PAT",
            pattern=re.compile(r"(?<![a-zA-Z0-9])dckr_pat_[a-zA-Z0-9_-]{20,}(?![a-zA-Z0-9_-])"),
            severity=Severity.HIGH,
            description="Docker Hub personal access token.",
        ),

        # ── Crypto / Keys ─────────────────────────────────────────────
        PatternRule(
            id="private-key",
            name="Private Key",
            pattern=re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
            severity=Severity.CRITICAL,
            description="PEM-encoded private key header.",
        ),
        PatternRule(
            id="jwt-token",
            name="JSON Web Token",
            pattern=re.compile(r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+"),
            severity=Severity.MEDIUM,
            description="Encoded JWT (may contain claims).",
        ),

        # ── Misc ───────────────────────────────────────────────────────
        PatternRule(
            id="heroku-api-key",
            name="Heroku API Key",
            pattern=re.compile(
                r"(?i)heroku[_-]?(?:api[_-]?)?key\s*[=:]\s*['\"]?"
                r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
            ),
            severity=Severity.HIGH,
            description="Heroku platform API key (UUID format).",
        ),
        PatternRule(
            id="telegram-bot-token",
            name="Telegram Bot Token",
            pattern=re.compile(r"(?<![0-9])[0-9]{8,10}:[a-zA-Z0-9_-]{35}(?![a-zA-Z0-9_-])"),
            severity=Severity.HIGH,
            description="Telegram Bot API token.",
        ),
        PatternRule(
            id="discord-bot-token",
            name="Discord Bot Token",
            pattern=re.compile(r"[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}"),
            severity=Severity.HIGH,
            description="Discord bot or user authentication token.",
        ),
        PatternRule(
            id="shopify-access-token",
            name="Shopify Access Token",
            pattern=re.compile(r"(?<![a-zA-Z0-9])shpat_[a-fA-F0-9]{32}(?![a-fA-F0-9])"),
            severity=Severity.HIGH,
            description="Shopify Admin API access token.",
        ),
        PatternRule(
            id="shopify-shared-secret",
            name="Shopify Shared Secret",
            pattern=re.compile(r"(?<![a-zA-Z0-9])shpss_[a-fA-F0-9]{32}(?![a-fA-F0-9])"),
            severity=Severity.HIGH,
            description="Shopify app shared secret.",
        ),
        PatternRule(
            id="square-access-token",
            name="Square Access Token",
            pattern=re.compile(r"(?<![a-zA-Z0-9])sq0atp-[0-9A-Za-z_-]{22}(?![0-9A-Za-z_-])"),
            severity=Severity.HIGH,
            description="Square (Block) OAuth access token.",
        ),
    ]
    return list(_BUILTIN_RULES_CACHE)
