"""
Authorization Authority Constants - ETSI TS 102941 Compliant

Defines all configuration constants for AA operations according to ETSI standards.
Centralizes magic numbers and hardcoded values for maintainability.

Standards Reference:
- ETSI TS 102941 V2.1.1: Trust and Privacy Management
- ETSI TS 103097 V2.1.1: Certificate Formats and Security Headers

Author: SecureRoad PKI Project
Date: October 2025
"""

# ========================================================================
# AUTHORIZATION TICKET VALIDITY (ETSI TS 102941 Section 6.3.3)
# ========================================================================

# Minimum validity for AT certificates (1 hour)
AT_VALIDITY_MIN_HOURS = 1

# Maximum validity for AT certificates (1 week = 168 hours)
# ETSI recommends 1-24 hours for pseudonymity, but allows up to 1 week
AT_VALIDITY_MAX_HOURS = 168

# Default validity for AT certificates (24 hours)
# ETSI TS 102941: Balance between privacy (shorter) and efficiency (longer)
AT_VALIDITY_DEFAULT_HOURS = 24

# ========================================================================
# CRL PUBLICATION SCHEDULE (ETSI TS 102941 Section 6.3.3)
# ========================================================================

# Full CRL publication schedule (weekly, Sunday at 02:30 AM)
# Time chosen to minimize traffic (off-peak hours)
CRL_FULL_SCHEDULE_DAY = "sunday"
CRL_FULL_SCHEDULE_TIME = "02:30"

# Full CRL validity period (7 days)
CRL_FULL_VALIDITY_DAYS = 7

# Delta CRL publication interval (every 1 hour)
# ETSI recommends frequent delta updates for timely revocation
CRL_DELTA_INTERVAL_HOURS = 1

# Delta CRL validity period (24 hours)
CRL_DELTA_VALIDITY_HOURS = 24

# ========================================================================
# SCHEDULER CONFIGURATION
# ========================================================================

# Scheduler polling interval (60 seconds)
SCHEDULER_POLL_INTERVAL_SECONDS = 60

# Certificate expiry check interval (1 hour)
EXPIRY_CHECK_INTERVAL_HOURS = 1

# ========================================================================
# BUTTERFLY KEY EXPANSION (ETSI TS 102941 Section 6.3.3)
# ========================================================================

# Maximum number of AT certificates in a single butterfly batch
# ETSI TS 102941: Recommended limit for performance and privacy
BUTTERFLY_MAX_BATCH_SIZE = 100

# Minimum batch size (at least 1 certificate required)
BUTTERFLY_MIN_BATCH_SIZE = 1

# ========================================================================
# ITS APPLICATION PERMISSIONS (ETSI EN 302 637)
# ========================================================================

# Default ITS application permissions (ONLY CAM and DENM as per ETSI base)
DEFAULT_APP_PERMISSIONS = ['CAM', 'DENM']

# CAM: Cooperative Awareness Message (ETSI EN 302 637-2)
# DENM: Decentralized Environmental Notification Message (ETSI EN 302 637-3)

# ========================================================================
# TRAFFIC PRIORITY LEVELS (ETSI TS 103097)
# ========================================================================

PRIORITY_NORMAL = 0      # Normal traffic
PRIORITY_HIGH = 5        # High priority (e.g., public transport)
PRIORITY_EMERGENCY = 7   # Emergency vehicles

# ========================================================================
# FILE EXTENSIONS (Managed by PKIPathManager)
# ========================================================================

# Authorization Ticket file extension (ASN.1 OER binary format)
AT_FILE_EXTENSION = ".oer"

# ========================================================================
# FILENAME PATTERNS (Managed by PKIPathManager)
# ========================================================================

# Authorization Ticket filename pattern (for glob search)
AT_FILENAME_PATTERN = "AT_*.oer"

# ========================================================================
# LOGGING CONFIGURATION
# ========================================================================

# Log emoji symbols for consistency
LOG_EMOJI_SUCCESS = "✅"
LOG_EMOJI_ERROR = "❌"
LOG_EMOJI_WARNING = "⚠️"
LOG_EMOJI_INFO = "ℹ️"
LOG_EMOJI_SECURITY = "🔐"
LOG_EMOJI_SCHEDULER = "⏰"

# ========================================================================
# THREAD CONFIGURATION
# ========================================================================

# Maximum time to wait for scheduler shutdown (seconds)
SCHEDULER_SHUTDOWN_TIMEOUT = 5

# Thread names
THREAD_NAME_CRL_SCHEDULER = "AA-{aa_id}-CRL-Scheduler"
THREAD_NAME_EXPIRY_CHECKER = "AA-{aa_id}-Expiry-Checker"

# ========================================================================
# VALIDATION MODES
# ========================================================================

VALIDATION_MODE_TLM = "TLM"      # Trust List Manager (modern, ETSI-compliant)
