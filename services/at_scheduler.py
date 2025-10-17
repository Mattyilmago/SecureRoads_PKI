"""
Authorization Ticket Scheduler Service

Manages automated scheduling for AA operations:
1. Full CRL publication (weekly)
2. Delta CRL publication (hourly)
3. Expired certificate cleanup (hourly)

**SIMPLIFIED** - Usa CRLManager direttamente (no interface).

Uses Python schedule library with background threading for non-blocking execution.

Standards Reference:
- ETSI TS 102941 V2.1.1 Section 6.3.3: CRL publication requirements

Author: SecureRoad PKI Project
Date: October 2025
"""

import threading
from pathlib import Path
from typing import Callable

import schedule

from protocols.etsi_authorization_ticket import ETSIAuthorizationTicketEncoder
from utils.aa_constants import (
    CRL_DELTA_INTERVAL_HOURS,
    CRL_DELTA_VALIDITY_HOURS,
    CRL_FULL_SCHEDULE_DAY,
    CRL_FULL_SCHEDULE_TIME,
    CRL_FULL_VALIDITY_DAYS,
    EXPIRY_CHECK_INTERVAL_HOURS,
    SCHEDULER_POLL_INTERVAL_SECONDS,
    AT_FILENAME_PATTERN,
)
from utils.logger import PKILogger
from utils.metrics import get_metrics_collector


class ATScheduler:
    """
    Automated scheduler for Authorization Authority tasks.
    
    **SIMPLIFIED** - Duck typing, no formal ABC needed.
    
    Runs background threads for:
    - CRL publication (full + delta)
    - Expired certificate tracking
    
    Thread-safe with proper shutdown handling.
    """
    
    def __init__(
        self,
        aa_id: str,
        crl_manager,  # CRLManager instance (direct, no interface)
        certificates_dir: Path,
        logger: PKILogger
    ):
        """
        Initialize scheduler.
        
        Args:
            aa_id: Authorization Authority identifier
            crl_manager: CRLManager instance for CRL operations
            certificates_dir: Directory containing AT certificates
            logger: Logger instance
        """
        self.aa_id = aa_id
        self.crl_manager = crl_manager  # Direct CRLManager reference
        self.certificates_dir = certificates_dir
        self.logger = logger
        
        # Thread management
        self._scheduler_thread: threading.Thread = None
        self._shutdown_event = threading.Event()
        self._is_running = False
    
    def start(self) -> None:
        """
        Start scheduler threads.
        
        Initializes:
        1. CRL publication scheduler
        2. Expiry check scheduler
        """
        if self._is_running:
            self.logger.warning(f"⚠️ Scheduler already running for {self.aa_id}")
            return
        
        self.logger.info(f"⏰ Starting scheduler for {self.aa_id}...")
        
        # Clear any existing schedules
        schedule.clear(f'aa-{self.aa_id}')
        
        # Schedule Full CRL (weekly, e.g., Sunday 02:30)
        getattr(schedule.every(), CRL_FULL_SCHEDULE_DAY).at(CRL_FULL_SCHEDULE_TIME).do(
            self._publish_full_crl_job
        ).tag(f'aa-{self.aa_id}')
        
        # Schedule Delta CRL (hourly)
        schedule.every(CRL_DELTA_INTERVAL_HOURS).hours.do(
            self._publish_delta_crl_job
        ).tag(f'aa-{self.aa_id}')
        
        # Schedule expiry check (hourly)
        schedule.every(EXPIRY_CHECK_INTERVAL_HOURS).hours.do(
            self._check_expired_certificates_job
        ).tag(f'aa-{self.aa_id}')
        
        # Start background thread
        self._shutdown_event.clear()
        self._scheduler_thread = threading.Thread(
            target=self._run_scheduler_loop,
            daemon=True,
            name=f"AA-{self.aa_id}-Scheduler"
        )
        self._scheduler_thread.start()
        self._is_running = True
        
        self.logger.info(f"✅ Scheduler started successfully")
        self.logger.info(f"   - Full CRL: Every {CRL_FULL_SCHEDULE_DAY} at {CRL_FULL_SCHEDULE_TIME}")
        self.logger.info(f"   - Delta CRL: Every {CRL_DELTA_INTERVAL_HOURS} hour(s)")
        self.logger.info(f"   - Expiry check: Every {EXPIRY_CHECK_INTERVAL_HOURS} hour(s)")
    
    def stop(self, timeout: int = 5) -> None:
        """
        Stop scheduler and wait for threads to finish.
        
        Args:
            timeout: Maximum seconds to wait for shutdown
        """
        if not self._is_running:
            return
        
        self.logger.info(f"⏰ Stopping scheduler for {self.aa_id}...")
        
        # Signal shutdown
        self._shutdown_event.set()
        
        # Wait for thread to finish
        if self._scheduler_thread and self._scheduler_thread.is_alive():
            self._scheduler_thread.join(timeout=timeout)
        
        # Clear schedules
        schedule.clear(f'aa-{self.aa_id}')
        
        self._is_running = False
        self.logger.info(f"✅ Scheduler stopped")
    
    def _run_scheduler_loop(self) -> None:
        """
        Main scheduler loop (runs in background thread).
        """
        self.logger.info(f"Scheduler thread started for {self.aa_id}")
        
        while not self._shutdown_event.is_set():
            try:
                # Run pending scheduled jobs
                schedule.run_pending()
                
                # Sleep with interruptible wait
                self._shutdown_event.wait(timeout=SCHEDULER_POLL_INTERVAL_SECONDS)
                
            except Exception as e:
                self.logger.error(f"❌ Scheduler error: {e}")
                # Continue despite errors
                self._shutdown_event.wait(timeout=SCHEDULER_POLL_INTERVAL_SECONDS)
        
        self.logger.info(f"Scheduler thread stopped for {self.aa_id}")
    
    # ========================================================================
    # SCHEDULED JOBS
    # ========================================================================
    
    def _publish_full_crl_job(self) -> None:
        """
        Scheduled job: Publish Full CRL (weekly).
        """
        try:
            self.logger.info(f"=== SCHEDULER: Publishing Full CRL (weekly) ===")
            self.crl_manager.publish_full_crl(validity_days=CRL_FULL_VALIDITY_DAYS)
            self.logger.info(f"=== SCHEDULER: Full CRL published successfully ===")
        except Exception as e:
            self.logger.error(f"❌ Full CRL publication failed: {e}")
    
    def _publish_delta_crl_job(self) -> None:
        """
        Scheduled job: Publish Delta CRL (hourly).
        
        Only publishes if there are new revocations (optimization).
        """
        try:
            # Check if there are pending revocations
            # Note: CRLManager has delta_revocations attribute
            if hasattr(self.crl_manager, 'delta_revocations'):
                if self.crl_manager.delta_revocations:
                    self.logger.info(f"=== SCHEDULER: Publishing Delta CRL (hourly) ===")
                    self.crl_manager.publish_delta_crl(
                        validity_hours=CRL_DELTA_VALIDITY_HOURS,
                        skip_backup=True  # Performance optimization
                    )
                    self.logger.info(f"=== SCHEDULER: Delta CRL published successfully ===")
                else:
                    self.logger.debug(f"Scheduler: No new revocations, Delta CRL not needed")
            else:
                # Fallback: Always publish
                self.logger.info(f"=== SCHEDULER: Publishing Delta CRL (hourly) ===")
                self.crl_manager.publish_delta_crl(
                    validity_hours=CRL_DELTA_VALIDITY_HOURS,
                    skip_backup=True
                )
                self.logger.info(f"=== SCHEDULER: Delta CRL published successfully ===")
        except Exception as e:
            self.logger.error(f"❌ Delta CRL publication failed: {e}")
    
    def _check_expired_certificates_job(self) -> None:
        """
        Scheduled job: Check for expired AT certificates (hourly).
        
        Decrements active_certificates metric for expired ATs.
        Does not delete files (kept for audit trail).
        """
        try:
            self.logger.debug(f"=== SCHEDULER: Checking expired AT certificates ===")
            
            if not self.certificates_dir.exists():
                self.logger.debug(f"Certificates directory not found: {self.certificates_dir}")
                return
            
            expired_count = 0
            encoder = ETSIAuthorizationTicketEncoder()
            
            # Scan for AT_*.oer files
            for cert_file in self.certificates_dir.glob(AT_FILENAME_PATTERN):
                try:
                    # Load and decode AT certificate
                    with open(cert_file, 'rb') as f:
                        cert_oer = f.read()
                    
                    cert_data = encoder.decode_authorization_ticket(cert_oer)
                    
                    if 'error' in cert_data:
                        self.logger.warning(f"⚠️ Cannot decode {cert_file.name}: {cert_data['error']}")
                        continue
                    
                    # Check if expired
                    from datetime import datetime, timezone
                    expiry_str = cert_data.get('expiry')
                    if expiry_str:
                        expiry_time = datetime.fromisoformat(expiry_str)
                        now = datetime.now(timezone.utc)
                        
                        if expiry_time <= now:
                            # Certificate expired - decrement counter
                            metrics = get_metrics_collector()
                            metrics.decrement_counter('active_certificates')
                            expired_count += 1
                            
                            self.logger.debug(f"Expired AT found: {cert_file.name}")
                
                except Exception as e:
                    self.logger.warning(f"⚠️ Error processing {cert_file.name}: {e}")
                    continue
            
            if expired_count > 0:
                self.logger.info(f"=== SCHEDULER: {expired_count} expired AT(s) found, metrics updated ===")
            else:
                self.logger.debug(f"=== SCHEDULER: No expired AT certificates found ===")
                
        except Exception as e:
            self.logger.error(f"❌ Expiry check failed: {e}")
