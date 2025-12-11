"""
Enhanced Email Validator with comprehensive validation features.
Supports syntax validation, DNS verification, and security checks.
"""
import re
import dns.resolver  # type: ignore
import time
import json
import logging
import csv
import io
from typing import List, Dict, Any, Tuple, TypedDict, Optional, DefaultDict
from datetime import datetime, timezone
from dataclasses import dataclass
from collections import defaultdict
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load .env from current directory
load_dotenv()

# accessing the .env constant COMPANY_DOMAINS
raw_domains = os.getenv("COMPANY_DOMAINS", "")
LOCAL_DOMAINS: list[str] = [d.strip() for d in raw_domains.split(",") if d.strip()]

# ==================== TYPE DEFINITIONS ====================

class SyntaxValidationDetails(TypedDict, total=False):
    """Type definition for syntax validation results."""
    email: str
    local_part: str
    domain: str
    domain_parts: List[str]
    checks_passed: List[str]
    checks_failed: List[str]
    suggestions: List[str]


class DNSInfo(TypedDict, total=False):
    """Type definition for DNS query results."""
    domain: str
    has_mx: bool
    has_a: bool
    has_aaaa: bool
    has_txt: bool
    mx_records: List[Dict[str, Any]]
    txt_records: List[str]
    a_records: List[str]
    aaaa_records: List[str]
    error: Optional[str]
    timestamp: str


class SecurityChecks(TypedDict, total=False):
    """Type definition for security check results."""
    is_disposable: bool
    is_free_provider: bool
    has_spf: bool
    has_dmarc: bool
    spf_record: Optional[str]
    dmarc_record: Optional[str]
    suggestions: List[str]
    warnings: List[str]


class ValidationDetails(TypedDict, total=False):
    """Type definition for complete validation details."""
    syntax: SyntaxValidationDetails
    domain: Dict[str, Any]
    security: SecurityChecks
    overall_score: float
    error: Optional[str]
    syntax_details: SyntaxValidationDetails
    domain_details: Dict[str, Any]


class ValidationResultDict(TypedDict, total=False):
    """Type definition for serialized validation results."""
    email: str
    is_valid: bool
    validation_level: str
    timestamp: str
    details: ValidationDetails


class BulkResults(TypedDict, total=False):
    """Type definition for bulk validation results."""
    total_emails: int
    unique_emails: int
    valid: int
    invalid: int
    validation_time: Optional[float]
    emails_per_second: float
    valid_percentage: float
    details: List[ValidationResultDict]
    summary_by_domain: DefaultDict[str, Dict[str, int]]
    statistics: Dict[str, Any]


# ==================== DATA CLASSES ====================

@dataclass
class ValidationResult:
    """Data class for structured validation results."""
    email: str
    is_valid: bool
    validation_level: str
    timestamp: datetime
    details: ValidationDetails
    
    def to_dict(self) -> ValidationResultDict:
        """Convert to dictionary for serialization."""
        result: ValidationResultDict = {
            "email": self.email,
            "is_valid": self.is_valid,
            "validation_level": self.validation_level,
            "timestamp": self.timestamp.isoformat(),
            "details": self.details
        }
        return result


@dataclass
class DNSCacheEntry:
    """Data class for DNS cache entries."""
    data: DNSInfo
    timestamp: datetime
    ttl: int
    
    def is_expired(self) -> bool:
        """Check if cache entry has expired."""
        now = datetime.now(timezone.utc)
        if self.timestamp.tzinfo is None:
            # If timestamp is naive, assume UTC
            timestamp_utc = self.timestamp.replace(tzinfo=timezone.utc)
        else:
            timestamp_utc = self.timestamp.astimezone(timezone.utc)
        
        return (now - timestamp_utc).total_seconds() > self.ttl


# ==================== MAIN VALIDATOR CLASS ====================

class EnhancedEmailValidator:
    """
    Advanced email validator with caching, threading, and comprehensive checks.
    """
    # Common disposable email domains (truncated - would be larger in production)
    DISPOSABLE_DOMAINS = {
        'tempmail.com', '10minutemail.com', 'guerrillamail.com',
        'mailinator.com', 'yopmail.com', 'throwawaymail.com',
        'maildrop.cc', 'fakeinbox.com', 'trashmail.com'
    }
    
    # Common free email providers
    FREE_PROVIDERS = {
        'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
        'icloud.com', 'aol.com', 'protonmail.com', 'zoho.com',
        'gmx.com', 'yandex.com', 'mail.com'
    }
    
    # Construtor 
    def __init__(
        self,
        cache_ttl: int = 300,
        dns_timeout: int = 5,
        max_workers: int = 5,
        rate_limit_delay: float = 0.1,
        scoring_weights: Optional[Dict[str, int]] = None
    ):
        """
        Initialize the email validator.
        
        Args:
            cache_ttl: DNS cache time-to-live in seconds
            dns_timeout: DNS query timeout in seconds
            max_workers: Maximum threads for parallel processing
            rate_limit_delay: Delay between DNS queries to avoid rate limiting
            scoring_weights: Custom weights for validation scoring
        """
        # RFC 5322 compliant email regex
        self.email_regex = re.compile(r'''
            ^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+          # Local part
            @                                          # @ symbol
            (?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+  # Subdomains
            [a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$        # TLD
        ''', re.VERBOSE)
        
        # local domains set up
        self.local_domains: set[str] = set(LOCAL_DOMAINS)
        self.validation_cache: Dict[str, DNSCacheEntry] = {}
        self.cache_ttl = cache_ttl
        self.dns_timeout = dns_timeout
        self.max_workers = max_workers
        self.rate_limit_delay = rate_limit_delay
        self.last_query_time = 0.0
        self._cache_lock = threading.Lock()
        
        # Configurable scoring weights
        self.scoring_weights = scoring_weights or {
            "syntax": 30,
            "domain": 40,
            "has_spf": 10,
            "has_dmarc": 10,
            "not_disposable": 10
        }
        
        # Configure DNS resolver
        try:
            self.resolver = dns.resolver.Resolver(configure=False)
            self.resolver.nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
            self.resolver.timeout = dns_timeout
            self.resolver.lifetime = dns_timeout * 2
            dns.resolver.default_resolver = self.resolver
        except Exception as e:
            logger.warning("Could not configure custom DNS resolver: %s", str(e))
            # Fall back to system resolver
        
        logger.info("EmailValidator initialized with %d max workers", max_workers)
    
    def _apply_rate_limit(self) -> None:
        """Apply rate limiting between DNS queries."""
        current_time = time.time()
        time_since_last = current_time - self.last_query_time
        if time_since_last < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - time_since_last)
        self.last_query_time = time.time()
    
    def is_valid_syntax(self, email: str) -> Tuple[bool, SyntaxValidationDetails]:
        """
        Validate email syntax with detailed diagnostics.
        
        Returns:
            Tuple of (is_valid, details_dict)
        """
        details: SyntaxValidationDetails = {
            "email": email,
            "checks_passed": [],
            "checks_failed": [],
            "suggestions": []
        }
        
        # Basic checks
        if not email:
            details["checks_failed"].append("Email is empty")
            return False, details
        
        if len(email) > 254:
            details["checks_failed"].append(f"Email length {len(email)} > 254 characters")
            return False, details
        
        # Check for @ symbol
        if '@' not in email:
            details["checks_failed"].append("Missing @ symbol")
            return False, details
        
        # Split email
        try:
            local_part, domain = email.rsplit('@', 1)
        except ValueError:
            details["checks_failed"].append("Invalid email format")
            return False, details
        
        # Length checks
        if len(local_part) > 64:
            details["checks_failed"].append(f"Local part '{local_part}' exceeds 64 characters")
        
        if len(domain) > 253:
            details["checks_failed"].append(f"Domain '{domain}' exceeds 253 characters")
        
        # Pattern checks
        if local_part.startswith('.') or local_part.endswith('.'):
            details["checks_failed"].append("Local part cannot start or end with dot")
        
        if '..' in local_part:
            details["checks_failed"].append("Local part contains consecutive dots")
        
        if '..' in domain:
            details["checks_failed"].append("Domain contains consecutive dots")
        
        # Regex validation
        if not self.email_regex.match(email):
            details["checks_failed"].append("Does not match RFC 5322 email format")
        
        # Add domain info
        details["local_part"] = local_part
        details["domain"] = domain
        details["domain_parts"] = domain.split('.')
        
        # Determine validity
        is_valid = len(details["checks_failed"]) == 0
        if is_valid:
            details["checks_passed"] = [
                "Valid length", "Contains @ symbol", "Valid local part",
                "Valid domain format", "RFC 5322 compliant"
            ]
        
        return is_valid, details
    
    def check_domain_records(self, domain: str) -> DNSInfo:
        """
        Comprehensive domain DNS checks with caching.
        
        Args:
            domain: Domain to check
            
        Returns:
            Dictionary with DNS information
        """
        # Check cache first
        cache_key = f"dns_{domain}"
        with self._cache_lock:
            if cache_key in self.validation_cache:
                cache_entry = self.validation_cache[cache_key]
                if not cache_entry.is_expired():
                    logger.debug("Cache hit for domain: %s", domain)
                    return cache_entry.data
        
        # Apply rate limiting
        self._apply_rate_limit()
        
        result: DNSInfo = {
            "domain": domain,
            "has_mx": False,
            "has_a": False,
            "has_aaaa": False,
            "has_txt": False,
            "mx_records": [],
            "txt_records": [],
            "a_records": [],
            "aaaa_records": [],
            "error": None,
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            # Check MX records
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                result["has_mx"] = True
                result["mx_records"] = sorted([
                    {"priority": mx.preference, "exchange": str(mx.exchange).rstrip('.')}
                    for mx in mx_records
                ], key=lambda x: x["priority"])
                logger.debug("Found %d MX records for %s", len(mx_records), domain)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                logger.debug("No MX records found for %s", domain)
            except Exception as e:
                logger.warning("Error checking MX records for %s: %s", domain, str(e))
            
            # Check A records
            try:
                a_records = dns.resolver.resolve(domain, 'A')
                result["has_a"] = True
                result["a_records"] = [str(record) for record in a_records]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            # Check AAAA records
            try:
                aaaa_records = dns.resolver.resolve(domain, 'AAAA')
                result["has_aaaa"] = True
                result["aaaa_records"] = [str(record) for record in aaaa_records]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            # Check TXT records (for SPF/DMARC)
            try:
                txt_records = dns.resolver.resolve(domain, 'TXT')
                result["has_txt"] = True
                result["txt_records"] = [str(record).strip('"') for record in txt_records]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            # Cache the result
            with self._cache_lock:
                self.validation_cache[cache_key] = DNSCacheEntry(
                    data=result,
                    timestamp=datetime.now(),
                    ttl=self.cache_ttl
                )
            
        except dns.resolver.NoNameservers:
            result["error"] = "No DNS nameservers found"
            logger.error("No nameservers for domain: %s", domain)
        except dns.resolver.Timeout:
            result["error"] = "DNS query timeout"
            logger.warning("DNS timeout for domain: %s", domain)
        except Exception as e:
            result["error"] = f"DNS error: {str(e)}"
            logger.error("Unexpected DNS error for %s: %s", domain, str(e))
        
        return result
    
    def is_domain_valid(self, domain: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Validate if domain can receive email.
        
        Args:
            domain: Domain to validate
            
        Returns:
            Tuple of (is_valid, validation_details)
        """
        # Check local domains
        if domain in self.local_domains:
            return True, {
                "type": "local_domain",
                "domain": domain,
                "reason": "Domain is in local domains list"
            }
        
        # Perform DNS checks
        dns_info = self.check_domain_records(domain)
        
        # Determine validity
        is_valid = dns_info["has_mx"] or dns_info["has_a"] or dns_info["has_aaaa"]
        
        details = {
            "type": "internet_domain",
            "domain": domain,
            "dns_info": dns_info,
            "has_mx": dns_info["has_mx"],
            "has_a": dns_info["has_a"],
            "has_aaaa": dns_info["has_aaaa"]
        }
        
        if dns_info.get("error"):
            details["warning"] = dns_info["error"]
        
        if not is_valid:
            details["reason"] = "No MX, A, or AAAA records found"
        
        return is_valid, details
    
    def perform_security_checks(self, email: str, domain: str) -> SecurityChecks:
        """
        Perform security and quality checks on email/domain.
        """
        checks: SecurityChecks = {
            "is_disposable": domain.lower() in self.DISPOSABLE_DOMAINS,
            "is_free_provider": domain.lower() in self.FREE_PROVIDERS,
            "has_spf": False,
            "has_dmarc": False,
            "spf_record": None,
            "dmarc_record": None,
            "suggestions": [],
            "warnings": []
        }
        
        # Check SPF
        dns_info = self.check_domain_records(domain)
        for txt_record in dns_info.get("txt_records", []):
            if 'v=spf1' in txt_record.lower():
                checks["has_spf"] = True
                checks["spf_record"] = txt_record
                break
        
        # Check DMARC
        dmarc_domain = f"_dmarc.{domain}"
        dmarc_info = self.check_domain_records(dmarc_domain)
        for txt_record in dmarc_info.get("txt_records", []):
            if 'v=dmarc1' in txt_record.lower():
                checks["has_dmarc"] = True
                checks["dmarc_record"] = txt_record
                break
        
        # Generate suggestions
        if checks["is_disposable"]:
            checks["suggestions"].append(
                "This appears to be a disposable/temporary email address. "
                "Consider using a permanent email for important communications."
            )
            checks["warnings"].append("Disposable email detected")
        
        elif checks["is_free_provider"]:
            checks["suggestions"].append(
                "For professional or business use, consider using a custom domain email."
            )
        
        if not checks["has_spf"]:
            checks["warnings"].append("No SPF record found - email spoofing possible")
            checks["suggestions"].append(
                "The domain lacks SPF records, which helps prevent email spoofing."
            )
        
        if not checks["has_dmarc"]:
            checks["warnings"].append("No DMARC record found")
        
        return checks
    
    def _calculate_validation_score(self, security_checks: SecurityChecks) -> float:
        """Calculate an overall validation score (0-100)."""
        score = 0
        
        # Syntax and domain are always valid at this point (called from validate_email)
        score += self.scoring_weights.get("syntax", 30)
        score += self.scoring_weights.get("domain", 40)
        
        # Security bonuses
        if security_checks.get("has_spf"):
            score += self.scoring_weights.get("has_spf", 10)
        
        if security_checks.get("has_dmarc"):
            score += self.scoring_weights.get("has_dmarc", 10)
        
        if not security_checks.get("is_disposable"):
            score += self.scoring_weights.get("not_disposable", 10)
        
        return min(score, 100)
    
    def validate_email(self, email: str) -> ValidationResult:
        """
        Comprehensive email validation with all checks.
        
        Args:
            email: Email address to validate
            
        Returns:
            ValidationResult object
        """
        logger.info("Validating email: %s", email)
        
        # Step 1: Syntax validation
        syntax_valid, syntax_details = self.is_valid_syntax(email)
        if not syntax_valid:
            return ValidationResult(
                email=email,
                is_valid=False,
                validation_level="syntax",
                timestamp=datetime.now(),
                details={
                    "error": "Syntax validation failed",
                    "syntax_details": syntax_details
                }
            )
        
        domain = syntax_details["domain"]
        
        # Step 2: Domain validation
        domain_valid, domain_details = self.is_domain_valid(domain)
        if not domain_valid:
            return ValidationResult(
                email=email,
                is_valid=False,
                validation_level="domain",
                timestamp=datetime.now(),
                details={
                    "error": "Domain validation failed",
                    "domain_details": domain_details
                }
            )
        
        # Step 3: Security checks
        security_checks = self.perform_security_checks(email, domain)
        
        # Step 4: Compile final result
        details: ValidationDetails = {
            "syntax": syntax_details,
            "domain": domain_details,
            "security": security_checks,
            "overall_score": self._calculate_validation_score(security_checks)
        }
        
        return ValidationResult(
            email=email,
            is_valid=True,
            validation_level="comprehensive",
            timestamp=datetime.now(),
            details=details
        )
    
    def validate_bulk_emails(
        self, 
        emails: List[str], 
        parallel: bool = True
    ) -> BulkResults:
        """
        Validate multiple emails, optionally in parallel.
        
        Args:
            emails: List of email addresses
            parallel: Whether to use parallel processing
            
        Returns:
            Dictionary with validation results
        """
        logger.info("Starting bulk validation of %d emails", len(emails))
        
        # Remove duplicates and normalize
        unique_emails: List[str] = []
        seen: set[str] = set()
        for email in emails:
            normalized = email.strip().lower()
            if normalized and normalized not in seen:
                seen.add(normalized)
                unique_emails.append(normalized)
        
        results: BulkResults = {
            "total_emails": len(emails),
            "unique_emails": len(unique_emails),
            "valid": 0,
            "invalid": 0,
            "validation_time": None,
            "emails_per_second": 0.0,
            "valid_percentage": 0.0,
            "details": [],
            "summary_by_domain": defaultdict(lambda: {"valid": 0, "invalid": 0}),
            "statistics": {}
        }
        
        start_time = time.time()
        
        if parallel and len(unique_emails) > 1:
            # Parallel processing
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_email = {
                    executor.submit(self.validate_email, email): email 
                    for email in unique_emails
                }
                
                for future in as_completed(future_to_email):
                    try:
                        result = future.result()
                        self._process_validation_result(result, results)
                    except Exception as e:
                        email = future_to_email[future]
                        logger.error("Error validating %s: %s", email, str(e))
                        self._process_error_result(email, str(e), results)
        else:
            # Sequential processing
            for email in unique_emails:
                try:
                    result = self.validate_email(email)
                    self._process_validation_result(result, results)
                except Exception as e:
                    logger.error("Error validating %s: %s", email, str(e))
                    self._process_error_result(email, str(e), results)
        
        # Calculate statistics
        validation_time = time.time() - start_time
        results["validation_time"] = validation_time
        
        if validation_time > 0:
            results["emails_per_second"] = len(unique_emails) / validation_time
        else:
            results["emails_per_second"] = float('inf') if unique_emails else 0.0
            logger.warning("Validation completed in near-zero time")
        
        if unique_emails:
            results["valid_percentage"] = (results["valid"] / len(unique_emails)) * 100
        else:
            results["valid_percentage"] = 0.0
            logger.warning("No valid emails to validate")
        
        logger.info(
            "Bulk validation completed: %d valid, %d invalid (%.2f%%) in %.2f seconds",
            results["valid"], results["invalid"], results["valid_percentage"],
            results["validation_time"]
        )
        
        return results
    
    def _process_validation_result(
        self, 
        result: ValidationResult, 
        results: BulkResults
    ) -> None:
        """Process a single validation result."""
        results["details"].append(result.to_dict())
        
        if result.is_valid:
            results["valid"] += 1
        else:
            results["invalid"] += 1
        
        # Update domain summary
        domain = result.email.split('@')[1] if '@' in result.email else 'unknown'
        if result.is_valid:
            results["summary_by_domain"][domain]["valid"] += 1
        else:
            results["summary_by_domain"][domain]["invalid"] += 1
    
    def _process_error_result(
        self, 
        email: str, 
        error: str, 
        results: BulkResults
    ) -> None:
        """Process a validation error."""
        error_result = ValidationResult(
            email=email,
            is_valid=False,
            validation_level="error",
            timestamp=datetime.now(),
            details={"error": error}
        )
        results["details"].append(error_result.to_dict())
        results["invalid"] += 1
        results["summary_by_domain"]["error"]["invalid"] += 1
    
    def generate_report(
        self, 
        results: BulkResults, 
        format: str = "text"
    ) -> str:
        """
        Generate validation report in specified format.
        
        Args:
            results: Validation results from validate_bulk_emails
            format: Output format ("text", "json", "csv")
            
        Returns:
            Formatted report string
            
        Raises:
            ValueError: If format is not supported
        """
        if format == "json":
            return json.dumps(results, indent=2, default=str)
        
        elif format == "csv":
            return self._generate_csv_report(results)
        
        elif format == "text":
            return self._generate_text_report(results)
        
        else:
            raise ValueError(f"Unsupported format: {format}. Use 'text', 'json', or 'csv'.")
    
    def _generate_text_report(self, results: BulkResults) -> str:
        """Generate human-readable text report."""
        report_lines = []
        
        # Header
        report_lines.append("=" * 70)
        report_lines.append("EMAIL VALIDATION REPORT")
        report_lines.append("=" * 70)
        
        # Summary
        report_lines.append(f"Summary:")
        report_lines.append(f"  Total emails: {results['total_emails']}")
        report_lines.append(f"  Unique emails: {results['unique_emails']}")
        report_lines.append(f"  Valid: {results['valid']} ({results['valid_percentage']:.1f}%)")
        report_lines.append(f"  Invalid: {results['invalid']}")
        report_lines.append(f"  Validation time: {results['validation_time']:.2f} seconds")
        report_lines.append(f"  Speed: {results['emails_per_second']:.1f} emails/second")
        
        # Details
        report_lines.append("\n" + "-" * 70)
        report_lines.append("Validation Details:")
        
        for detail in results["details"][:10]:  # Show first 10
            status = "✅ VALID" if detail["is_valid"] else "❌ INVALID"
            report_lines.append(f"{status}: {detail['email']}")
            if not detail["is_valid"]:
                error = detail["details"].get("error", "Unknown error")
                report_lines.append(f"     Reason: {error}")
        
        if len(results["details"]) > 10:
            report_lines.append(f"... and {len(results['details']) - 10} more")
        
        # Domain summary
        report_lines.append("\n" + "-" * 70)
        report_lines.append("Domain Summary:")
        
        for domain, stats in sorted(results["summary_by_domain"].items())[:15]:
            total = stats["valid"] + stats["invalid"]
            if total > 0:
                valid_pct = (stats["valid"] / total) * 100
                report_lines.append(
                    f"  {domain}: {stats['valid']}/{total} valid ({valid_pct:.1f}%)"
                )
        
        report_lines.append("=" * 70)
        
        return "\n".join(report_lines)
    
    def _generate_csv_report(self, results: BulkResults) -> str:
        """Generate CSV report."""
        output = io.StringIO()
        writer = csv.writer(output)
        
        # ✅ FIXED: Correct header that matches data columns
        writer.writerow([
            "Email", "Is Valid", "Validation Level", "Domain", 
            "Has SPF", "Has DMARC", "Is Disposable", "Score"
        ])
        
        # Write data
        for detail in results["details"]:
            domain = detail["email"].split('@')[1] if '@' in detail["email"] else ""
            security = detail["details"].get("security", {})
            score = detail["details"].get("overall_score", 0)
            
            writer.writerow([
                detail["email"],
                detail["is_valid"],
                detail["validation_level"],
                domain,
                security.get("has_spf", False),
                security.get("has_dmarc", False),
                security.get("is_disposable", False),
                score
            ])
        
        return output.getvalue()
    
    def clear_cache(self) -> None:
        """Clear the DNS validation cache."""
        with self._cache_lock:
            self.validation_cache.clear()
        logger.info("Validation cache cleared")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self._cache_lock:
            total_entries = len(self.validation_cache)
            expired_entries = sum(
                1 for entry in self.validation_cache.values() 
                if entry.is_expired()
            )
        
        return {
            "total_entries": total_entries,
            "expired_entries": expired_entries,
            "active_entries": total_entries - expired_entries,
            "cache_ttl": self.cache_ttl
        }