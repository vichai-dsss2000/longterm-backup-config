"""
Error Handling and Retry Logic System
====================================

This module provides comprehensive error handling, retry mechanisms, and
logging utilities for the network device backup system. It includes
configurable retry strategies, circuit breaker patterns, and detailed
error classification and reporting.

Features:
- Configurable retry strategies (exponential backoff, linear, custom)
- Circuit breaker pattern for failing services
- Error classification and categorization
- Comprehensive logging with structured output
- Rate limiting for API calls and connections
- Health monitoring and metrics collection
- Exception handling decorators
- Audit trail and error tracking
"""

import logging
import time
import functools
import threading
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Callable, Type, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import json
import traceback
from contextlib import contextmanager
import hashlib

# Configure logging
logger = logging.getLogger(__name__)


class ErrorCategory(Enum):
    """Error category classification."""
    NETWORK = "network"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    TIMEOUT = "timeout"
    CONFIGURATION = "configuration"
    TEMPLATE = "template"
    STORAGE = "storage"
    VALIDATION = "validation"
    SYSTEM = "system"
    UNKNOWN = "unknown"


class ErrorSeverity(Enum):
    """Error severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RetryStrategy(Enum):
    """Retry strategy types."""
    EXPONENTIAL_BACKOFF = "exponential_backoff"
    LINEAR_BACKOFF = "linear_backoff"
    FIXED_INTERVAL = "fixed_interval"
    FIBONACCI = "fibonacci"
    CUSTOM = "custom"


@dataclass
class ErrorInfo:
    """Detailed error information."""
    error_id: str
    timestamp: datetime
    category: ErrorCategory
    severity: ErrorSeverity
    error_type: str
    error_message: str
    context: Dict[str, Any] = field(default_factory=dict)
    stack_trace: Optional[str] = None
    retry_count: int = 0
    is_retryable: bool = True
    suggested_action: Optional[str] = None
    related_errors: List[str] = field(default_factory=list)


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    max_attempts: int = 3
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL_BACKOFF
    base_delay: float = 1.0
    max_delay: float = 300.0
    backoff_multiplier: float = 2.0
    jitter: bool = True
    retryable_exceptions: List[Type[Exception]] = field(default_factory=list)
    non_retryable_exceptions: List[Type[Exception]] = field(default_factory=list)
    retry_condition: Optional[Callable[[Exception], bool]] = None


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker."""
    failure_threshold: int = 5
    recovery_timeout: int = 60
    expected_exception: Type[Exception] = Exception
    name: str = "default"


class CircuitBreakerState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class ErrorClassifier:
    """Classifies and categorizes errors."""
    
    @staticmethod
    def classify_error(exception: Exception, context: Dict[str, Any] = None) -> Tuple[ErrorCategory, ErrorSeverity]:
        """Classify error into category and severity."""
        error_type = type(exception).__name__
        error_message = str(exception).lower()
        
        # Network-related errors
        if any(keyword in error_message for keyword in ['connection', 'network', 'socket', 'timeout', 'unreachable']):
            if 'timeout' in error_message:
                return ErrorCategory.TIMEOUT, ErrorSeverity.MEDIUM
            else:
                return ErrorCategory.NETWORK, ErrorSeverity.HIGH
        
        # Authentication errors
        if any(keyword in error_message for keyword in ['authentication', 'login', 'password', 'credentials', 'unauthorized']):
            return ErrorCategory.AUTHENTICATION, ErrorSeverity.HIGH
        
        # Authorization errors
        if any(keyword in error_message for keyword in ['permission', 'access denied', 'forbidden', 'privilege']):
            return ErrorCategory.AUTHORIZATION, ErrorSeverity.MEDIUM
        
        # Configuration errors
        if any(keyword in error_message for keyword in ['configuration', 'config', 'syntax', 'invalid command']):
            return ErrorCategory.CONFIGURATION, ErrorSeverity.MEDIUM
        
        # Template errors
        if any(keyword in error_message for keyword in ['template', 'variable', 'substitution', 'jinja']):
            return ErrorCategory.TEMPLATE, ErrorSeverity.LOW
        
        # Storage errors
        if any(keyword in error_message for keyword in ['file', 'storage', 'disk', 'directory', 'permission denied']):
            return ErrorCategory.STORAGE, ErrorSeverity.MEDIUM
        
        # Validation errors
        if any(keyword in error_message for keyword in ['validation', 'invalid', 'format', 'parse']):
            return ErrorCategory.VALIDATION, ErrorSeverity.LOW
        
        # System errors
        if any(keyword in error_type.lower() for keyword in ['system', 'os', 'memory', 'resource']):
            return ErrorCategory.SYSTEM, ErrorSeverity.CRITICAL
        
        return ErrorCategory.UNKNOWN, ErrorSeverity.MEDIUM
    
    @staticmethod
    def is_retryable(exception: Exception, context: Dict[str, Any] = None) -> bool:
        """Determine if error is retryable."""
        category, severity = ErrorClassifier.classify_error(exception, context)
        
        # Never retry authentication/authorization errors
        if category in [ErrorCategory.AUTHENTICATION, ErrorCategory.AUTHORIZATION]:
            return False
        
        # Never retry validation/template errors (they won't fix themselves)
        if category in [ErrorCategory.VALIDATION, ErrorCategory.TEMPLATE]:
            return False
        
        # Retry network, timeout, and system errors
        if category in [ErrorCategory.NETWORK, ErrorCategory.TIMEOUT, ErrorCategory.SYSTEM]:
            return True
        
        # Retry storage errors (might be temporary)
        if category == ErrorCategory.STORAGE:
            return True
        
        # Default to retryable for unknown errors
        return True
    
    @staticmethod
    def suggest_action(exception: Exception, context: Dict[str, Any] = None) -> str:
        """Suggest corrective action for error."""
        category, severity = ErrorClassifier.classify_error(exception, context)
        
        suggestions = {
            ErrorCategory.NETWORK: "Check network connectivity and device reachability",
            ErrorCategory.AUTHENTICATION: "Verify username and password credentials",
            ErrorCategory.AUTHORIZATION: "Check user permissions and privilege levels",
            ErrorCategory.TIMEOUT: "Increase timeout values or check device responsiveness",
            ErrorCategory.CONFIGURATION: "Verify device configuration and command syntax",
            ErrorCategory.TEMPLATE: "Check template syntax and variable definitions",
            ErrorCategory.STORAGE: "Check disk space and file permissions",
            ErrorCategory.VALIDATION: "Verify input data format and values",
            ErrorCategory.SYSTEM: "Check system resources and restart services if needed",
            ErrorCategory.UNKNOWN: "Review error details and system logs"
        }
        
        return suggestions.get(category, "Contact system administrator")


class RetryManager:
    """Manages retry logic with various strategies."""
    
    def __init__(self, config: RetryConfig):
        self.config = config
    
    def calculate_delay(self, attempt: int) -> float:
        """Calculate delay for next retry attempt."""
        if self.config.strategy == RetryStrategy.EXPONENTIAL_BACKOFF:
            delay = self.config.base_delay * (self.config.backoff_multiplier ** attempt)
        elif self.config.strategy == RetryStrategy.LINEAR_BACKOFF:
            delay = self.config.base_delay * (attempt + 1)
        elif self.config.strategy == RetryStrategy.FIXED_INTERVAL:
            delay = self.config.base_delay
        elif self.config.strategy == RetryStrategy.FIBONACCI:
            delay = self._fibonacci_delay(attempt)
        else:
            delay = self.config.base_delay
        
        # Apply maximum delay limit
        delay = min(delay, self.config.max_delay)
        
        # Add jitter to prevent thundering herd
        if self.config.jitter:
            import random
            delay *= (0.5 + random.random() * 0.5)
        
        return delay
    
    def _fibonacci_delay(self, attempt: int) -> float:
        """Calculate Fibonacci-based delay."""
        if attempt <= 1:
            return self.config.base_delay
        
        fib_prev, fib_curr = 0, 1
        for _ in range(attempt):
            fib_prev, fib_curr = fib_curr, fib_prev + fib_curr
        
        return self.config.base_delay * fib_curr
    
    def should_retry(self, exception: Exception, attempt: int) -> bool:
        """Determine if operation should be retried."""
        if attempt >= self.config.max_attempts:
            return False
        
        # Check exception types
        if self.config.non_retryable_exceptions:
            if any(isinstance(exception, exc_type) for exc_type in self.config.non_retryable_exceptions):
                return False
        
        if self.config.retryable_exceptions:
            if not any(isinstance(exception, exc_type) for exc_type in self.config.retryable_exceptions):
                return False
        
        # Use custom retry condition if provided
        if self.config.retry_condition:
            return self.config.retry_condition(exception)
        
        # Default to error classifier
        return ErrorClassifier.is_retryable(exception)


class CircuitBreaker:
    """Circuit breaker implementation for fault tolerance."""
    
    def __init__(self, config: CircuitBreakerConfig):
        self.config = config
        self.state = CircuitBreakerState.CLOSED
        self.failure_count = 0
        self.last_failure_time = None
        self.lock = threading.RLock()
    
    def __call__(self, func):
        """Decorator to apply circuit breaker to function."""
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            with self.lock:
                if self.state == CircuitBreakerState.OPEN:
                    if self._should_attempt_reset():
                        self.state = CircuitBreakerState.HALF_OPEN
                    else:
                        raise Exception(f"Circuit breaker {self.config.name} is OPEN")
                
                try:
                    result = func(*args, **kwargs)
                    self._on_success()
                    return result
                except self.config.expected_exception as e:
                    self._on_failure()
                    raise e
        
        return wrapper
    
    def _should_attempt_reset(self) -> bool:
        """Check if circuit breaker should attempt reset."""
        if self.last_failure_time is None:
            return True
        
        return (datetime.now() - self.last_failure_time).total_seconds() > self.config.recovery_timeout
    
    def _on_success(self):
        """Handle successful operation."""
        self.failure_count = 0
        self.state = CircuitBreakerState.CLOSED
    
    def _on_failure(self):
        """Handle failed operation."""
        self.failure_count += 1
        self.last_failure_time = datetime.now()
        
        if self.failure_count >= self.config.failure_threshold:
            self.state = CircuitBreakerState.OPEN
    
    def get_state(self) -> CircuitBreakerState:
        """Get current circuit breaker state."""
        return self.state
    
    def reset(self):
        """Manually reset circuit breaker."""
        with self.lock:
            self.failure_count = 0
            self.state = CircuitBreakerState.CLOSED
            self.last_failure_time = None


class ErrorTracker:
    """Tracks and analyzes error patterns."""
    
    def __init__(self, max_errors: int = 1000):
        self.max_errors = max_errors
        self.errors: deque = deque(maxlen=max_errors)
        self.error_counts: Dict[str, int] = defaultdict(int)
        self.lock = threading.RLock()
    
    def record_error(self, error_info: ErrorInfo):
        """Record an error occurrence."""
        with self.lock:
            self.errors.append(error_info)
            self.error_counts[error_info.error_type] += 1
    
    def get_error_statistics(self, time_window: Optional[timedelta] = None) -> Dict[str, Any]:
        """Get error statistics for specified time window."""
        with self.lock:
            if time_window is None:
                relevant_errors = list(self.errors)
            else:
                cutoff_time = datetime.now(timezone.utc) - time_window
                relevant_errors = [e for e in self.errors if e.timestamp >= cutoff_time]
            
            if not relevant_errors:
                return {"total_errors": 0, "error_breakdown": {}, "most_common": []}
            
            # Count errors by category
            category_counts = defaultdict(int)
            severity_counts = defaultdict(int)
            type_counts = defaultdict(int)
            
            for error in relevant_errors:
                category_counts[error.category.value] += 1
                severity_counts[error.severity.value] += 1
                type_counts[error.error_type] += 1
            
            # Find most common errors
            most_common = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            
            return {
                "total_errors": len(relevant_errors),
                "time_window": str(time_window) if time_window else "all_time",
                "category_breakdown": dict(category_counts),
                "severity_breakdown": dict(severity_counts),
                "type_breakdown": dict(type_counts),
                "most_common": most_common,
                "error_rate": len(relevant_errors) / (time_window.total_seconds() / 3600) if time_window else 0
            }
    
    def get_recent_errors(self, count: int = 10) -> List[ErrorInfo]:
        """Get most recent errors."""
        with self.lock:
            return list(self.errors)[-count:]
    
    def clear_errors(self):
        """Clear all recorded errors."""
        with self.lock:
            self.errors.clear()
            self.error_counts.clear()


class StructuredLogger:
    """Enhanced logger with structured output and context."""
    
    def __init__(self, name: str, error_tracker: Optional[ErrorTracker] = None):
        self.logger = logging.getLogger(name)
        self.error_tracker = error_tracker
        self.context_stack: List[Dict[str, Any]] = []
    
    @contextmanager
    def context(self, **context_vars):
        """Add context variables for logging."""
        self.context_stack.append(context_vars)
        try:
            yield
        finally:
            self.context_stack.pop()
    
    def _get_context(self) -> Dict[str, Any]:
        """Get current context from stack."""
        context = {}
        for ctx in self.context_stack:
            context.update(ctx)
        return context
    
    def _create_log_entry(self, level: str, message: str, **kwargs) -> Dict[str, Any]:
        """Create structured log entry."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "message": message,
            "context": self._get_context()
        }
        entry.update(kwargs)
        return entry
    
    def info(self, message: str, **kwargs):
        """Log info message."""
        entry = self._create_log_entry("INFO", message, **kwargs)
        self.logger.info(json.dumps(entry))
    
    def warning(self, message: str, **kwargs):
        """Log warning message."""
        entry = self._create_log_entry("WARNING", message, **kwargs)
        self.logger.warning(json.dumps(entry))
    
    def error(self, message: str, exception: Optional[Exception] = None, **kwargs):
        """Log error message with optional exception tracking."""
        entry = self._create_log_entry("ERROR", message, **kwargs)
        
        if exception:
            # Add exception details
            category, severity = ErrorClassifier.classify_error(exception, self._get_context())
            
            error_info = ErrorInfo(
                error_id=hashlib.md5(f"{message}{str(exception)}".encode()).hexdigest(),
                timestamp=datetime.now(timezone.utc),
                category=category,
                severity=severity,
                error_type=type(exception).__name__,
                error_message=str(exception),
                context=self._get_context(),
                stack_trace=traceback.format_exc(),
                suggested_action=ErrorClassifier.suggest_action(exception, self._get_context())
            )
            
            entry["exception"] = {
                "type": error_info.error_type,
                "message": error_info.error_message,
                "category": error_info.category.value,
                "severity": error_info.severity.value,
                "stack_trace": error_info.stack_trace,
                "suggested_action": error_info.suggested_action
            }
            
            # Track error if tracker is available
            if self.error_tracker:
                self.error_tracker.record_error(error_info)
        
        self.logger.error(json.dumps(entry))
    
    def critical(self, message: str, exception: Optional[Exception] = None, **kwargs):
        """Log critical message."""
        entry = self._create_log_entry("CRITICAL", message, **kwargs)
        
        if exception:
            entry["exception"] = {
                "type": type(exception).__name__,
                "message": str(exception),
                "stack_trace": traceback.format_exc()
            }
        
        self.logger.critical(json.dumps(entry))


def retry_with_backoff(config: RetryConfig = None):
    """Decorator for adding retry logic to functions."""
    if config is None:
        config = RetryConfig()
    
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            retry_manager = RetryManager(config)
            last_exception = None
            
            for attempt in range(config.max_attempts):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    
                    if not retry_manager.should_retry(e, attempt):
                        break
                    
                    if attempt < config.max_attempts - 1:
                        delay = retry_manager.calculate_delay(attempt)
                        logger.warning(f"Attempt {attempt + 1} failed for {func.__name__}: {e}. Retrying in {delay:.2f}s")
                        time.sleep(delay)
                    else:
                        logger.error(f"All {config.max_attempts} attempts failed for {func.__name__}")
            
            if last_exception:
                raise last_exception
            
        return wrapper
    return decorator


def log_exceptions(logger_instance: Optional[StructuredLogger] = None):
    """Decorator for automatic exception logging."""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if logger_instance:
                    logger_instance.error(f"Exception in {func.__name__}", exception=e)
                else:
                    logger.error(f"Exception in {func.__name__}: {e}")
                raise
        return wrapper
    return decorator


class ErrorHandlingManager:
    """Central error handling manager."""
    
    def __init__(self):
        self.error_tracker = ErrorTracker()
        self.structured_logger = StructuredLogger("error_handling", self.error_tracker)
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
    
    def get_circuit_breaker(self, name: str, config: CircuitBreakerConfig = None) -> CircuitBreaker:
        """Get or create circuit breaker."""
        if name not in self.circuit_breakers:
            if config is None:
                config = CircuitBreakerConfig(name=name)
            self.circuit_breakers[name] = CircuitBreaker(config)
        
        return self.circuit_breakers[name]
    
    def get_error_statistics(self, time_window: Optional[timedelta] = None) -> Dict[str, Any]:
        """Get comprehensive error statistics."""
        return self.error_tracker.get_error_statistics(time_window)
    
    def get_circuit_breaker_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all circuit breakers."""
        status = {}
        for name, breaker in self.circuit_breakers.items():
            status[name] = {
                "state": breaker.get_state().value,
                "failure_count": breaker.failure_count,
                "last_failure_time": breaker.last_failure_time.isoformat() if breaker.last_failure_time else None
            }
        return status
    
    def reset_circuit_breaker(self, name: str) -> bool:
        """Reset specific circuit breaker."""
        if name in self.circuit_breakers:
            self.circuit_breakers[name].reset()
            return True
        return False
    
    def get_logger(self, name: str) -> StructuredLogger:
        """Get structured logger instance."""
        return StructuredLogger(name, self.error_tracker)


# Global error handling manager
error_manager = ErrorHandlingManager()


if __name__ == "__main__":
    # Example usage and testing
    logging.basicConfig(level=logging.DEBUG)
    
    # Test retry decorator
    @retry_with_backoff(RetryConfig(max_attempts=3, strategy=RetryStrategy.EXPONENTIAL_BACKOFF))
    def test_function():
        import random
        if random.random() < 0.7:  # 70% chance of failure
            raise Exception("Random test failure")
        return "Success!"
    
    # Test circuit breaker
    circuit_config = CircuitBreakerConfig(failure_threshold=3, recovery_timeout=5, name="test_circuit")
    test_breaker = error_manager.get_circuit_breaker("test_circuit", circuit_config)
    
    @test_breaker
    def failing_function():
        raise Exception("This always fails")
    
    # Test structured logging
    test_logger = error_manager.get_logger("test")
    
    try:
        with test_logger.context(operation="backup", device_id=123):
            test_logger.info("Starting test operation")
            result = test_function()
            test_logger.info("Operation completed", result=result)
    except Exception as e:
        test_logger.error("Operation failed", exception=e)
    
    # Print error statistics
    stats = error_manager.get_error_statistics()
    print(f"Error statistics: {json.dumps(stats, indent=2)}")
    
    # Print circuit breaker status
    cb_status = error_manager.get_circuit_breaker_status()
    print(f"Circuit breaker status: {json.dumps(cb_status, indent=2)}")