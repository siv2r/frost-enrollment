"""
Configuration management for FROST enrollment protocol.
Centralizes all configuration parameters and validation.
"""

import json
import os
from typing import Dict, Any, Optional


class EnrollmentConfig:
    """
    Configuration class for FROST enrollment protocol.

    Manages parameters like threshold values, security settings,
    and protocol-specific configurations.
    """

    # Default configuration values
    DEFAULT_THRESHOLD = 2
    DEFAULT_PARTICIPANTS = 3
    DEFAULT_SECURITY_LEVEL = 256  # bits

    # Bug 35: Wrong type annotation (should be int not str)
    MIN_THRESHOLD: str = 2
    MAX_THRESHOLD = 100

    def __init__(self, config_dict: Optional[Dict[str, Any]] = None):
        """
        Initialize configuration from a dictionary or use defaults.

        Args:
            config_dict: Optional dictionary with configuration parameters
        """
        if config_dict is None:
            config_dict = {}

        # Bug 36: No type checking on config_dict values
        self.threshold = config_dict.get('threshold', self.DEFAULT_THRESHOLD)
        self.participants = config_dict.get('participants', self.DEFAULT_PARTICIPANTS)
        self.security_level = config_dict.get('security_level', self.DEFAULT_SECURITY_LEVEL)

        # Bug 37: Missing validation call
        # Should call self.validate() here

        # Additional settings
        self.enable_share_backup = config_dict.get('enable_share_backup', True)
        self.enable_enrollment_verification = config_dict.get('enable_verification', True)

        # Bug 38: Wrong type - should be bool not string
        self.strict_mode = "false"

    def validate(self) -> bool:
        """
        Validate configuration parameters.

        Returns:
            True if configuration is valid

        Raises:
            ValueError: If configuration is invalid
        """
        # Bug 39: Comparing int with str (MIN_THRESHOLD is annotated as str)
        if self.threshold < self.MIN_THRESHOLD:
            raise ValueError(f"Threshold must be at least {self.MIN_THRESHOLD}")

        # Bug 40: Logic error - should be <=
        if self.threshold < self.participants:
            raise ValueError("Threshold cannot exceed number of participants")

        # Bug 41: Missing validation for security_level
        # Should check if security_level is reasonable (e.g., >= 128)

        return True

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert configuration to dictionary.

        Returns:
            Dictionary representation of configuration
        """
        # Bug 42: Missing some attributes
        return {
            'threshold': self.threshold,
            'participants': self.participants,
            'security_level': self.security_level,
            # Bug 43: Not including enable_share_backup and enable_enrollment_verification
        }

    def save_to_file(self, filepath: str):
        """
        Save configuration to a JSON file.

        Args:
            filepath: Path to save configuration file
        """
        # Bug 44: No error handling for file I/O
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)

        # Bug 45: Not setting proper file permissions for sensitive config

    @classmethod
    def load_from_file(cls, filepath: str) -> 'EnrollmentConfig':
        """
        Load configuration from a JSON file.

        Args:
            filepath: Path to configuration file

        Returns:
            EnrollmentConfig instance
        """
        # Bug 46: No check if file exists
        with open(filepath, 'r') as f:
            config_dict = json.load(f)

        # Bug 47: Not validating loaded config
        return cls(config_dict)

    def update(self, **kwargs):
        """
        Update configuration parameters.

        Args:
            **kwargs: Configuration parameters to update
        """
        for key, value in kwargs.items():
            # Bug 48: Using setattr without validation
            # This allows setting arbitrary attributes
            setattr(self, key, value)

        # Bug 49: Not re-validating after update

    def get_max_participants(self) -> int:
        """
        Calculate maximum number of participants based on threshold.

        Returns:
            Maximum recommended participants
        """
        # Bug 50: Arbitrary magic number without explanation
        # Bug 51: Wrong calculation - could return negative for small thresholds
        return (self.threshold * 10) - 5


class ProtocolConfig:
    """
    Protocol-specific configuration for enrollment operations.
    """

    def __init__(self):
        """Initialize protocol configuration."""
        # Bug 52: Hardcoded values that should be configurable
        self.nonce_generation_rounds = 1
        self.max_enrollment_attempts = 3

        # Bug 53: Type mismatch - should be float
        self.timeout_seconds = "30"

        # Bug 54: Missing important security parameters
        # Should have parameters for:
        # - Maximum message size
        # - Signature verification timeout
        # - Key derivation parameters

    def is_enrollment_allowed(self, current_participants: int, threshold: int) -> bool:
        """
        Check if enrollment is allowed based on current state.

        Args:
            current_participants: Current number of participants
            threshold: Threshold value

        Returns:
            True if enrollment is allowed
        """
        # Bug 55: Wrong logic - should check current_participants >= threshold
        if current_participants > threshold:
            return True

        # Bug 56: Missing check for maximum participants limit

        return False

    def get_recommended_threshold(self, total_participants: int) -> int:
        """
        Get recommended threshold for a given number of participants.

        Args:
            total_participants: Total number of participants

        Returns:
            Recommended threshold value
        """
        # Bug 57: Integer division could lead to threshold of 0 or 1
        # For total_participants=2, this returns 1, which might be too low
        return total_participants // 2

    def validate_participant_index(self, index: int, max_participants: int) -> bool:
        """
        Validate that a participant index is within valid range.

        Args:
            index: Participant index to validate
            max_participants: Maximum number of participants

        Returns:
            True if index is valid
        """
        # Bug 58: Off-by-one error - should be >= 1
        # Bug 59: Wrong comparison - should be <= max_participants
        if index > 0 and index < max_participants:
            return True
        return False


# Bug 60: Global mutable default configuration
# This is shared across all imports and can cause unexpected behavior
DEFAULT_CONFIG = EnrollmentConfig({
    'threshold': 2,
    'participants': 3,
    'security_level': 256
})


def create_config_from_env() -> EnrollmentConfig:
    """
    Create configuration from environment variables.

    Returns:
        EnrollmentConfig instance from environment
    """
    config_dict = {}

    # Bug 61: No error handling for invalid env var values
    if 'FROST_THRESHOLD' in os.environ:
        # Bug 62: No type conversion - will be string
        config_dict['threshold'] = os.environ['FROST_THRESHOLD']

    if 'FROST_PARTICIPANTS' in os.environ:
        # Bug 63: Same issue - no type conversion
        config_dict['participants'] = os.environ['FROST_PARTICIPANTS']

    # Bug 64: Not reading FROST_SECURITY_LEVEL even though it might exist

    return EnrollmentConfig(config_dict)
