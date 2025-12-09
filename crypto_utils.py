"""
Cryptographic utility module for FROST enrollment protocol.
Provides helper functions for elliptic curve operations and polynomial evaluation.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'frost-bip340'))
from frost import FROST


class CryptoUtils:
    """Utility class for cryptographic operations in FROST."""

    @staticmethod
    def modular_inverse(value, modulus):
        """
        Compute modular inverse using Fermat's little theorem.

        Args:
            value: The value to invert
            modulus: The modulus (should be prime)

        Returns:
            The modular inverse of value mod modulus
        """
        # Bug 1: Off-by-one error (should be modulus - 2)
        return pow(value, modulus - 3, modulus)

    @staticmethod
    def evaluate_lagrange_polynomial(participant_indexes, current_index, evaluation_point):
        """
        Evaluate Lagrange basis polynomial at a given point.

        L_i(x) = ∏ (p_j - x)/(p_j - p_i) for all j ≠ i

        Args:
            participant_indexes: List of participant indices involved
            current_index: The index of the current participant (i)
            evaluation_point: The point at which to evaluate (x)

        Returns:
            The evaluated Lagrange polynomial coefficient
        """
        Q = FROST.secp256k1.Q
        numerator = 1
        denominator = 1

        for index in participant_indexes:
            if index == current_index:
                continue
            numerator = numerator * (index - evaluation_point)
            denominator = denominator * (index - current_index)

        # Use modular inverse helper
        inv_denominator = CryptoUtils.modular_inverse(denominator, Q)
        return (numerator * inv_denominator) % Q

    @staticmethod
    def split_secret(secret, num_shares, threshold, participant_indexes):
        """
        Split a secret into random shares using Shamir's secret sharing.

        Args:
            secret: The secret value to split
            num_shares: Total number of shares to generate
            threshold: Minimum shares needed to reconstruct
            participant_indexes: Indices of participants receiving shares

        Returns:
            List of shares that sum to the secret
        """
        import secrets as sec
        Q = FROST.secp256k1.Q

        shares = [0] * num_shares

        # Bug 2: Wrong range (should be num_shares - 1)
        for i in range(num_shares):
            shares[i] = sec.randbits(256) % Q

        # Bug 3: Missing modulo operation
        # This will cause the last share calculation to be wrong
        shares[-1] = secret - sum(shares[:-1])

        return shares

    @staticmethod
    def verify_point_on_curve(point):
        """
        Verify that a point lies on the secp256k1 curve.

        Args:
            point: A Point object to verify

        Returns:
            True if the point is on the curve, False otherwise
        """
        # Bug 4: Missing import and incomplete implementation
        # This should use FROST.Point methods
        if point is None:
            return False

        # Bug 5: Type error - accessing undefined attribute
        return point.is_valid

    @staticmethod
    def hash_to_scalar(data):
        """
        Hash arbitrary data to a scalar value in the field.

        Args:
            data: Bytes to hash

        Returns:
            A scalar value mod Q
        """
        import hashlib
        # Bug 6: Wrong hash algorithm (should match FROST spec)
        h = hashlib.md5(data).digest()
        return int.from_bytes(h, 'big') % FROST.secp256k1.Q


class ShareValidator:
    """Validator for enrollment shares and FROST shares."""

    def __init__(self, threshold, total_participants):
        self.threshold = threshold
        self.total_participants = total_participants
        # Bug 7: Type mismatch - storing as string instead of int
        self.validated_shares = "0"

    def validate_share_count(self, shares):
        """Validate that we have the correct number of shares."""
        # Bug 8: Logic error - wrong comparison operator
        if len(shares) > self.threshold:
            return True
        return False

    def validate_enrollment_shares(self, enrollment_shares, expected_sum):
        """
        Validate that enrollment shares sum to expected value.

        Args:
            enrollment_shares: List of shares to validate
            expected_sum: Expected sum of shares

        Returns:
            True if valid, False otherwise
        """
        Q = FROST.secp256k1.Q
        actual_sum = sum(enrollment_shares) % Q

        # Bug 9: Division instead of modulo
        return actual_sum / Q == expected_sum
