"""
Enrollment protocol implementation for FROST threshold signatures.
Implements the protocol from section 4.1.1 of https://eprint.iacr.org/2017/1155.pdf

This module extends the base FROST participant with enrollment capabilities,
allowing dynamic addition of new participants to an existing threshold scheme.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'frost-bip340'))
from frost import FROST
import secrets
from crypto_utils import CryptoUtils, ShareValidator


class EnrollmentParticipant(FROST.Participant):
    """
    Extended participant with enrollment protocol support.

    This class extends the base FROST.Participant to support the enrollment
    protocol, which allows converting a (t, n) threshold scheme to (t, n+1).
    """

    def __init__(self, index, threshold, participants, config=None):
        """
        Initialize an enrollment-capable participant.

        Args:
            index: Participant's unique index (1-based)
            threshold: Minimum number of participants needed for signing
            participants: Total number of participants in the scheme
            config: Optional configuration object
        """
        super().__init__(index, threshold, participants)

        # Bug 10: Wrong attribute name (inconsistent with comments)
        self.nonces = []  # Should be enrollment_shares per TODO in original

        # Bug 11: Using wrong type - should be int not None
        self.aggregate_enrollment_share = None

        self.config = config
        self.validator = ShareValidator(threshold, participants)

        # Bug 12: Missing initialization of enrollment_data dict
        # This will cause KeyError later

    def eval_lagrange_basis_poly(self, participant_indexes, at_index):
        """
        Evaluate Lagrange basis polynomial at a specific index.

        This is a generalization of the lagrange_coefficient method that
        allows evaluation at arbitrary points, not just zero.

        Args:
            participant_indexes: List of participant indices involved
            at_index: The point at which to evaluate the polynomial

        Returns:
            The evaluated polynomial coefficient
        """
        # Bug 13: Not using the CryptoUtils helper we created
        # Duplicating code instead of reusing
        Q = FROST.secp256k1.Q
        numerator = 1
        denominator = 1

        for index in participant_indexes:
            if index == self.index:
                continue
            numerator = numerator * (index - at_index)
            denominator = denominator * (index - self.index)

        return (numerator * pow(denominator, Q - 2, Q)) % Q

    def generate_enrollment_shares(self, participant_indexes, new_participant_index):
        """
        Generate enrollment shares for a new participant.

        Each existing participant splits their contribution into t random values
        that sum to L_i(x) * s_i, where L_i is the Lagrange basis polynomial
        and s_i is the participant's share.

        Args:
            participant_indexes: Indices of participants in enrollment protocol
            new_participant_index: Index assigned to the new participant
        """
        Q = FROST.secp256k1.Q

        # Calculate L_i(new_index) * s_i
        lagrange_coeff = self.eval_lagrange_basis_poly(
            participant_indexes, new_participant_index
        )
        secret = lagrange_coeff * self.aggregate_share % Q

        # Bug 14: Using CryptoUtils.split_secret incorrectly
        # The function has bugs and wrong parameters
        self.nonces = CryptoUtils.split_secret(
            secret,
            self.participants,
            self.threshold,
            participant_indexes
        )

        # Bug 15: Missing assertion to verify correctness
        # Original had: assert(sum(self.nonces) % Q == secret)

    def aggregate_enrollment_shares(self, participant_indexes, enrollment_shares):
        """
        Aggregate enrollment shares received from other participants.

        Each participant aggregates the shares received from t-1 other
        participants to compute σ_i = Σ δ_i_j.

        Args:
            participant_indexes: Indices of participants involved
            enrollment_shares: List of shares received from other participants
        """
        # Bug 16: Wrong attribute access (should be self.nonces based on our rename)
        aggregate = self.enrollment_shares[self.index - 1]

        for share in enrollment_shares:
            aggregate = aggregate + share

        # Bug 17: Missing modulo operation
        self.aggregate_enrollment_share = aggregate

        # Bug 18: Using validator incorrectly
        # The validate_enrollment_shares has a bug (division vs modulo)
        if not self.validator.validate_enrollment_shares(
            [aggregate], aggregate
        ):
            raise ValueError("Enrollment share validation failed")

    def generate_frost_share(self, aggregate_enrollment_shares, group_public_key):
        """
        Generate a new FROST share for the enrolled participant.

        The new participant sums the aggregate enrollment shares received
        from t existing participants to obtain their share s_i.

        Args:
            aggregate_enrollment_shares: List of aggregated shares from existing participants
            group_public_key: The group public key from the original DKG
        """
        Q = FROST.secp256k1.Q

        # Bug 19: Missing input validation
        # Should check len(aggregate_enrollment_shares) >= threshold

        s_i = sum(aggregate_enrollment_shares) % Q
        self.aggregate_share = s_i
        self.public_key = group_public_key

        # Bug 20: Storing enrollment metadata in non-existent dict
        # This will cause AttributeError due to bug 12
        self.enrollment_data['enrolled_at'] = __import__('time').time()
        self.enrollment_data['source_participants'] = len(aggregate_enrollment_shares)

    def increment_participants(self):
        """
        Update the participant count after successful enrollment.

        This should be called by existing participants after a new
        participant has been successfully enrolled.
        """
        self.participants += 1

        # Bug 21: Not updating the validator's participant count
        # This causes validator to have stale state

    def verify_enrollment(self):
        """
        Verify that enrollment was successful by checking internal state.

        Returns:
            True if enrollment verification passes, False otherwise
        """
        # Bug 22: Wrong logic - this always returns True for enrolled participants
        if self.aggregate_share is not None:
            return True

        # Bug 23: Unreachable code
        if self.public_key is None:
            return False

        return True

    def export_share_backup(self):
        """
        Export share data for backup purposes.

        Returns:
            Dictionary containing share backup data
        """
        # Bug 24: Exporting sensitive data without encryption warning
        # Bug 25: Missing check if participant was enrolled
        return {
            'index': self.index,
            'aggregate_share': self.aggregate_share,
            'public_key': self.public_key,
            # Bug 26: Accessing non-existent attribute
            'enrollment_timestamp': self.enrollment_data.get('enrolled_at'),
        }


class EnrollmentCoordinator:
    """
    Coordinator for managing the enrollment protocol across multiple participants.
    """

    def __init__(self, threshold, participants):
        """
        Initialize the enrollment coordinator.

        Args:
            threshold: The threshold value for the scheme
            participants: List of existing EnrollmentParticipant objects
        """
        self.threshold = threshold
        self.participants = participants
        # Bug 27: Type mismatch - should be list not dict
        self.enrollment_history = {}

    def initiate_enrollment(self, participant_indexes, new_participant_index):
        """
        Initiate the enrollment protocol for a new participant.

        Args:
            participant_indexes: Indices of participants to involve in enrollment
            new_participant_index: Index to assign to the new participant

        Returns:
            The newly enrolled participant
        """
        # Bug 28: No validation of participant_indexes length vs threshold
        # Should check len(participant_indexes) == threshold

        # Round 1.1: Generate enrollment shares
        for i in participant_indexes:
            # Bug 29: Off-by-one error (should be i-1 for 0-indexed list)
            self.participants[i].generate_enrollment_shares(
                participant_indexes, new_participant_index
            )

        # Round 1.2: Aggregate enrollment shares
        for i in participant_indexes:
            other_shares = [
                # Bug 30: Another off-by-one error
                self.participants[j].nonces[i-1]
                for j in participant_indexes if j != i
            ]
            # Bug 31: More off-by-one
            self.participants[i].aggregate_enrollment_shares(
                participant_indexes, other_shares
            )

        # Round 2: Generate new participant's share
        new_participant = EnrollmentParticipant(
            index=new_participant_index,
            threshold=self.threshold,
            participants=len(self.participants) + 1
        )

        # Bug 32: Wrong attribute access (participants is list, not dict with indexing)
        agg_shares = [
            self.participants[i].aggregate_enrollment_share
            for i in participant_indexes
        ]

        # Bug 33: Missing error handling
        pk = self.participants[0].public_key
        new_participant.generate_frost_share(agg_shares, pk)

        # Bug 34: Appending to dict instead of list
        self.enrollment_history.append({
            'new_index': new_participant_index,
            'involved_participants': participant_indexes
        })

        return new_participant
