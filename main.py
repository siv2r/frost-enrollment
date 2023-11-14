# This module implements an enrollment protocol for
# BIP-340 compatible FROST implementation (by Jesse Posner).
# Spec details: section 4.1.1 in https://eprint.iacr.org/2017/1155.pdf.

from frost import *
import secrets
import unittest

class ExtendedParticipant(FROST.Participant):
    def __init__(self, index, threshold, participants):
        super().__init__(index, threshold, participants)
        #todo: rename to "nonces"
        self.enrollment_shares = []
        #todo: rename to "enrolment_shares"
        self.aggregate_enrollment_share = None

    # splits the secret (λ_i.s_i) into t additive shares
    def generate_enrollment_shares(self, participant_indexes):
        # λ_i.s_i = ∑ ẟ_j_i, 0 ≤ j ≤ t - 1
        Q = FROST.secp256k1.Q

        secret = self.lagrange_coefficient(participant_indexes) * self.aggregate_share % Q
        # generate t random shares that sum to λ_i.s_i
        self.enrollment_shares = [0 for _ in range(self.participants)]

        for index in participant_indexes:
            # we assign share for P_i (self) after this loop
            if index == self.index:
                continue
            self.enrollment_shares[index-1] = secrets.randbits(256) % Q

        share_Pi = (secret - sum(self.enrollment_shares)) % Q
        self.enrollment_shares[self.index - 1] = share_Pi

        assert(sum(self.enrollment_shares) % Q == secret)

    def aggregate_enrollment_shares(self, participant_indexes, enrollment_shares):
        # σ_i = ∑ ẟ_i_j, 0 ≤ j ≤ t - 1
        aggregate = self.enrollment_shares[self.index - 1]
        for share in enrollment_shares:
            aggregate = aggregate + share
        self.aggregate_enrollment_share = aggregate % FROST.secp256k1.Q

    def generate_frost_share(self, aggregate_enrollment_shares):
        s_i = sum(aggregate_enrollment_shares) % FROST.secp256k1.Q
        self.aggregate_share = s_i

    def increment_participants(self):
        self.participants += 1


class EnrollmentTests(unittest.TestCase):
    def test_generate_frost_share(self):
        p1 = ExtendedParticipant(index=1, threshold=2, participants=3)
        p2 = ExtendedParticipant(index=2, threshold=2, participants=3)
        p3 = ExtendedParticipant(index=3, threshold=2, participants=3)

        # KeyGen
        p1.init_keygen()
        p2.init_keygen()
        p3.init_keygen()

        p1.generate_shares()
        p2.generate_shares()
        p3.generate_shares()

        p1.aggregate_shares([p2.shares[p1.index-1], p3.shares[p1.index-1]])
        p2.aggregate_shares([p1.shares[p2.index-1], p3.shares[p2.index-1]])
        p3.aggregate_shares([p1.shares[p3.index-1], p2.shares[p3.index-1]])

        p1.derive_public_key([p2.coefficient_commitments[0], p3.coefficient_commitments[0]])
        p2.derive_public_key([p1.coefficient_commitments[0], p3.coefficient_commitments[0]])
        pk = p3.derive_public_key([p1.coefficient_commitments[0], p2.coefficient_commitments[0]])

        # Enrollment Protocol
        participant_indexes = [1, 2]
        # Round 1.1
        p1.generate_enrollment_shares(participant_indexes)
        p2.generate_enrollment_shares(participant_indexes)
        # Round 1.2
        p1.aggregate_enrollment_shares(participant_indexes, [p2.enrollment_shares[p1.index - 1]])
        p2.aggregate_enrollment_shares(participant_indexes, [p1.enrollment_shares[p2.index - 1]])
        # Round 2.1
        # New participant enrolled
        p4 = ExtendedParticipant(index=4, threshold=2, participants=4)
        p4.generate_frost_share([p1.aggregate_enrollment_share, p2.aggregate_enrollment_share])
        # Round 2.2
        p1.increment_participants()
        p2.increment_participants()

        # Reconstruct Secret

    def test_sign(self):
        # generate the new frost share
        # check if the sig using this new share is valid
        pass
    def test_not_in_keygen(self):
        ## checks that new pariticpant was not in keygen
        pass

if __name__ == '__main__':
    unittest.main()