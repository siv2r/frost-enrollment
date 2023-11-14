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
    def setUp(self):
        participants = [ExtendedParticipant(index=i, threshold=2, participants=3) for i in range(1, 4)]
        pk = None

        # KeyGen Protocol
        for p in participants:
            p.init_keygen()

        for p in participants:
            p.generate_shares()
        # same as Round 2.3 in `test_keygen` fn (in frost-bip340/frost.py)
        for i, pi in enumerate(participants):
            other_shares = [pj.shares[i] for pj in participants if pj != pi]
            pi.aggregate_shares(other_shares)

        for i, pi in enumerate(participants):
            other_coeff_commitments = [pj.coefficient_commitments[0] for pj in participants if pj != pi]
            derived_pk = pi.derive_public_key(other_coeff_commitments)
            if i == 0:
                pk = derived_pk
            else:
                self.assertEqual(pk, derived_pk)

        # Enrollment Protocol
        participant_indexes = [1, 2]
        # Round 1.1
        for i in participant_indexes:
            participants[i-1].generate_enrollment_shares(participant_indexes)
        # Round 1.2
        for i in participant_indexes:
            other_enroll_shares = [participants[j-1].enrollment_shares[i-1] for j in participant_indexes if j != i]
            participants[i-1].aggregate_enrollment_shares(participant_indexes, other_enroll_shares)
        # Round 2
        # New participant enrolled, 2-of-3 becomes 2-of-4
        p4 = ExtendedParticipant(index=len(participants)+1, threshold=2, participants=len(participants)+1)
        agg_enrollment_shares = [participants[i-1].aggregate_enrollment_share for i in participant_indexes]
        p4.generate_frost_share(agg_enrollment_shares)

        # Later participants update n to n+1
        for p in participants:
            p.increment_participants()

        # copy the values to setup
        self.participants = participants
        self.pk = pk
        self.participant_indexes = participant_indexes
        self.new_participant = p4

    def test_generate_frost_share(self):
        Q = FROST.secp256k1.Q
        G = FROST.secp256k1.G()

        p1 = self.participants[0]
        p2 = self.participants[1]
        p3 = self.participants[2]
        # new participant who joined through "Enrollment Protocol"
        p_new = self.new_participant
        participant_indexes = self.participant_indexes

        # Reconstruct Secret with p1 & p2
        l1 = p1.lagrange_coefficient([1, 2])
        l2 = p2.lagrange_coefficient([1, 2])
        secret = ((p1.aggregate_share * l1) + (p2.aggregate_share * l2)) % Q
        self.assertEqual(secret * G, self.pk)

        # Reconstruct Secret with p1 & p_new
        l1 = p1.lagrange_coefficient([1, 4])
        l_new = p_new.lagrange_coefficient([1, 4])
        secret = ((p1.aggregate_share * l1) + (p_new.aggregate_share * l_new)) % Q
        self.assertEqual(secret * G, self.pk)

        # Reconstruct Secret with p3 & p_new
        l3 = p3.lagrange_coefficient([3, 4])
        l_new = p_new.lagrange_coefficient([3, 4])
        secret = ((p3.aggregate_share * l3) + (p_new.aggregate_share * l_new)) % Q
        self.assertEqual(secret * G, self.pk)

    def test_sign(self):
        # generate the new frost share
        # check if the sig using this new share is valid
        pass
    def test_not_in_keygen(self):
        ## checks that new pariticpant was not in keygen
        pass

if __name__ == '__main__':
    unittest.main()