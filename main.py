# This module implements an enrollment protocol for
# BIP-340 compatible FROST implementation (by Jesse Posner).
# Spec details: section 4.1.1 in https://eprint.iacr.org/2017/1155.pdf.

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'frost-bip340'))
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

    # generalization of `lagrange_coefficient` method
    def eval_lagrange_basis_poly(self, participant_indexes, at_index):
        Q = FROST.secp256k1.Q
        # 𝓛_i(x) = ∏ (p_j - x)/(p_j - p_i), 1 ≤ j ≤ α, j ≠ i
        numerator = 1
        denominator = 1
        for index in participant_indexes:
            if index == self.index:
                continue
            numerator = numerator * (index - at_index)
            denominator = denominator * (index - self.index)
        return (numerator * pow(denominator, Q - 2, Q)) % Q

    def generate_enrollment_shares(self, participant_indexes, new_participant_index):
        """Generate enrollment shares for a new participant joining the protocol.

        This method implements Round 1.1 of the enrollment protocol. Each existing
        participant generates t random shares that sum to 𝓛_i(x).s_i, where 𝓛_i(x)
        is the Lagrange basis polynomial evaluated at the new participant's index.

        Args:
            participant_indexes: List of current participant indices
            new_participant_index: Index of the new participant being enrolled
        """
        Q = FROST.secp256k1.Q

        # 𝓛_i(x).s_i = ∑ ẟ_j_i, 0 ≤ j ≤ t - 1
        secret = self.eval_lagrange_basis_poly(participant_indexes, new_participant_index) * self.aggregate_share % Q
        # generate t random shares that sum to 𝓛_i(x).s_i
        self.enrollment_shares = [0 for _ in range(self.participants)]

        for index in participant_indexes:
            # we assign share for P_i (self) after this loop
            if index == self.index:
                continue
            self.enrollment_shares[index-1] = secrets.randbits(256) % Q

        share_Pi = (secret - sum(self.enrollment_shares)) % Q
        self.enrollment_shares[self.index - 1] = share_Pi

        # Verify shares sum to the expected secret
        shares_sum = sum(self.enrollment_shares) % Q
        if shares_sum != secret:
            raise ValueError(f"Enrollment shares verification failed: sum={shares_sum}, expected={secret}")

    def aggregate_enrollment_shares(self, participant_indexes, enrollment_shares):
        """Aggregate enrollment shares from other participants.

        Args:
            participant_indexes: List of participant indices involved in enrollment
            enrollment_shares: List of enrollment shares received from other participants
        """
        # σ_i = ∑ ẟ_i_j, 0 ≤ j ≤ t - 1
        aggregate = self.enrollment_shares[self.index - 1]
        for share in enrollment_shares:
            aggregate += share
        self.aggregate_enrollment_share = aggregate % FROST.secp256k1.Q

    def generate_frost_share(self, aggregate_enrollment_shares, group_public_key):
        """Generate FROST share for the new participant.

        This method allows a new participant to compute their aggregate share
        from the enrollment shares received from existing participants.

        Args:
            aggregate_enrollment_shares: List of aggregate shares from existing participants
            group_public_key: The group's public key from the original DKG
        """
        if not aggregate_enrollment_shares:
            raise ValueError("Cannot generate FROST share: no enrollment shares provided")

        self.aggregate_share = sum(aggregate_enrollment_shares) % FROST.secp256k1.Q
        self.public_key = group_public_key

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
        self.assertIsNotNone(pk)

        # Enrollment Protocol
        participant_indexes = [1, 2]
        # 2-of-3 becomes 2-of-4
        p_new = ExtendedParticipant(index=len(participants)+1, threshold=2, participants=len(participants)+1)

        # Round 1.1
        for i in participant_indexes:
            participants[i-1].generate_enrollment_shares(participant_indexes, p_new.index)
        # Round 1.2
        for i in participant_indexes:
            other_enroll_shares = [participants[j-1].enrollment_shares[i-1] for j in participant_indexes if j != i]
            participants[i-1].aggregate_enrollment_shares(participant_indexes, other_enroll_shares)
        # Round 2
        agg_enrollment_shares = [participants[i-1].aggregate_enrollment_share for i in participant_indexes]
        p_new.generate_frost_share(agg_enrollment_shares, pk)

        # Later participants update n to n+1
        for p in participants:
            p.increment_participants()

        # copy the values to setup
        self.participants = participants
        self.pk = pk
        self.participant_indexes = participant_indexes
        self.new_participant = p_new

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
        p3 = self.participants[2]
        p_new = self.new_participant
        pk = self.pk

        # NonceGen
        p3.generate_nonces(1)
        p_new.generate_nonces(1)

        # Sign
        msg = b'Hey p4, welcome to the world of threshold sigs!'
        participant_indexes = [3, 4]
        agg = FROST.Aggregator(pk, msg, [None, None, p3.nonce_commitment_pairs, p_new.nonce_commitment_pairs], participant_indexes)
        message, nonce_commitment_pairs = agg.signing_inputs()

        s3 = p3.sign(message, nonce_commitment_pairs, participant_indexes)
        s_new = p_new.sign(message, nonce_commitment_pairs, participant_indexes)

        # σ = (R, z)
        sig = agg.signature([s3, s_new])
        sig_bytes = bytes.fromhex(sig)
        nonce_commitment = FROST.Point.xonly_deserialize(sig_bytes[0:32].hex())
        z = int.from_bytes(sig_bytes[32:64], 'big')

        # verify
        G = FROST.secp256k1.G()
        # c = H_2(R, Y, m)
        challenge_hash = FROST.Aggregator.challenge_hash(nonce_commitment, pk, msg)
        # Negate Y if Y.y is odd
        if pk.y % 2 != 0:
            pk = -pk

        # R ≟ g^z * Y^-c
        self.assertTrue(nonce_commitment == (z * G) + (FROST.secp256k1.Q - challenge_hash) * pk)

    def test_participant_not_in_dkg(self):
        p_new = self.new_participant

        # asserts participant was absent in DKG
        self.assertListEqual(p_new.coefficients, [])
        self.assertListEqual(p_new.coefficient_commitments, [])
        self.assertListEqual(p_new.proof_of_knowledge, [])
        self.assertListEqual(p_new.shares, [])

        # asserts participant can participate in signing
        self.assertIsNotNone(p_new.aggregate_share)
        self.assertIsNotNone(p_new.public_key)

if __name__ == '__main__':
    unittest.main()