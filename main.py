# This module implements an enrollment protocol for
# BIP-340 compatible FROST implementation (by Jesse Posner).
# Spec details: section 4.1.1 in https://eprint.iacr.org/2017/1155.pdf.

from frost import *
import unittest

class ExtendedParticipant(FROST.Participant):
    def __init__(self, index, threshold, participants):
        super().__init__(index, threshold, participants)
        self.enrollment_shares = []
        self.aggregate_enrollment_share = None
        #TODO: don't forget to update `n` after creating a new enroll share

        # splits λ_i.s_i into n additive shares
        #todo: this should be `t` right? not `n`. So, where should this param be saved? check frost
        def generate_enrollment_shares(self):

            # assert the shares sum upto λ_i.s_i

        def aggregate_enrollment_shares(self, enrollment_shares):
            pass

        def generate_frost_share(self, aggregate_enrollment_shares):
            pass

class EnrollmentTests(unittest.TestCase):
    def test_generate_frost_share():
        # generate the frost shares for a new pariticpant
        # reconstruct the secret using this new share
        pass
    def test_sign():
        # generate the new frost share
        # check if the sig using this new share is valid
        pass
    def test_not_in_keygen():
        ## checks that new pariticpant was not in keygen
        pass

if __name__ == '__main__':
    pass