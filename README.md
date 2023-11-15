Description
---
Extends [BIP340-compatible FROST](https://github.com/jesseposner/FROST-BIP340) with an [enrollment protocol](https://gist.github.com/nickfarrow/64c2e65191cde6a1a47bbd4572bf8cf8#multi-party-computation-enrollment). It enables recovery of lost shares and addition of new participants. Essentially, it converts a $(t, n)$ threshold scheme to a $(t, n+1)$ scheme.

API Details
---
- `generate_enrollment_shares`
   - $t$ participants involved in enrollment protocol will run this API first
   - this splits each participants contribution (towards a new share) into $t$ random values
     - we do this for security reasons
     - without this the new participant can compute $P_i$'s frost share
     - by multiplying the data $P_i$ sends with $\ell_i(x)^{-1}$
   - these $t$ value are sent to the other $t-1$ participants (not to new participant)
```python
def generate_enrollment_shares(self, participant_indexes, new_participant_index)
```
- `aggregate_enrollment_shares`
   - each participants aggregates the random values received from other $t-1$ participants
   - now each participant sends this aggregated value to the new participant
   - they also need to send their group public key, since new participant was not part of dkg
```python
def aggregate_enrollment_shares(self, participant_indexes, enrollment_shares)
```
- `generate_frost_share`
   - new participant simply sums the the value received from $t$ participants
   - this will result in a new frost share which they can use for signing
   - now the scheme go from $(t, n)$ to $(t, n+1)$
```python
def generate_frost_share(self, aggregate_enrollment_shares, group_public_key)
```

Build Instructions
---
To clone the repo:
```bash
git clone --recurse-submodules <project-url>
```
To build the code:
```bash
# need to run this `export` cmd when you start a new terminal session
export PYTHONPATH=$PYTHONPATH:./frost-bip340
python main.py
```
To run the tests:
```bash
# runs all tests
python -m unittest main.py

# runs the sepecified test
python -m unittest -k EnrollmentTests.<test-name> main.py
```