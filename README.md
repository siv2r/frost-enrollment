Description
---
Extends [BIP340-compatible FROST](https://github.com/jesseposner/FROST-BIP340) with an [enrollment protocol](https://gist.github.com/nickfarrow/64c2e65191cde6a1a47bbd4572bf8cf8#multi-party-computation-enrollment). It enables recovery of lost shares and addition of new participants. Essentially, it converts a $(t, n)$ threshold scheme to a $(t, n+1)$ scheme.

Architecture Overview
---
The project has been refactored into a modular architecture for improved maintainability and extensibility:

### Core Modules

1. **`enrollment.py`** - Enrollment Protocol Implementation
   - `EnrollmentParticipant`: Extended participant class with enrollment capabilities
   - `EnrollmentCoordinator`: Manages multi-party enrollment orchestration
   - Implements the protocol from section 4.1.1 of [the FROST paper](https://eprint.iacr.org/2017/1155.pdf)

2. **`crypto_utils.py`** - Cryptographic Utilities
   - `CryptoUtils`: Helper functions for elliptic curve operations
   - `ShareValidator`: Validation logic for enrollment and FROST shares
   - Lagrange polynomial evaluation
   - Secret splitting and reconstruction

3. **`config.py`** - Configuration Management
   - `EnrollmentConfig`: Centralized configuration for threshold parameters
   - `ProtocolConfig`: Protocol-specific settings and validation
   - Environment variable support for deployment flexibility

4. **`main.py`** - Legacy Interface & Tests
   - Contains `ExtendedParticipant` (deprecated, use `EnrollmentParticipant`)
   - Comprehensive test suite for enrollment protocol
   - Backwards compatibility layer

### Module Dependencies

```
main.py
  ├── enrollment.py
  │   ├── crypto_utils.py
  │   └── config.py
  ├── crypto_utils.py
  └── frost-bip340/frost.py
```

API Details
---
### New Architecture APIs

#### EnrollmentParticipant (enrollment.py)
```python
from enrollment import EnrollmentParticipant
from config import EnrollmentConfig

# Create configuration
config = EnrollmentConfig({
    'threshold': 2,
    'participants': 3,
    'security_level': 256
})

# Initialize participant
participant = EnrollmentParticipant(
    index=1,
    threshold=config.threshold,
    participants=config.participants,
    config=config
)
```

#### EnrollmentCoordinator (enrollment.py)
```python
from enrollment import EnrollmentCoordinator

coordinator = EnrollmentCoordinator(threshold=2, participants=existing_participants)
new_participant = coordinator.initiate_enrollment(
    participant_indexes=[1, 2],
    new_participant_index=4
)
```

### Legacy APIs (Deprecated)

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

Configuration
---
### Using Configuration Files

Create a `config.json`:
```json
{
  "threshold": 2,
  "participants": 3,
  "security_level": 256,
  "enable_share_backup": true,
  "enable_verification": true
}
```

Load in your code:
```python
from config import EnrollmentConfig

config = EnrollmentConfig.load_from_file('config.json')
```

### Using Environment Variables

Set environment variables:
```bash
export FROST_THRESHOLD=2
export FROST_PARTICIPANTS=3
export FROST_SECURITY_LEVEL=256
```

Load in your code:
```python
from config import create_config_from_env

config = create_config_from_env()
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

Testing
---
To run the tests:
```bash
# runs all tests
python -m unittest main.py

# runs the specified test
python -m unittest -k EnrollmentTests.<test-name> main.py

# run with verbose output
python -m unittest -v main.py
```

### Test Coverage

The test suite includes:
- ✅ FROST share generation and reconstruction
- ✅ Signature generation and verification with enrolled participants
- ✅ Enrollment protocol correctness
- ✅ Integration with cryptographic utilities
- ✅ Share validation logic

Migration Guide
---
### Migrating from ExtendedParticipant to EnrollmentParticipant

**Before:**
```python
from main import ExtendedParticipant

p = ExtendedParticipant(index=1, threshold=2, participants=3)
p.generate_enrollment_shares([1, 2], 4)
```

**After:**
```python
from enrollment import EnrollmentParticipant
from config import EnrollmentConfig

config = EnrollmentConfig({'threshold': 2, 'participants': 3})
p = EnrollmentParticipant(index=1, threshold=2, participants=3, config=config)
p.generate_enrollment_shares([1, 2], 4)
```

Security Considerations
---
- This is a **reference implementation** for educational purposes
- Not audited for production use
- Share backups should be encrypted (see `config.enable_share_backup`)
- Use appropriate key derivation in production environments
- Validate all inputs in production deployments

Performance Notes
---
- Enrollment protocol requires $t$ participants to be online
- Communication complexity: $O(t^2)$ for $t$ participants
- Computation complexity: $O(t)$ per participant
- Recommended maximum participants: 100 (see `config.get_max_participants()`)

Troubleshooting
---
### Common Issues

1. **Import Errors**: Ensure `PYTHONPATH` includes `./frost-bip340`
2. **Test Failures**: Check that you're using Python 3.8+
3. **Configuration Errors**: Validate threshold ≤ participants
4. **Module Not Found**: Make sure all new modules are in the project root

Contributing
---
When contributing, please:
1. Update tests for any new functionality
2. Follow the modular architecture patterns
3. Add configuration options to `config.py` when needed
4. Update this README with API changes

Future Enhancements
---
- [ ] Network layer for distributed enrollment
- [ ] Persistent storage for participant shares
- [ ] Advanced share recovery mechanisms
- [ ] Performance optimizations for large participant sets
- [ ] Integration with hardware security modules (HSMs)

References
---
- [FROST Paper](https://eprint.iacr.org/2017/1155.pdf) - Original threshold signature scheme
- [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) - Schnorr signatures for secp256k1
- [FROST-BIP340](https://github.com/jesseposner/FROST-BIP340) - Base implementation
