Description
---

API Details
---
- `TODO`
   - point1
   - point2
```python
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