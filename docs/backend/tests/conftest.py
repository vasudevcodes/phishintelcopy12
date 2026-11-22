"""
Test configuration.

The pre-existing suite was written for offline, deterministic behaviour. Live DNS verification is therefore
disabled for it by default so tests never touch the network. Tests that exercise live verification inject a
fake resolver (see test_live_authentication.py) or enable the flag explicitly.

To run the suite WITH live DNS (needs internet):  PHISHINTEL_TEST_ONLINE=1 pytest
"""
import os

if os.getenv("PHISHINTEL_TEST_ONLINE") != "1":
    os.environ["PHISHINTEL_ONLINE_AUTH"] = "0"
