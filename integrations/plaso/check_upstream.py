"""CI only: execute the upstream parser suites against the pinned native stack."""

import json
import sys
import unittest

sys.path.insert(0, "/opt/plaso-source")
unittest.fail_unless_has_test_file = True
suite = unittest.defaultTestLoader.discover(
    "/opt/plaso-source/tests/parsers", pattern="*.py", top_level_dir="/opt/plaso-source"
)
result = unittest.TextTestRunner(verbosity=1).run(suite)
print(
    json.dumps(
        {
            "tests": result.testsRun,
            "errors": len(result.errors),
            "failures": len(result.failures),
            "skipped": [{"test": str(test), "reason": reason} for test, reason in result.skipped],
        },
        sort_keys=True,
    )
)
sys.exit(not result.wasSuccessful())
