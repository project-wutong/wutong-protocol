# SPDX-License-Identifier: AGPL-3.0-only
"""Zero-dependency pytest compatibility shim & runner for environments without pytest installed."""
import inspect
import pathlib
import re
import sys
import tempfile
import traceback


class _RaisesContext:
    def __init__(self, exc_type, match=None):
        self.exc_type = exc_type
        self.match = match
        self.value = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            raise AssertionError(f"DID NOT RAISE {self.exc_type}")
        if not issubclass(exc_type, self.exc_type):
            return False
        self.value = exc_val
        if self.match is not None and not re.search(self.match, str(exc_val)):
            raise AssertionError(
                f"Exception {exc_val!r} did not match pattern {self.match!r}"
            )
        return True


class _Mark:
    @staticmethod
    def parametrize(argnames, argvalues, ids=None):
        def decorator(fn):
            existing = getattr(fn, "_parametrize", [])
            existing.append((argnames, list(argvalues), ids))
            fn._parametrize = existing
            return fn

        return decorator


mark = _Mark()


def raises(exc_type, *, match=None):
    return _RaisesContext(exc_type, match=match)


def run_module(mod):
    passed = 0
    failed = 0
    for name, fn in inspect.getmembers(mod, inspect.isfunction):
        if not name.startswith("test_"):
            continue
        sig = inspect.signature(fn)
        params = getattr(fn, "_parametrize", None)
        cases = []
        if params:
            argname, vals, ids_fn = params[0]
            for idx, v in enumerate(vals):
                case_id = ids_fn(v) if callable(ids_fn) else str(idx)
                cases.append((f"{name}[{case_id}]", {argname: v}))
        else:
            cases.append((name, {}))

        for label, kwargs in cases:
            try:
                with tempfile.TemporaryDirectory() as td:
                    call_kwargs = dict(kwargs)
                    if "tmp_path" in sig.parameters:
                        call_kwargs["tmp_path"] = pathlib.Path(td)
                    fn(**call_kwargs)
                passed += 1
            except Exception as e:
                failed += 1
                print(f"FAIL: {label}: {e}", file=sys.stderr)
                traceback.print_exc()
    print(f"{passed} passed, {failed} failed")
    return 0 if failed == 0 else 1
