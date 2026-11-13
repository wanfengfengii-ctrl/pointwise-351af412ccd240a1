import json
import sys
from reader import load, read
from compact import replay


def evaluate(path):
    bundle = load(path)
    after = replay(bundle)
    evidence = []
    for query in bundle["observations"]:
        snapshot, at = query["snapshot"], query["at"]
        original = read(bundle, snapshot, at)
        actual = read(after, snapshot, at)
        for key, value in query["expected"].items():
            assert original[key] == value, ("SOURCE_CONTRACT", key, original)
        evidence.append({"snapshot": snapshot, "at": at,
                         "before": original, "after": actual,
                         "changed": [k for k in bundle["keys"]
                                     if original[k] != actual[k]],
                         "balance_before": original["a"] + original["b"]
                         if "a" in original and original["a"] is not None
                         and original["b"] is not None else None,
                         "balance_after": actual["a"] + actual["b"]
                         if "a" in actual and actual["a"] is not None
                         and actual["b"] is not None else None})
    return evidence


def main(mode):
    if mode == "normal":
        evidence = evaluate("data/normal.json")
        assert all(not r["changed"] for r in evidence), evidence
        print(json.dumps(evidence, sort_keys=True))
        print("NORMAL_COUNTER_READ_OK")
        return 0
    if mode in ("incident", "demo"):
        evidence = evaluate("data/incident.json")
        print(json.dumps(evidence, sort_keys=True))
        failed = any(r["changed"] for r in evidence)
        if failed:
            print("MERGE_VIEW_DIVERGENCE")
        return int(failed and mode == "incident")
    raise ValueError("unknown mode: " + mode)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
