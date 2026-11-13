import copy
import json


def load(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def applicable(row, key):
    if row["op"] == "range":
        return row["lo"] <= key < row["hi"]
    return row["key"] == key


def resolve(rows, key, snapshot, at, cap):
    visible = sorted(
        (r for r in rows if r["seq"] <= snapshot and applicable(r, key)),
        key=lambda r: r["seq"], reverse=True)
    pending = []
    value = None
    for row in visible:
        op = row["op"]
        expiry = row.get("until")
        expired = expiry is not None and at >= expiry
        if op == "add":
            if not expired:
                pending.append(row["value"])
            continue
        if op == "put" and not expired:
            value = row["value"]
        break
    for delta in reversed(pending):
        value = min(cap, max(0, (0 if value is None else value) + delta))
    return value


def read(bundle, snapshot, at):
    rows = [row for run in bundle["runs"].values() for row in run]
    return {key: resolve(rows, key, snapshot, at, bundle["cap"])
            for key in bundle["keys"]}


def with_base(bundle, key, value):
    result = copy.deepcopy(bundle)
    result["runs"]["bottom"] = [
        r for r in result["runs"]["bottom"] if r["key"] != key]
    if value is not None:
        result["runs"]["bottom"].append(
            {"id": "context-" + key, "key": key, "seq": 0,
             "op": "put", "value": value})
    return result
