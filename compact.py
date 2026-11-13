import copy


def compact(bundle, inputs, output):
    result = copy.deepcopy(bundle)
    selected = [r for name in inputs for r in result["runs"].pop(name)]
    emitted = [r for r in selected if r["op"] == "range"]
    points = {}
    for row in selected:
        if row["op"] != "range":
            points.setdefault(row["key"], []).append(row)
    for key, rows in sorted(points.items()):
        rows.sort(key=lambda r: r["seq"])
        group = []

        def flush():
            if not group:
                return
            if len(group) == 1:
                emitted.append(group[0])
            else:
                deadlines = [r.get("until") for r in group]
                emitted.append({
                    "id": output + ":" + key + ":" + str(group[-1]["seq"]),
                    "key": key, "seq": group[-1]["seq"], "op": "add",
                    "value": sum(r["value"] for r in group),
                    "until": None if None in deadlines else max(deadlines),
                    "parents": [r["id"] for r in group]})
            group.clear()

        for row in rows:
            if row["op"] == "add":
                group.append(row)
            else:
                flush()
                emitted.append(row)
        flush()
    result["runs"][output] = sorted(emitted, key=lambda r: (r["seq"], r["id"]))
    return result


def replay(bundle):
    state = bundle
    for job in bundle["jobs"]:
        state = compact(state, job["inputs"], job["output"])
    return state
