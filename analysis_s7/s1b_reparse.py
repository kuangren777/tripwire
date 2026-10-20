"""calls_in_text: tool-call JSON objects left in a model's final text (shared parse-rate rule, copied unchanged)."""
import json

DEC = json.JSONDecoder()


def calls_in_text(text):
    """Every JSON object (also inside a JSON list) with a function name and an argument dict."""
    out, i = [], 0
    while i < len(text):
        if text[i] in "{[":
            try:
                obj, j = DEC.raw_decode(text, i)
            except ValueError:
                i += 1
                continue
            for o in (obj if isinstance(obj, list) else [obj]):
                if not isinstance(o, dict):
                    continue
                f = o.get("name") or o.get("function")
                a = o.get("arguments", o.get("parameters", o.get("args")))
                if isinstance(f, dict):                     # {"function": {"name":..., "arguments":...}}
                    f, a = f.get("name"), f.get("arguments", a)
                if isinstance(f, str) and isinstance(a, dict):
                    out.append({"f": f, "a": a})
            i = j
        else:
            i += 1
    return out
