"""patch_v2.py — replace Phase 4 app content in generate_notebook.py"""
import pathlib

GEN = pathlib.Path("generate_notebook.py")
APP = pathlib.Path("streamlit_app_premium.py")

gen_text = GEN.read_text(encoding="utf-8")
app_text = APP.read_text(encoding="utf-8")

# Phase 4 starts here (current text after first patch)
START_MARKER = "# ---------- PHASE 4: STREAMLIT APP (PREMIUM) ----------"
# Phase 5 starts here
END_MARKER   = "# ---------- PHASE 5: LAUNCH ----------"

si = gen_text.find(START_MARKER)
ei = gen_text.find(END_MARKER)

if si == -1 or ei == -1:
    raise RuntimeError(f"Marker not found! si={si} ei={ei}")

print(f"Replacing Phase 4 block [{si}:{ei}], {ei-si} chars")

# Escape the app text so it can be embedded in a Python JSON string
# We'll use json.dumps to get a safe Python string literal
import json
app_escaped = json.dumps(app_text)     # produces "..content..with proper escaping.."

new_phase4 = f'''# ---------- PHASE 4: STREAMLIT APP (PREMIUM) ----------
cells.append(md("## Phase 4 — Write Streamlit Demo App"))
_app_content = {app_escaped}
cells.append(writefile_cell("/kaggle/working/SecureByDesign/app/streamlit_app.py", _app_content))
cells.append(code('print("\\u2705 Premium Streamlit app written.")'))

'''

patched = gen_text[:si] + new_phase4 + gen_text[ei:]
GEN.write_text(patched, encoding="utf-8")
print("Done. Lines now:", len(patched.splitlines()))
