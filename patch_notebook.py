"""patch_notebook.py — injects premium Streamlit app into generate_notebook.py"""
import pathlib, re

gen_path     = pathlib.Path("generate_notebook.py")
premium_path = pathlib.Path("streamlit_app_premium.py")

gen     = gen_path.read_text(encoding="utf-8")
premium = premium_path.read_text(encoding="utf-8")

# Locate the PHASE 4 block: from the comment to the %%writefile call for streamlit
start_marker = "# ---------- PHASE 4: STREAMLIT APP ----------"
end_marker   = 'cells.append(writefile_cell("/kaggle/working/SecureByDesign/app/streamlit_app.py"'

start_idx = gen.find(start_marker)
end_idx   = gen.find(end_marker, start_idx)

if start_idx == -1 or end_idx == -1:
    raise RuntimeError(f"Markers not found. start={start_idx} end={end_idx}")

print(f"Replacing block [{start_idx}:{end_idx}]")

# Build replacement: new phase 4 header + writefile_cell using premium content
# We store the premium content as a Python variable and then call writefile_cell
new_block = (
    '# ---------- PHASE 4: STREAMLIT APP (PREMIUM) ----------\n'
    'cells.append(md("## Phase 4 — Write Streamlit Demo App (Premium UI)"))\n'
    '_premium_app = open("streamlit_app_premium.py", encoding="utf-8").read()\n'
    '# Note: on Kaggle the file won\'t be present, so we embed the content directly:\n'
    '_premium_app_content = r\'\'\'' + premium.replace("'''", r"\'\'\'") + '\'\'\'\n'
    'cells.append(writefile_cell("/kaggle/working/SecureByDesign/app/streamlit_app.py",\n'
    '    _premium_app_content))\n'
)

gen_patched = gen[:start_idx] + new_block + gen[end_idx:]
gen_path.write_text(gen_patched, encoding="utf-8")
print("Done. generate_notebook.py patched successfully.")
