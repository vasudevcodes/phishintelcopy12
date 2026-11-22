# Fix: "PyTorch/transformers could not be loaded" + header showing Offline

## Cause
1. `backend/requirements.txt` did not list `torch` / `transformers`, so a fresh venv never got them.
   (Already fixed in this package.) A second possible cause on Windows is a blocked torch DLL (WinError 4551).
2. The DistilBERT weights are NOT in the zip (`models/` is git-ignored). Even with torch installed the model
   reports "checkpoint not found" until the folder exists.

## Steps (PowerShell, from the project root)
```powershell
cd backend
.\.venv\Scripts\Activate.ps1

# Optional, NVIDIA GPU only (e.g. RTX 3050) - install BEFORE the next line:
# pip install torch --index-url https://download.pytorch.org/whl/cu124

pip install -r requirements.txt
```
Then make sure your trained model is at:
```
<project root>\models\distilbert_baseline\   (config.json + model.safetensors + tokenizer files)
```
(or point to it: `$env:PHISHINTEL_MODEL_DIR="D:\path\to\distilbert_baseline"`).

Restart the backend and check:
```powershell
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
# browser: http://127.0.0.1:8000/health/model
```
You want `"torch_importable": true` and `"checkpoint_found": true`.

## If you still see WinError 4551 / DLL blocked
Install "Microsoft Visual C++ Redistributable 2015-2022 (x64)", then
`pip uninstall torch -y; pip install torch`, and keep the venv outside policy-restricted folders.

## Header badge
The top-right badge now retries until the backend answers and also falls back to `/health`.
It shows "Live DNS · Online" when the backend has online verification enabled. If it still says Offline:
- the backend isn't running on 127.0.0.1:8000 (open `/api/v1/system/status` there), or
- `PHISHINTEL_ONLINE_AUTH=0` is set in that shell (`Remove-Item Env:PHISHINTEL_ONLINE_AUTH`), or
- restart `npm run dev` (vite.config.ts changed: `/health` is now proxied).

## "transformers not found" even after pip install
pip and uvicorn are probably using different Pythons. Always use `python -m` so they match:
```powershell
cd backend
.\.venv\Scripts\Activate.ps1
python -c "import sys; print(sys.executable)"      # must point inside backend\.venv
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -c "import torch, transformers; print(torch.__version__, transformers.__version__)"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
Stop any old uvicorn first (Ctrl+C in its window). Then open http://127.0.0.1:8000/health/model -
`python_executable` shows exactly which Python the server uses and `import_error` the real reason.
