# Install: PhishIntel online SPF / DKIM / DMARC

1. **Back up / commit your project first** (this package overwrites 12 existing files; see docs/online_authentication.md).
2. Extract this zip **into your project root** (the folder that contains `backend/`, `frontend/`, `docs/`),
   choosing "replace files" when asked.
3. Install the two new Python dependencies:
       cd backend
       pip install -r requirements.txt
4. Start the backend as usual, then open  http://localhost:8000/health/dns
   You should see  "dns_reachable": true.
5. Frontend: no new packages. Restart `npm run dev` if it was running.
6. Run the tests:  `cd backend && pytest`
   (Live DNS is switched off automatically for the old test-suite by tests/conftest.py, so tests never need internet.)

To turn online verification off at any time:  set  PHISHINTEL_ONLINE_AUTH=0
