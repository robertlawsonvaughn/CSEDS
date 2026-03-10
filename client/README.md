1. Register screen
   └── username + password → derive keys → register → auto-login

2. Main screen (logged in)
   ├── Simple data editor (text area — proves the encrypt/sync cycle)
   ├── Save button → encrypt → upload blob
   ├── Sync status indicator (last sync timestamp, blob size)
   └── Logout button

3. Login screen
   └── username + password → derive keys → login → sync blob down

4. Recovery screen
   └── "Forgot credentials" → read IndexedDB #2 → display credentials
