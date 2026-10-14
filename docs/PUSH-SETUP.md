# Push notifications: setup checklist

Everything for push (new messages and incoming calls) is implemented in the server, the core
and the mobile app. It stays **off until the credentials below are provided**: without them the
server logs `FCM push disabled` / `APNs VoIP call pushes disabled`, `/v1/info` reports
`"push_enabled": false`, and the app runs normally (notifications only while it runs).

## How it works (privacy model)

Like Signal, a push is only a wake-up signal. It never contains message content, the sender,
the caller or the conversation:

| Event | Android (FCM, data-only, high priority) | iOS |
|---|---|---|
| New message | `{"type":"new_message","p":"<tag>"}` | FCM → APNs alert with fixed text "New message" (loc-key `NEW_MESSAGE`) |
| Incoming call | `{"type":"call","call_id":"…","p":"<tag>"}`, TTL 60 s | APNs **VoIP** push `{"aps":{},"type":"call","call_id":"…","p":"<tag>"}` → CallKit; without the VoIP key: FCM alert "Incoming call" |

- `p` is a random tag the app picked for that account on that phone. It only tells the app which
  of its accounts the push is for (several accounts per phone, one open at a time).
- The server sends a push when an envelope is stored for a device without an open WebSocket, or
  whose socket did not acknowledge it within 10 s (3 s for a call offer). At most one message push
  per device per 10 s; one call push per call. The caller's app marks an offer with its call id;
  the offer itself stays end-to-end encrypted.
- Push tokens are never logged. Tokens that FCM / APNs report as invalid are deleted.
- Do-not-disturb, muted chats and notification previews are client settings the server never
  sees: the app decides whether to show or ring. Android, app running: the app fetches, decrypts
  and notifies as usual (honoring all of them). App not running: no account is open and the
  local data cannot be read without the password, so only a generic "New message" /
  "Incoming call" is shown (do-not-disturb, mirrored in `prefs.json`, is still honored). iOS:
  the system shows the generic alert; for calls, CallKit shows "Dialog" and the app ends the call
  at once during the app's do-not-disturb.

## What the owner must provide

### (a) Firebase project (Android and iOS apps)

1. <https://console.firebase.google.com> → *Add project* (Analytics not needed).
2. *Add app* → **Android**, package name **`pm.dialog.chat`**. Download
   **`google-services.json`** → put it at **`mobile/android/app/google-services.json`**.
   The Google services Gradle plugin is applied automatically only when this file exists.
3. *Add app* → **iOS**, bundle ID **`pm.dialog.chat`**. Download
   **`GoogleService-Info.plist`** → put it at **`mobile/ios/Runner/GoogleService-Info.plist`**.
   No Xcode step: the Runner build phase "Copy Firebase config (optional)" bundles it when it
   exists (and builds without it otherwise).
4. Skip the "add the Firebase SDK" steps (already done: `firebase_core`, `firebase_messaging`).

These two files identify the Firebase project; they are not secrets, but keep them out of a
public repository if you do not want the project id published.

### (b) APNs authentication key (.p8): in Firebase **and** on the server

1. <https://developer.apple.com/account/resources/authkeys/list> (your team) → *Keys* →
   **+** → name "Dialog push", enable **Apple Push Notifications service (APNs)** → *Continue* →
   *Register* → **Download** `AuthKey_XXXXXXXXXX.p8` (only downloadable once). Note the
   **Key ID** (10 characters) and your **Team ID** (Membership details).
2. Firebase console → *Project settings* → *Cloud Messaging* → *Apple app configuration* →
   *APNs Authentication Key* → upload the .p8 with Key ID and Team ID. (FCM uses it for iOS
   message alerts.)
3. The same .p8 on the server for VoIP call pushes (optional but recommended; without it iOS
   calls arrive as an ordinary "Incoming call" alert and do not ring through CallKit):
   `/srv/dialog/src/secrets/apns-auth-key.p8`.
4. App ID `pm.dialog.chat`: the *Push Notifications* capability is enabled automatically by
   Xcode's automatic signing (the project now has `Runner/Runner.entitlements` with
   `aps-environment`); if signing complains, enable it once at
   <https://developer.apple.com/account/resources/identifiers/list>. VoIP pushes use the topic
   `pm.dialog.chat.voip` (no separate certificate with a .p8 key).

### (c) Firebase service account for the server

1. Firebase console → *Project settings* → *Service accounts* → *Generate new private key* →
   a JSON file (`"type": "service_account"`). This **is** a secret.
2. Copy both files to the host (never into git; `*.p8` and `*service-account*.json` are
   ignored) and make them readable by the server container (UID 65532):

   ```sh
   scp fcm-service-account.json AuthKey_XXXXXXXXXX.p8 deploy@your-server:/tmp/
   ssh deploy@your-server
   sudo install -d -m 0750 -o 65532 -g 65532 /srv/dialog/src/secrets
   sudo install -m 0400 -o 65532 -g 65532 /tmp/fcm-service-account.json /srv/dialog/src/secrets/fcm-service-account.json
   sudo install -m 0400 -o 65532 -g 65532 /tmp/AuthKey_XXXXXXXXXX.p8 /srv/dialog/src/secrets/apns-auth-key.p8
   rm /tmp/fcm-service-account.json /tmp/AuthKey_XXXXXXXXXX.p8
   ```

   docker-compose mounts `./secrets` read-only at `/run/secrets/chatapp`.
3. Add to `/srv/dialog/src/.env`:

   ```sh
   CHATAPP_FCM_CREDENTIALS_FILE=/run/secrets/chatapp/fcm-service-account.json
   CHATAPP_APNS_KEY_FILE=/run/secrets/chatapp/apns-auth-key.p8
   CHATAPP_APNS_KEY_ID=XXXXXXXXXX
   CHATAPP_APNS_TEAM_ID=XXXXXXXXXX
   CHATAPP_APNS_TOPIC=pm.dialog.chat.voip
   # false (production APNs) for TestFlight / App Store builds; true only for a server used
   # with apps installed from Xcode / `flutter run` (development-signed).
   CHATAPP_APNS_SANDBOX=false
   ```

4. Deploy the new server version (`scripts/deploy-server.sh`; it runs migration 0015) or, if it
   is already deployed, `cd /srv/dialog/src && docker compose up -d server`. The configuration is
   validated at startup: a missing/unreadable file, a malformed key, a Key ID or Team ID that is
   not 10 characters, or a topic not ending in `.voip` stop the server with a clear message.

### (d) For the store releases later (not needed for push itself)

- **Google Play Console**: the *Full-screen intent* declaration (App content → "Calling app":
  the app rings for incoming calls with `USE_FULL_SCREEN_INTENT`); Data safety: device or other
  IDs (push token) collected for app functionality, not shared; the notification permission is
  requested at runtime (Android 13+).
- **App Store Connect**: the app uses the `voip` background mode, which App Review accepts only for
  real VoIP calling: give the reviewer a demo account and a second account to call. Privacy
  label: push tokens are used only for app functionality (never for tracking); declare them as
  such if you list identifiers. TestFlight and App Store builds use the production APNs
  environment (`CHATAPP_APNS_SANDBOX=false`).

## How to test

1. Server: `curl -s https://chat.dialog.pm/v1/info | jq '.push_enabled, .voip_push_enabled'`
   → `true true`; `docker compose logs server | grep -i push` shows `push notifications enabled`
   (with the Firebase project id) and `VoIP call pushes enabled`.
2. Build the apps with the Firebase files in place (`flutter run` / `flutter build`). In the app:
   Settings → Notifications → "Push notifications" says *Enabled*.
3. Android (real device or emulator with Google Play services): open an account, put the app in
   the background, send it a message from another account → a notification within seconds.
   Swipe the app away (not *Force stop*: force-stopped apps get no FCM) and send again →
   generic "New message". Call it with the app in the background → full-screen ringing with
   Answer / Decline.
4. iOS (real device; the simulator gets no VoIP pushes): background the app → "New message"
   alert. Lock the phone and call it → the CallKit incoming-call screen ("Dialog", then the
   caller's name if notification previews are on). If the app was terminated, answering opens a
   call that connects once you open Dialog and your account (the local data needs the
   password).
5. Two accounts on one phone: open account A, send a message to account B → "New message in
   another account"; tapping it shows the accounts list.
6. Unit tests (no network): `cd server-rs && cargo test push` (FCM / APNs against a local mock
   endpoint, coalescing, routing).

## Limitations and later improvements

- **iOS Notification Service Extension**: would let iOS decrypt and show sender / text (when
  previews are on) instead of the fixed "New message". Needs an app group shared with the
  extension and the account password problem solved (the local data is password-locked).
- After a cold start the account must be opened with its password before messages can be
  fetched or a call connected: that is the price of not trusting the OS keystore.
- Group calls ring through ordinary message pushes (no call push yet).
- If audio does not start after answering on the CallKit screen, wire WebRTC's `RTCAudioSession`
  to CallKit's audio session activation (`VoipCalls.provider(_:didActivate:)`).
- A phone's push token is refreshed on the server only for the account that is open; another
  account on the phone gets the new token the next time it is opened.
