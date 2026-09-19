# firestore-marketplace-rules

Tested Cloud Firestore security rules for a two-sided services marketplace: **customers** post jobs, **approved providers** accept them, **admins** moderate. 61 tests run against the Firestore emulator.

The point of the repo is the approach: security rules are the only authorisation layer a client-side Firebase app has, so they are written as a small, closed contract and every line of that contract has a test that would fail if it were loosened.

## Design rules

| Rule | How it is enforced |
|---|---|
| Clients never choose their own privileges | Admin comes from an auth **custom claim** set with the Admin SDK. There is no `role` field a user can write, on create or on update. |
| Approval is not self-service | A provider profile can only be created as `pending`. Only an admin can change `status`, and only that field. |
| A job follows a state machine | `open → accepted → completed`, or `→ cancelled`. Each transition is allowed for exactly one actor, and the write may touch only the fields that transition needs (`diff().affectedKeys().hasOnly(...)`). |
| Only approved providers can claim work | The `accepted` transition looks up the caller's provider profile with `get()`. |
| Audit and chat history are write-once | `auditLog` and job `messages` are create-only; `update` and `delete` are `false` for everyone, admins included. |
| Writes are shape-checked | Every `create` lists its allowed keys (`keys().hasOnly`), bounds string lengths, and pins server-controlled values (`createdAt == request.time`, `status == 'open'`). |
| Everything else is closed | A final `match /{document=**}` denies all access. |

## Run the tests

Needs Node 18+ and Java 11+ (for the emulator).

```bash
npm install
npm test
```

`npm test` starts the Firestore emulator under a `demo-` project id, which can never touch real Firebase resources, runs the suite with Node's built-in test runner, and shuts the emulator down.

## What the tests cover

`test/rules.test.js` is organised by collection: `users`, `providers`, `jobs` (create/read and the status machine), `job messages`, `audit log`, and `default deny`. Each grant has a test that proves the allowed path works and a test that proves the forbidden neighbours are rejected: another user, an anonymous caller, an unapproved provider, a stale state, an extra field, an impersonated sender.

The first draft of these rules let an anonymous caller read approved provider profiles. The test `anonymous users cannot read even approved providers` failed, and the rule was fixed rather than the test.

## What rules cannot do

Be clear about the limits before relying on this for a real app:

- **No rate limiting or quota control.** Use App Check and server-side limits.
- **No uniqueness or cross-document invariants.** Rules see one document plus a few `get()`s. Anything that must hold across many documents belongs in a transaction or a Cloud Function.
- **Racing writers are decided by Firestore, not by the rules.** Two providers claiming the same job both pass the rule against the stored `open` document, and the database lets only one commit. Clients must handle the loser.
- **Setting custom claims needs trusted server code.** This repo assumes that step exists.
- **Rules are not a substitute for reviewing what your queries return.** A rule that permits a read permits every field on that document.

## Files

- `firestore.rules`: the rules
- `test/rules.test.js`: the suite
- `firebase.json`: emulator configuration

## Licence

MIT. See `LICENSE`.
