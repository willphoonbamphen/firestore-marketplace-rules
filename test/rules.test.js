// Security-rules tests for firestore.rules. Run with `npm test` (needs Java for the emulator).
//
// Every rule that grants access has a test that proves the allowed path works, and every rule
// that withholds access has a test that proves the forbidden path is rejected. A rule with only
// "allowed" tests can be silently wide open.
const { test, before, after, beforeEach, describe } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const {
  initializeTestEnvironment,
  assertFails,
  assertSucceeds,
} = require('@firebase/rules-unit-testing');
const {
  addDoc, collection, deleteDoc, doc, getDoc, getDocs, query, serverTimestamp, setDoc, updateDoc, where,
  setLogLevel,
} = require('firebase/firestore');

// Rejected writes are the point of these tests; keep the SDK from logging each one as an error.
setLogLevel('silent');

let env;

before(async () => {
  env = await initializeTestEnvironment({
    projectId: 'demo-marketplace', // "demo-" projects can never touch real Firebase resources
    firestore: {
      rules: fs.readFileSync(path.join(__dirname, '..', 'firestore.rules'), 'utf8'),
      host: '127.0.0.1',
      port: 8080,
    },
  });
});

after(async () => {
  await env.cleanup();
});

beforeEach(async () => {
  await env.clearFirestore();
  // Seed with rules disabled so each test starts from a known state.
  await env.withSecurityRulesDisabled(async (ctx) => {
    const db = ctx.firestore();
    await setDoc(doc(db, 'providers', 'pro1'), { bio: 'Approved', categories: ['plumbing'], status: 'approved' });
    await setDoc(doc(db, 'providers', 'pro2'), { bio: 'Pending', categories: [], status: 'pending' });
    await setDoc(doc(db, 'jobs', 'open1'), {
      customerId: 'cust1', title: 'Fix a tap', description: 'Leaking', category: 'plumbing',
      status: 'open', providerId: null,
    });
    await setDoc(doc(db, 'jobs', 'acc1'), {
      customerId: 'cust1', title: 'Fix a sink', description: 'Blocked', category: 'plumbing',
      status: 'accepted', providerId: 'pro1',
    });
    await setDoc(doc(db, 'jobs', 'done1'), {
      customerId: 'cust1', title: 'Old job', description: 'Done', category: 'plumbing',
      status: 'completed', providerId: 'pro1',
    });
    await setDoc(doc(db, 'jobs', 'acc1', 'messages', 'm1'), { senderId: 'cust1', text: 'Hello' });
    await setDoc(doc(db, 'users', 'cust1'), { displayName: 'Customer', phone: '000' });
  });
});

const as = (uid, claims) => env.authenticatedContext(uid, claims).firestore();
const anon = () => env.unauthenticatedContext().firestore();
const admin = () => as('admin1', { admin: true });

const newJob = (over = {}) => ({
  customerId: 'cust1', title: 'Paint a wall', description: 'Two coats', category: 'painting',
  status: 'open', providerId: null, createdAt: serverTimestamp(), ...over,
});

describe('users', () => {
  test('owner can create a profile', () =>
    assertSucceeds(setDoc(doc(as('u1'), 'users', 'u1'), { displayName: 'Ana', phone: '1', createdAt: serverTimestamp() })));

  test('a profile cannot carry a role field', () =>
    assertFails(setDoc(doc(as('u1'), 'users', 'u1'), { displayName: 'Ana', phone: '1', role: 'admin', createdAt: serverTimestamp() })));

  test('cannot create a profile for someone else', () =>
    assertFails(setDoc(doc(as('u2'), 'users', 'u1'), { displayName: 'Ana', phone: '1', createdAt: serverTimestamp() })));

  test('anonymous users cannot read a profile', () => assertFails(getDoc(doc(anon(), 'users', 'cust1'))));
  test('another user cannot read a profile', () => assertFails(getDoc(doc(as('u2'), 'users', 'cust1'))));
  test('owner can read their profile', () => assertSucceeds(getDoc(doc(as('cust1'), 'users', 'cust1'))));
  test('an admin can read any profile', () => assertSucceeds(getDoc(doc(admin(), 'users', 'cust1'))));

  test('owner can update the display name', () =>
    assertSucceeds(updateDoc(doc(as('cust1'), 'users', 'cust1'), { displayName: 'New name' })));

  test('owner cannot add a role by updating', () =>
    assertFails(updateDoc(doc(as('cust1'), 'users', 'cust1'), { role: 'admin' })));

  test('profiles cannot be deleted', () => assertFails(deleteDoc(doc(as('cust1'), 'users', 'cust1'))));
});

describe('providers', () => {
  test('an applicant can apply, and starts as pending', () =>
    assertSucceeds(setDoc(doc(as('p9'), 'providers', 'p9'), {
      bio: 'Electrician', categories: ['electrical'], status: 'pending', createdAt: serverTimestamp(),
    })));

  test('an applicant cannot create themselves as approved', () =>
    assertFails(setDoc(doc(as('p9'), 'providers', 'p9'), {
      bio: 'Electrician', categories: [], status: 'approved', createdAt: serverTimestamp(),
    })));

  test('a provider cannot approve themselves', () =>
    assertFails(updateDoc(doc(as('pro2'), 'providers', 'pro2'), { status: 'approved' })));

  test('a provider can edit their own bio', () =>
    assertSucceeds(updateDoc(doc(as('pro2'), 'providers', 'pro2'), { bio: 'Updated bio' })));

  test('an admin can approve a provider', () =>
    assertSucceeds(updateDoc(doc(admin(), 'providers', 'pro2'), { status: 'approved' })));

  test('an admin can only change status, not the bio', () =>
    assertFails(updateDoc(doc(admin(), 'providers', 'pro2'), { bio: 'Edited by admin' })));

  test('signed-in users can list approved providers', () =>
    assertSucceeds(getDocs(query(collection(as('cust1'), 'providers'), where('status', '==', 'approved')))));

  test('signed-in users cannot read a pending provider', () =>
    assertFails(getDoc(doc(as('cust1'), 'providers', 'pro2'))));

  test('an unfiltered listing is rejected', () =>
    assertFails(getDocs(collection(as('cust1'), 'providers'))));

  test('anonymous users cannot read even approved providers', () =>
    assertFails(getDoc(doc(anon(), 'providers', 'pro1'))));
});

describe('jobs: create and read', () => {
  test('a customer can post an open job', () =>
    assertSucceeds(setDoc(doc(as('cust1'), 'jobs', 'new1'), newJob())));

  test('cannot post a job as another customer', () =>
    assertFails(setDoc(doc(as('cust2'), 'jobs', 'new1'), newJob())));

  test('cannot post a job that is already accepted', () =>
    assertFails(setDoc(doc(as('cust1'), 'jobs', 'new1'), newJob({ status: 'accepted' }))));

  test('cannot post a job with a provider pre-assigned', () =>
    assertFails(setDoc(doc(as('cust1'), 'jobs', 'new1'), newJob({ providerId: 'pro1' }))));

  test('cannot post a job with extra fields', () =>
    assertFails(setDoc(doc(as('cust1'), 'jobs', 'new1'), newJob({ price: 1 }))));

  test('cannot post a job with an empty title', () =>
    assertFails(setDoc(doc(as('cust1'), 'jobs', 'new1'), newJob({ title: '' }))));

  test('anonymous users cannot post jobs', () =>
    assertFails(setDoc(doc(anon(), 'jobs', 'new1'), newJob())));

  test('the customer can read their job', () => assertSucceeds(getDoc(doc(as('cust1'), 'jobs', 'open1'))));
  test('the assigned provider can read the job', () => assertSucceeds(getDoc(doc(as('pro1'), 'jobs', 'acc1'))));
  test('an outsider cannot read a job', () => assertFails(getDoc(doc(as('stranger'), 'jobs', 'open1'))));
  test('an admin can read a job', () => assertSucceeds(getDoc(doc(admin(), 'jobs', 'open1'))));
  test('jobs cannot be deleted, even by the customer', () => assertFails(deleteDoc(doc(as('cust1'), 'jobs', 'open1'))));
});

describe('jobs: status machine', () => {
  test('an approved provider can accept an open job', () =>
    assertSucceeds(updateDoc(doc(as('pro1'), 'jobs', 'open1'), { status: 'accepted', providerId: 'pro1' })));

  test('an unapproved provider cannot accept a job', () =>
    assertFails(updateDoc(doc(as('pro2'), 'jobs', 'open1'), { status: 'accepted', providerId: 'pro2' })));

  test('a user with no provider profile cannot accept a job', () =>
    assertFails(updateDoc(doc(as('nobody'), 'jobs', 'open1'), { status: 'accepted', providerId: 'nobody' })));

  test('the customer cannot accept their own job', () =>
    assertFails(updateDoc(doc(as('cust1'), 'jobs', 'open1'), { status: 'accepted', providerId: 'cust1' })));

  test('a provider cannot assign a different provider', () =>
    assertFails(updateDoc(doc(as('pro1'), 'jobs', 'open1'), { status: 'accepted', providerId: 'someone-else' })));

  test('accepting cannot smuggle in other field changes', () =>
    assertFails(updateDoc(doc(as('pro1'), 'jobs', 'open1'), { status: 'accepted', providerId: 'pro1', title: 'Changed' })));

  test('an already-accepted job cannot be taken over', async () => {
    await env.withSecurityRulesDisabled(async (ctx) => {
      await setDoc(doc(ctx.firestore(), 'providers', 'pro3'), { bio: 'Second', categories: [], status: 'approved' });
    });
    await assertFails(updateDoc(doc(as('pro3'), 'jobs', 'acc1'), { status: 'accepted', providerId: 'pro3' }));
  });

  test('the customer can cancel an open job', () =>
    assertSucceeds(updateDoc(doc(as('cust1'), 'jobs', 'open1'), { status: 'cancelled' })));

  test('the customer can cancel an accepted job', () =>
    assertSucceeds(updateDoc(doc(as('cust1'), 'jobs', 'acc1'), { status: 'cancelled' })));

  test('the customer cannot cancel a completed job', () =>
    assertFails(updateDoc(doc(as('cust1'), 'jobs', 'done1'), { status: 'cancelled' })));

  test('the customer cannot mark a job completed', () =>
    assertFails(updateDoc(doc(as('cust1'), 'jobs', 'acc1'), { status: 'completed' })));

  test('the assigned provider can complete the job', () =>
    assertSucceeds(updateDoc(doc(as('pro1'), 'jobs', 'acc1'), { status: 'completed' })));

  test('the provider cannot complete a job that was never accepted', () =>
    assertFails(updateDoc(doc(as('pro1'), 'jobs', 'open1'), { status: 'completed' })));

  test('a different provider cannot complete the job', async () => {
    await env.withSecurityRulesDisabled(async (ctx) => {
      await setDoc(doc(ctx.firestore(), 'providers', 'pro3'), { bio: 'Other', categories: [], status: 'approved' });
    });
    await assertFails(updateDoc(doc(as('pro3'), 'jobs', 'acc1'), { status: 'completed' }));
  });

  test('a completed job cannot be reopened', () =>
    assertFails(updateDoc(doc(as('pro1'), 'jobs', 'done1'), { status: 'open' })));

  test('an admin cannot bypass the state machine', () =>
    assertFails(updateDoc(doc(admin(), 'jobs', 'open1'), { status: 'completed' })));
});

describe('job messages', () => {
  const msg = (uid) => ({ senderId: uid, text: 'Hi there', createdAt: serverTimestamp() });

  test('the customer can post a message', () =>
    assertSucceeds(addDoc(collection(as('cust1'), 'jobs', 'acc1', 'messages'), msg('cust1'))));

  test('the assigned provider can post a message', () =>
    assertSucceeds(addDoc(collection(as('pro1'), 'jobs', 'acc1', 'messages'), msg('pro1'))));

  test('an outsider cannot post a message', () =>
    assertFails(addDoc(collection(as('stranger'), 'jobs', 'acc1', 'messages'), msg('stranger'))));

  test('a participant cannot post as someone else', () =>
    assertFails(addDoc(collection(as('cust1'), 'jobs', 'acc1', 'messages'), msg('pro1'))));

  test('participants can read messages, outsiders cannot', async () => {
    await assertSucceeds(getDocs(collection(as('pro1'), 'jobs', 'acc1', 'messages')));
    await assertFails(getDocs(collection(as('stranger'), 'jobs', 'acc1', 'messages')));
  });

  test('a provider not yet assigned cannot read messages', () =>
    assertFails(getDocs(collection(as('pro2'), 'jobs', 'open1', 'messages'))));

  test('messages are immutable', async () => {
    await assertFails(updateDoc(doc(as('cust1'), 'jobs', 'acc1', 'messages', 'm1'), { text: 'Edited' }));
    await assertFails(deleteDoc(doc(as('cust1'), 'jobs', 'acc1', 'messages', 'm1')));
  });
});

describe('audit log', () => {
  const entry = (uid) => ({ actorId: uid, action: 'provider.approved', targetId: 'pro2', at: serverTimestamp() });

  test('an admin can append an entry', () =>
    assertSucceeds(addDoc(collection(admin(), 'auditLog'), entry('admin1'))));

  test('an admin cannot write an entry in someone else\'s name', () =>
    assertFails(addDoc(collection(admin(), 'auditLog'), entry('another-admin'))));

  test('a normal user cannot write or read the log', async () => {
    await assertFails(addDoc(collection(as('cust1'), 'auditLog'), entry('cust1')));
    await assertFails(getDocs(collection(as('cust1'), 'auditLog')));
  });

  test('a user cannot grant themselves admin through a profile field', () =>
    assertFails(updateDoc(doc(as('cust1'), 'users', 'cust1'), { admin: true })));

  test('entries can never be edited or deleted, even by an admin', async () => {
    let ref;
    await env.withSecurityRulesDisabled(async (ctx) => {
      ref = await addDoc(collection(ctx.firestore(), 'auditLog'), { actorId: 'admin1', action: 'x', targetId: 'y', at: 1 });
    });
    await assertFails(updateDoc(doc(admin(), 'auditLog', ref.id), { action: 'tampered' }));
    await assertFails(deleteDoc(doc(admin(), 'auditLog', ref.id)));
  });
});

describe('default deny', () => {
  test('unknown collections are closed to everyone, including admins', async () => {
    await assertFails(getDoc(doc(admin(), 'somethingElse', 'x')));
    await assertFails(setDoc(doc(admin(), 'somethingElse', 'x'), { a: 1 }));
  });
});
