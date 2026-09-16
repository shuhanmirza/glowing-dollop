<script setup>
import { ref, computed, onMounted, watch } from 'vue'
import { detectWallets, authenticate } from '../walletBridge.js'
import { burst } from '../confetti.js'
import { log, abbrev } from '../log.js'
// Bundled by Vite (hashed into the build), so the wallet reward GIF always
// loads offline — no external hotlink to fail during a live demo.
import rickrollGif from '../assets/rickroll.gif'

// Identifier-first sign-in flow. Step 1 collects the email and asks the backend
// how to authenticate this user (POST /api/login/start). The backend replies
// with a `method`, which decides step 2:
//
//   - "password": the user has a local account here; prompt for a password.
//   - "oauth":    the user's provider is bound to the Verifier; the domain->
//                 issuer trust is known, so sign in via that provider (Google).
//   - "trust":    with no pre-binding, the user's domain declared an authorized
//                 issuer (via WebFinger over HTTPS), so the Verifier trusts the
//                 domain->issuer relationship. Shown as a trust cue.
//   - "ebia":     no trusted domain->issuer relationship; prove mailbox control
//                 via a magic link instead (shown in the UI for the demo).
//
// The OAuth round-trip leaves the SPA (redirect to the provider and back), so
// on load we also check for a ?login=<id> / ?login_error=<code> return.

// step: 'email' | 'password' | 'oauth' | 'relay' | 'trust' | 'ebia' | 'ebia_verified' | 'done'
const step = ref('email')
const email = ref('')
const domain = ref('')
const password = ref('')
const trust = ref(null)
const ebia = ref(null)
const relay = ref(null)
// Relay method page controls (Task 1: reveal discovery doc; Task 2: step-by-step).
const showRelayDetails = ref(false)
const stepByStep = ref(false)
const session = ref(null)
const loading = ref(false)
const error = ref('')
// ebiaSession is set after the user returns from the magic link (mailbox
// control proven); it lets the wallet sign-in skip the domain->issuer check.
const ebiaSession = ref('')

// Identity-wallet state: wallets that announced themselves, and status while
// the proof-of-possession round-trip runs.
const wallets = ref([])
const walletBusy = ref(false)
const walletError = ref('')

const canStart = computed(() => email.value.trim().length > 0 && !loading.value)
const canSubmitPassword = computed(
  () => password.value.length > 0 && !loading.value,
)

// Show just the host of an issuer URL in the trust cue (e.g. accounts.google.com).
const issuerHost = computed(() => {
  if (!trust.value?.issuer) return ''
  try {
    return new URL(trust.value.issuer).host
  } catch (e) {
    return trust.value.issuer
  }
})

const relayIssuerHost = computed(() => {
  if (!relay.value?.issuer) return ''
  try {
    return new URL(relay.value.issuer).host
  } catch (e) {
    return relay.value.issuer
  }
})

// The (tongue-in-cheek) "resource" the user unlocks, themed by how they
// signed in. Password and OAuth use self-contained CSS/emoji animations; the
// wallet reward is the bundled rickroll GIF.
const rewards = {
  password: {
    meme: 'potato',
    title: 'The Legendary Dancing Potato',
    blurb: 'Local password accepted. Behold your spud.',
  },
  oauth: {
    meme: 'googly',
    title: 'Certified Googly Eyes™',
    blurb: 'Signed in with Google. These eyes see all.',
  },
  wallet: {
    meme: 'rickroll',
    title: 'An Exclusive Musical Performance',
    blurb: 'Proof-of-possession verified. You earned this.',
  },
  relay: {
    meme: 'rickroll',
    title: 'An Exclusive Musical Performance',
    blurb: 'Signed in through a blind relay — it never saw your token.',
  },
}

const reward = computed(() => rewards[session.value?.method] || rewards.password)

// Celebrate when the user reaches the success page.
watch(step, (s) => {
  if (s === 'done') burst()
})

const oauthErrors = {
  google_unavailable: 'Google sign-in is temporarily unavailable.',
  expired: 'That sign-in attempt expired. Please try again.',
  exchange_failed: 'Could not complete sign-in with Google.',
  invalid_id_token: 'Could not verify the response from Google.',
  nonce_mismatch: 'Could not verify the response from Google.',
  access_denied: 'Sign-in was cancelled.',
}

function oauthErrorMessage(code) {
  return oauthErrors[code] || 'Sign-in did not complete. Please try again.'
}

onMounted(async () => {
  const params = new URLSearchParams(window.location.search)
  const loginId = params.get('login')
  const loginErr = params.get('login_error')
  const ebiaSid = params.get('ebia')
  const ebiaErr = params.get('ebia_error')
  if (!loginId && !loginErr && !ebiaSid && !ebiaErr) return

  // Clean the return params out of the URL.
  window.history.replaceState({}, '', window.location.pathname)

  // EBIA magic-link return: mailbox control was proven. Let the user finish
  // signing in with their wallet (authority here comes from mailbox control,
  // so the wallet sign-in skips the domain->issuer check).
  if (ebiaErr) {
    error.value = 'That email verification link expired. Please start again.'
    return
  }
  if (ebiaSid) {
    loading.value = true
    try {
      const res = await fetch('/api/ebia/info?session=' + encodeURIComponent(ebiaSid))
      const data = await res.json()
      if (!res.ok) {
        error.value = data.error || 'Email verification expired. Please start again.'
        return
      }
      email.value = data.email
      domain.value = data.email.slice(data.email.lastIndexOf('@') + 1)
      ebiaSession.value = ebiaSid
      step.value = 'ebia_verified'
      detectWallets().then((list) => {
        wallets.value = list
      })
    } catch (e) {
      error.value = 'Email verification could not be completed.'
    } finally {
      loading.value = false
    }
    return
  }

  if (loginErr) {
    error.value = oauthErrorMessage(loginErr)
    return
  }

  loading.value = true
  try {
    const res = await fetch('/api/login/result?id=' + encodeURIComponent(loginId))
    const data = await res.json()
    if (!res.ok) {
      error.value = data.error || 'Could not complete sign-in.'
      return
    }
    email.value = data.email
    // Derive the success-page theme from how the login actually completed. The
    // relay flow reports provider "relay"; everything else here is Google OAuth.
    const method = data.provider === 'relay' ? 'relay' : 'oauth'
    session.value = { ...data, method }
    step.value = 'done'
  } catch (e) {
    error.value = 'Could not complete sign-in.'
  } finally {
    loading.value = false
  }
})

async function startLogin() {
  error.value = ''
  loading.value = true
  try {
    const res = await fetch('/api/login/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email.value }),
    })
    const data = await res.json()
    if (!res.ok) {
      error.value = data.error || 'Something went wrong. Please try again.'
      return
    }
    email.value = data.email
    domain.value = data.domain
    trust.value = data.trust || null
    ebia.value = data.ebia || null
    relay.value = data.relay || null
    if (data.method === 'password') step.value = 'password'
    else if (data.method === 'oauth') step.value = 'oauth'
    else if (data.method === 'relay') step.value = 'relay'
    else if (data.method === 'trust') step.value = 'trust'
    else if (data.method === 'ebia') step.value = 'ebia'
    else step.value = 'ebia'

    // Offer the identity wallet only where there is NO pre-binding with a
    // provider -- i.e. the domain declared its issuer via WebFinger ("trust").
    // For "oauth" the Verifier already has a provider binding, so keep the
    // existing redirect flow only (no wallet).
    if (step.value === 'trust') {
      detectWallets().then((list) => {
        wallets.value = list
      })
    }
  } catch (e) {
    error.value = 'Could not reach the server. Please try again.'
  } finally {
    loading.value = false
  }
}

// signInWithWallet runs the proof-of-possession flow with a chosen wallet:
// get a fresh challenge, have the wallet sign it with the key committed in its
// PK Token, then post the PK Token + signed challenge for server verification.
async function signInWithWallet(wallet) {
  walletError.value = ''
  walletBusy.value = true
  log('verifier-page', `PoP flow start with wallet "${wallet.name}"`, {
    email: email.value,
    basis: ebiaSession.value ? 'ebia (mailbox control)' : 'domain→issuer trust',
  })
  try {
    log('verifier-page', '→ GET /api/wallet/challenge', { email: email.value })
    const chRes = await fetch(
      '/api/wallet/challenge?email=' + encodeURIComponent(email.value),
    )
    const chData = await chRes.json()
    if (!chRes.ok) {
      walletError.value = chData.error || 'Could not start wallet sign-in.'
      return
    }
    log('verifier-page', '← challenge issued by backend', { challenge: chData.challenge })

    const { pkt, osm } = await authenticate({
      rdns: wallet.rdns,
      email: email.value,
      challenge: chData.challenge,
      // In the EBIA case the wallet may hold any issuer's token for this email;
      // otherwise require a token from the domain-declared issuer.
      issuer: ebiaSession.value ? '' : trust.value?.issuer || '',
    })

    const body = { email: email.value, challenge: chData.challenge, pkt, osm }
    // When we arrived via the magic link, present the EBIA session so the
    // backend accepts the token on the basis of proven mailbox control.
    if (ebiaSession.value) body.ebiaSession = ebiaSession.value

    log('verifier-page', '→ POST /api/wallet/verify (PK Token + signed challenge)', {
      pkt: abbrev(pkt),
      osm: abbrev(osm),
      ebiaSession: ebiaSession.value ? abbrev(ebiaSession.value) : '(none)',
    })
    const vRes = await fetch('/api/wallet/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    const vData = await vRes.json()
    if (!vRes.ok) {
      log('verifier-page', `← verify FAILED (${vRes.status})`, { error: vData.error })
      walletError.value = vData.error || 'Wallet verification failed.'
      return
    }
    log('verifier-page', '← verify OK — signed in', {
      email: vData.email,
      issuer: vData.issuer,
      source: vData.source,
    })
    session.value = { email: vData.email, iss: vData.issuer, provider: 'wallet', method: 'wallet' }
    step.value = 'done'
  } catch (e) {
    walletError.value = walletErrorMessage(e.message)
  } finally {
    walletBusy.value = false
  }
}

// walletErrorMessage turns the wallet's terse outcome codes into readable text.
function walletErrorMessage(code) {
  switch (code) {
    case 'expired-token':
      return 'Your token for this email expired. Refresh it in your wallet, then try again.'
    case 'no-token':
      return 'Add a token for this email in your wallet, then try again.'
    case 'denied':
    case 'cancelled':
      return 'Wallet sign-in was cancelled.'
    default:
      return code || 'Wallet sign-in did not complete.'
  }
}

async function submitPassword() {
  error.value = ''
  loading.value = true
  try {
    const res = await fetch('/api/login/password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email.value, password: password.value }),
    })
    const data = await res.json()
    if (!res.ok) {
      error.value = data.error || 'Incorrect email or password.'
      return
    }
    session.value = { email: email.value, provider: '' }
    step.value = 'done'
  } catch (e) {
    error.value = 'Could not reach the server. Please try again.'
  } finally {
    loading.value = false
  }
}

// Leave the SPA and start the Google OAuth flow. The backend redirects to
// Google and, after consent, back to this app with the result.
function continueWithGoogle() {
  window.location.href =
    '/api/oauth/google/start?email=' + encodeURIComponent(email.value)
}

// Leave the SPA and start the blind-relay (split-PKCE) flow. The backend
// redirects to the OP via the relay's registered redirect URI; the relay
// relays the code back and the backend redeems it, then returns here.
// When "step-by-step" is on we pass step=1; the backend and relay then pause
// at each hop to show what is being sent (the toggle rides in the OAuth state).
function continueThroughRelay() {
  let url = '/api/relay/start?email=' + encodeURIComponent(email.value)
  if (stepByStep.value) url += '&step=1'
  window.location.href = url
}

function reset() {
  step.value = 'email'
  password.value = ''
  domain.value = ''
  trust.value = null
  ebia.value = null
  relay.value = null
  showRelayDetails.value = false
  stepByStep.value = false
  session.value = null
  error.value = ''
  wallets.value = []
  walletBusy.value = false
  walletError.value = ''
  ebiaSession.value = ''
}
</script>

<template>
  <div class="card" :class="{ 'card-celebrate': step === 'done' }">
    <div class="brand">XYZ.com</div>

    <!-- Step 1: email -->
    <template v-if="step === 'email'">
      <h1 class="title">Sign in</h1>
      <p class="subtitle">Use your email to continue</p>

      <form class="form" @submit.prevent="startLogin">
        <label class="label" for="email">Email</label>
        <input
          id="email"
          v-model="email"
          class="input"
          type="email"
          name="email"
          autocomplete="email"
          placeholder="you@example.com"
          autofocus
          @input="error = ''"
        />

        <p v-if="error" class="error">{{ error }}</p>

        <button class="button" type="submit" :disabled="!canStart">
          {{ loading ? 'Please wait…' : 'Next' }}
        </button>
      </form>
    </template>

    <!-- Step 2a: local password -->
    <template v-else-if="step === 'password'">
      <h1 class="title">Enter your password</h1>
      <p class="subtitle">
        Signing in as <strong>{{ email }}</strong>
      </p>

      <form class="form" @submit.prevent="submitPassword">
        <label class="label" for="password">Password</label>
        <input
          id="password"
          v-model="password"
          class="input"
          type="password"
          name="password"
          autocomplete="current-password"
          placeholder="Your password"
          autofocus
          @input="error = ''"
        />

        <p v-if="error" class="error">{{ error }}</p>

        <button class="button" type="submit" :disabled="!canSubmitPassword">
          {{ loading ? 'Signing in…' : 'Sign in' }}
        </button>
        <button class="button button-secondary" type="button" @click="reset">
          Use a different email
        </button>
      </form>
    </template>

    <!-- Step 2b: OAuth via a bound provider (Google) -->
    <template v-else-if="step === 'oauth'">
      <h1 class="title">Continue with your provider</h1>
      <p class="subtitle">
        Signing in as <strong>{{ email }}</strong>
      </p>

      <!-- Trust cue: the Verifier established the domain->issuer relationship. -->
      <div class="trust" role="status">
        <span class="trust-check" aria-hidden="true">🔒</span>
        <div class="trust-text">
          <div class="trust-title">Trusted domain → issuer</div>
          <div class="trust-detail">
            {{ trust?.domain }} → {{ issuerHost }}
            <span class="trust-src">via {{ trust?.source }}</span>
          </div>
        </div>
      </div>

      <p v-if="error" class="error">{{ error }}</p>

      <!-- XYZ.com already has a binding with this provider, so this is the
           standard redirect flow only (no wallet). -->
      <button class="button button-google" type="button" @click="continueWithGoogle">
        <span class="g-icon" aria-hidden="true">G</span>
        Continue with Google
      </button>
      <button class="button button-secondary" type="button" @click="reset">
        Use a different email
      </button>
    </template>

    <!-- Step 2b': blind relay declared by the domain (byoid-configuration) -->
    <template v-else-if="step === 'relay'">
      <h1 class="title">Continue through the blind relay</h1>
      <p class="subtitle">
        Signing in as <strong>{{ email }}</strong>
      </p>

      <!-- Cue: the domain delegates a blind relay fronting its issuer. -->
      <div class="trust" role="status">
        <span class="trust-check" aria-hidden="true">🛰️</span>
        <div class="trust-text">
          <div class="trust-title">Relayed identity provider</div>
          <div class="trust-detail">
            {{ relay?.namespace }} → {{ relayIssuerHost }}
            <span class="trust-src">via blind relay</span>
          </div>
        </div>
      </div>

      <p class="result-note">
        <strong>{{ relay?.namespace }}</strong> delegates a blind relay to sign
        its users in through <strong>{{ relayIssuerHost }}</strong>. The relay
        relays the login but never sees your token.
      </p>

      <!-- Task 1: reveal the byoid-configuration the Verifier fetched. -->
      <div class="disclose" v-if="relay?.wellKnown">
        <button
          type="button"
          class="disclose-toggle"
          :aria-expanded="showRelayDetails"
          @click="showRelayDetails = !showRelayDetails"
        >
          <span class="disclose-caret" :class="{ open: showRelayDetails }">▸</span>
          {{ showRelayDetails ? 'Hide' : 'Show' }} discovery document
          <span class="disclose-hint">/.well-known/byoid-configuration</span>
        </button>
        <pre v-if="showRelayDetails" class="disclose-json">{{ relay.wellKnown }}</pre>
      </div>

      <!-- Task 2: toggle a step-by-step walkthrough of the OIDC hops. -->
      <label class="stepwitch">
        <input type="checkbox" v-model="stepByStep" />
        <span class="stepwitch-track"><span class="stepwitch-thumb"></span></span>
        <span class="stepwitch-label">
          Step-by-step demo
          <span class="stepwitch-hint">pause at each hop to show what is sent</span>
        </span>
      </label>

      <p v-if="error" class="error">{{ error }}</p>

      <button class="button" type="button" @click="continueThroughRelay">
        Continue through the blind relay
      </button>
      <button class="button button-secondary" type="button" @click="reset">
        Use a different email
      </button>
    </template>

    <!-- Step 2c: trust established via the domain's own declaration (WebFinger) -->
    <template v-else-if="step === 'trust'">
      <h1 class="title">Trust established</h1>
      <p class="subtitle">
        Signing in as <strong>{{ email }}</strong>
      </p>

      <div class="trust" role="status">
        <span class="trust-check" aria-hidden="true">🔒</span>
        <div class="trust-text">
          <div class="trust-title">Trusted domain → issuer</div>
          <div class="trust-detail">
            {{ trust?.domain }} → {{ issuerHost }}
            <span class="trust-src">via {{ trust?.source }}</span>
          </div>
        </div>
      </div>

      <p class="result-note">
        <strong>{{ trust?.domain }}</strong> authorizes
        <strong>{{ issuerHost }}</strong> to issue credentials for its users.
      </p>

      <!-- Identity wallet(s): prove you hold a token from the trusted issuer. -->
      <div v-if="wallets.length" class="wallet-block">
        <div class="wallet-heading">Continue with your identity wallet</div>
        <button
          v-for="w in wallets"
          :key="w.uuid"
          class="button button-wallet"
          type="button"
          :disabled="walletBusy"
          @click="signInWithWallet(w)"
        >
          <span class="wallet-icon" aria-hidden="true">🔑</span>
          {{ walletBusy ? 'Waiting for your wallet…' : w.name }}
        </button>
        <p v-if="walletError" class="error">{{ walletError }}</p>
      </div>
      <p v-else class="result-note">
        Install the identity wallet to prove you hold a token from
        <strong>{{ issuerHost }}</strong>.
      </p>

      <button class="button button-secondary" type="button" @click="reset">
        Use a different email
      </button>
    </template>

    <!-- Step 2d: EBIA fallback — no trusted relationship, prove mailbox control -->
    <template v-else-if="step === 'ebia'">
      <h1 class="title">Verify your email</h1>
      <p class="subtitle">
        Signing in as <strong>{{ email }}</strong>
      </p>

      <div class="trust trust-warn" role="status">
        <span class="trust-check" aria-hidden="true">⚠️</span>
        <div class="trust-text">
          <div class="trust-title">No trusted domain → issuer relationship</div>
          <div class="trust-detail">
            <strong>{{ domain }}</strong> does not declare an authorized issuer.
          </div>
        </div>
      </div>

      <p class="result-note">
        Prove you control this mailbox instead. In a real flow we'd email you a
        link; for this demo, click it here:
      </p>

      <a class="button button-google" :href="ebia?.magicLink" target="_blank" rel="noopener">
        Open the verification link
      </a>
      <p class="magic-url">{{ ebia?.magicLink }}</p>

      <button class="button button-secondary" type="button" @click="reset">
        Use a different email
      </button>
    </template>

    <!-- Step 2e: EBIA verified — mailbox control proven, finish with wallet -->
    <template v-else-if="step === 'ebia_verified'">
      <h1 class="title">Email verified</h1>
      <p class="subtitle">
        Signing in as <strong>{{ email }}</strong>
      </p>

      <div class="trust" role="status">
        <span class="trust-check" aria-hidden="true">✅</span>
        <div class="trust-text">
          <div class="trust-title">Mailbox control verified</div>
          <div class="trust-detail">
            You proved you control <strong>{{ email }}</strong>.
          </div>
        </div>
      </div>

      <p class="result-note">
        Finish signing in by proving you hold an identity token for this email.
      </p>

      <!-- Identity wallet(s): authority here is your proven mailbox control. -->
      <div v-if="wallets.length" class="wallet-block">
        <div class="wallet-heading">Continue with your identity wallet</div>
        <button
          v-for="w in wallets"
          :key="w.uuid"
          class="button button-wallet"
          type="button"
          :disabled="walletBusy"
          @click="signInWithWallet(w)"
        >
          <span class="wallet-icon" aria-hidden="true">🔑</span>
          {{ walletBusy ? 'Waiting for your wallet…' : w.name }}
        </button>
        <p v-if="walletError" class="error">{{ walletError }}</p>
      </div>
      <p v-else class="result-note">
        Install the identity wallet to finish signing in for
        <strong>{{ email }}</strong>.
      </p>

      <button class="button button-secondary" type="button" @click="reset">
        Use a different email
      </button>
    </template>

    <!-- Done — an expanded, celebratory, deliberately silly success page. -->
    <template v-else-if="step === 'done'">
      <div class="success">
        <div class="success-badge">✓ Signed in</div>
        <h1 class="success-title">You’re in! 🎉</h1>
        <p class="success-sub">
          Signed in as <strong>{{ session?.email || email }}</strong>
          <span v-if="session && session.method === 'oauth'"> via Google</span>
          <span v-else-if="session && session.method === 'wallet'"> via your identity wallet</span>
          <span v-else-if="session && session.method === 'relay'"> via a blind relay</span>
        </p>

        <!-- The (very important) unlocked "resource". -->
        <div class="reward">
          <div class="reward-label">🔓 You now have access to</div>

          <!-- Self-contained meme animations (no external assets). -->
          <div class="meme">
            <!-- Password → dancing potato -->
            <div v-if="reward.meme === 'potato'" class="meme-potato" aria-hidden="true">
              <div class="potato">
                🥔
                <span class="potato-eye potato-eye-l"></span>
                <span class="potato-eye potato-eye-r"></span>
              </div>
              <div class="potato-shadow"></div>
            </div>

            <!-- OAuth → googly eyes -->
            <div v-else-if="reward.meme === 'googly'" class="meme-googly" aria-hidden="true">
              <div class="eye"><div class="pupil"></div></div>
              <div class="eye"><div class="pupil"></div></div>
            </div>

            <!-- Wallet → rickroll (bundled GIF) -->
            <div v-else class="meme-rickroll">
              <img class="rick-gif" :src="rickrollGif" alt="Rickroll" />
              <div class="rick-caption">♪ Never gonna give you up ♪</div>
            </div>
          </div>

          <div class="reward-title">{{ reward.title }}</div>
          <div class="reward-blurb">{{ reward.blurb }}</div>
        </div>

        <p v-if="session && session.iss" class="success-meta">
          Issuer: {{ session.iss }}
        </p>
        <button class="button button-secondary success-signout" type="button" @click="reset">
          Sign out
        </button>
      </div>
    </template>
  </div>
</template>

<style scoped>
.card {
  width: 100%;
  max-width: 400px;
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 40px 32px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.06);
  transition: max-width 0.35s ease, box-shadow 0.35s ease;
}

/* Success: expand and visually distinguish the card from the flow pages. */
.card-celebrate {
  max-width: 560px;
  background: linear-gradient(160deg, #ffffff 0%, #f3f0ff 100%);
  border-color: #d8ccff;
  box-shadow: 0 20px 60px rgba(90, 52, 184, 0.22);
}

.success {
  text-align: center;
  animation: pop-in 0.45s cubic-bezier(0.16, 1, 0.3, 1);
}

@keyframes pop-in {
  0% { opacity: 0; transform: scale(0.94); }
  100% { opacity: 1; transform: scale(1); }
}

.success-badge {
  display: inline-block;
  font-size: 13px;
  font-weight: 700;
  color: var(--ok-text);
  background: var(--ok-bg);
  border: 1px solid var(--ok-border);
  border-radius: 999px;
  padding: 5px 14px;
  margin-bottom: 14px;
}

.success-title {
  font-size: 30px;
  font-weight: 800;
  margin: 0 0 6px;
  letter-spacing: -0.02em;
}

.success-sub {
  color: var(--muted);
  font-size: 15px;
  margin: 0 0 22px;
}

/* The unlocked "resource" panel. */
.reward {
  background: #fff;
  border: 1px solid #e6def9;
  border-radius: 14px;
  padding: 24px;
  margin-bottom: 18px;
  box-shadow: inset 0 1px 0 #fff;
}

.reward-label {
  font-size: 12px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: #7c4dff;
  margin-bottom: 14px;
}

.meme {
  min-height: 150px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  margin-bottom: 16px;
}

.reward-title {
  font-size: 18px;
  font-weight: 800;
  margin-bottom: 4px;
}

.reward-blurb {
  font-size: 13px;
  color: var(--muted);
}

.success-meta {
  font-size: 12px;
  color: var(--muted);
  word-break: break-all;
  margin: 0 0 16px;
}

.success-signout {
  max-width: 260px;
  margin: 0 auto;
}

/* --- Meme: dancing potato (password) --- */
.meme-potato {
  position: relative;
}
.potato {
  position: relative;
  font-size: 72px;
  line-height: 1;
  animation: potato-dance 0.7s ease-in-out infinite;
  transform-origin: bottom center;
}
.potato-eye {
  position: absolute;
  top: 34px;
  width: 9px;
  height: 9px;
  background: #1f2328;
  border-radius: 50%;
  animation: potato-blink 2.4s infinite;
}
.potato-eye-l { left: 26px; }
.potato-eye-r { left: 44px; }
.potato-shadow {
  width: 70px;
  height: 12px;
  margin: 6px auto 0;
  background: rgba(0, 0, 0, 0.12);
  border-radius: 50%;
  animation: potato-shadow 0.7s ease-in-out infinite;
}
@keyframes potato-dance {
  0%, 100% { transform: rotate(-8deg) translateY(0); }
  50% { transform: rotate(8deg) translateY(-14px); }
}
@keyframes potato-shadow {
  0%, 100% { transform: scale(1); opacity: 0.6; }
  50% { transform: scale(0.7); opacity: 0.3; }
}
@keyframes potato-blink {
  0%, 92%, 100% { transform: scaleY(1); }
  96% { transform: scaleY(0.1); }
}

/* --- Meme: googly eyes (oauth) --- */
.meme-googly {
  display: flex;
  gap: 14px;
}
.eye {
  width: 62px;
  height: 62px;
  background: #fff;
  border: 3px solid #1f2328;
  border-radius: 50%;
  position: relative;
  overflow: hidden;
}
.pupil {
  position: absolute;
  width: 22px;
  height: 22px;
  background: #1f2328;
  border-radius: 50%;
  top: 30px;
  left: 20px;
  transform-origin: center -12px;
  animation: googly 1.1s ease-in-out infinite;
}
.eye:nth-child(2) .pupil { animation-delay: 0.15s; }
@keyframes googly {
  0% { transform: rotate(0deg); }
  25% { transform: rotate(140deg); }
  50% { transform: rotate(250deg); }
  75% { transform: rotate(360deg); }
  100% { transform: rotate(500deg); }
}

/* --- Meme: rickroll (wallet) — bundled GIF --- */
.meme-rickroll {
  position: relative;
  text-align: center;
}
.rick-gif {
  max-height: 200px;
  max-width: 100%;
  border-radius: 12px;
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.18);
}
.rick-caption {
  margin-top: 10px;
  font-size: 13px;
  font-weight: 700;
  color: #7c4dff;
  animation: caption-pulse 1s ease-in-out infinite;
}
@keyframes caption-pulse {
  0%, 100% { transform: scale(1); }
  50% { transform: scale(1.06); }
}

/* Respect reduced-motion preferences. */
@media (prefers-reduced-motion: reduce) {
  .potato, .potato-shadow, .pupil, .rick-caption,
  .success { animation: none; }
}

.brand {
  font-size: 20px;
  font-weight: 700;
  color: var(--accent);
  margin-bottom: 24px;
  letter-spacing: -0.01em;
}

.title {
  margin: 0 0 4px;
  font-size: 24px;
  font-weight: 600;
}

.subtitle {
  margin: 0 0 28px;
  color: var(--muted);
  font-size: 14px;
}

.form {
  display: flex;
  flex-direction: column;
}

.label {
  font-size: 13px;
  font-weight: 600;
  margin-bottom: 6px;
}

.input {
  width: 100%;
  padding: 11px 12px;
  font-size: 15px;
  border: 1px solid var(--border);
  border-radius: 8px;
  outline: none;
  transition: border-color 0.15s, box-shadow 0.15s;
}

.input:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px rgba(26, 115, 232, 0.15);
}

.error {
  color: var(--error);
  font-size: 13px;
  margin: 10px 0 0;
}

/* Discovery-document disclosure (relay step) */
.disclose {
  margin: 0 0 16px;
}

.disclose-toggle {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
  background: none;
  border: none;
  padding: 4px 0;
  cursor: pointer;
  font-family: inherit;
  font-size: 13px;
  font-weight: 600;
  color: var(--accent);
}

.disclose-caret {
  display: inline-block;
  transition: transform 0.15s ease;
  font-size: 11px;
}

.disclose-caret.open {
  transform: rotate(90deg);
}

.disclose-hint {
  margin-left: auto;
  font-weight: 400;
  font-size: 12px;
  color: var(--muted);
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
}

.disclose-json {
  margin: 10px 0 0;
  padding: 14px;
  background: #0f1117;
  color: #d6e2f5;
  border-radius: 8px;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12.5px;
  line-height: 1.5;
  overflow: auto;
  white-space: pre;
}

/* Step-by-step toggle (relay step) */
.stepwitch {
  display: flex;
  align-items: center;
  gap: 12px;
  margin: 0 0 20px;
  cursor: pointer;
  user-select: none;
}

.stepwitch input {
  position: absolute;
  opacity: 0;
  pointer-events: none;
}

.stepwitch-track {
  flex: none;
  width: 40px;
  height: 22px;
  border-radius: 999px;
  background: #cfd4dc;
  position: relative;
  transition: background 0.18s ease;
}

.stepwitch-thumb {
  position: absolute;
  top: 2px;
  left: 2px;
  width: 18px;
  height: 18px;
  border-radius: 50%;
  background: #fff;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.25);
  transition: transform 0.18s ease;
}

.stepwitch input:checked + .stepwitch-track {
  background: var(--accent);
}

.stepwitch input:checked + .stepwitch-track .stepwitch-thumb {
  transform: translateX(18px);
}

.stepwitch-label {
  font-size: 13px;
  font-weight: 600;
  color: #1f2328;
}

.stepwitch-hint {
  display: block;
  font-weight: 400;
  font-size: 12px;
  color: var(--muted);
}

/* Trust cue */
.trust {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 12px 14px;
  border-radius: 8px;
  background: #eaf6ec;
  border: 1px solid #b7e0bf;
  margin-bottom: 20px;
}

.trust-warn {
  background: #fdf3e7;
  border-color: #f2d3a2;
}

.trust-check {
  font-size: 16px;
  line-height: 1.4;
}

.trust-title {
  font-size: 13px;
  font-weight: 700;
  color: #1f2328;
}

.trust-detail {
  font-size: 13px;
  color: #4a5560;
  word-break: break-all;
}

.trust-src {
  color: var(--muted);
}

.wallet-block {
  margin-top: 8px;
  margin-bottom: 4px;
}

.wallet-heading {
  font-size: 13px;
  font-weight: 600;
  color: var(--muted);
  margin-bottom: 8px;
}

.button-wallet {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  margin-top: 0;
  margin-bottom: 8px;
  color: #fff;
  background: #6b3fd4;
}

.button-wallet:hover:not(:disabled) {
  background: #5a34b8;
}

.wallet-icon {
  font-size: 15px;
}

.wallet-sep {
  text-align: center;
  color: var(--muted);
  font-size: 12px;
  margin: 12px 0 4px;
}

.magic-url {
  font-size: 12px;
  color: var(--muted);
  word-break: break-all;
  margin: 10px 0 0;
  background: #f6f8fa;
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 8px 10px;
}

.button {
  margin-top: 20px;
  width: 100%;
  padding: 11px 12px;
  font-size: 15px;
  font-weight: 600;
  color: #fff;
  background: var(--accent);
  border: none;
  border-radius: 8px;
  cursor: pointer;
  transition: background 0.15s;
}

.button:hover:not(:disabled) {
  background: var(--accent-hover);
}

.button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.button-secondary {
  color: var(--accent);
  background: transparent;
  border: 1px solid var(--border);
}

.button-secondary:hover:not(:disabled) {
  background: #f6f8fa;
}

.button-google {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  color: #1f2328;
  background: #fff;
  border: 1px solid var(--border);
  text-decoration: none;
  box-sizing: border-box;
}

.button-google:hover:not(:disabled) {
  background: #f6f8fa;
}

.g-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 18px;
  height: 18px;
  border-radius: 50%;
  background: #fff;
  color: #4285f4;
  font-weight: 700;
  font-family: Arial, sans-serif;
}

.result-note {
  margin: 0 0 8px;
  color: var(--muted);
  font-size: 13px;
}

.result-meta {
  margin: 0 0 8px;
  color: var(--muted);
  font-size: 12px;
  word-break: break-all;
}
</style>
