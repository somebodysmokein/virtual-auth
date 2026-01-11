import * as Linking from 'expo-linking'
import * as WebBrowser from 'expo-web-browser'
import React, { useState } from 'react'
import { Alert, Button, Platform, StyleSheet, Text, TextInput, View } from 'react-native'

type VerifyResult = any

interface YubiKeyAuthProps {
  initialUsername?: string
  initialPassword?: string
  requireRegistration?: boolean // if true, run registration flow; otherwise run authentication
  serverUrl?: string // optional base URL for the WebAuthn server (e.g. http://localhost:4000). If omitted, uses current origin.
  onSuccess?: (result: VerifyResult) => void
  onError?: (err: Error | string) => void
}

// Helpers to convert ArrayBuffers to/from base64url (WebAuthn compatible)
function bufferToBase64Url(buffer: ArrayBuffer) {
  const bytes = new Uint8Array(buffer)
  let str = ''
  for (let i = 0; i < bytes.byteLength; i++) str += String.fromCharCode(bytes[i])
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function base64UrlToBuffer(base64url: string) {
  if (typeof base64url !== 'string') throw new Error('base64UrlToBuffer expected a string')
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/') + '=='.slice((2 - base64url.length * 3) & 3)
  const str = atob(base64)
  const bytes = new Uint8Array(str.length)
  for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i)
  return bytes.buffer
}

function toArrayBufferMaybe(value: any) {
  if (!value) return null
  if (typeof value === 'string') return base64UrlToBuffer(value)
  if (value instanceof ArrayBuffer) return value
  // TypedArray or BufferSource
  if (ArrayBuffer.isView(value)) return value.buffer
  try {
    return base64UrlToBuffer(String(value))
  } catch (_) {
    return null
  }
}

export default function YubiKeyAuth(props: YubiKeyAuthProps) {
  const [username, setUsername] = useState(props.initialUsername ?? '')
  const [password, setPassword] = useState(props.initialPassword ?? '')
  const [status, setStatus] = useState<string | null>(null)
  const [allowIds, setAllowIds] = useState<string[] | null>(null)

  const notifyError = (e: any) => {
    const msg = e instanceof Error ? e.message : String(e)
    setStatus(msg)
    props.onError?.(e)
  }

  async function fetchJson(path: string, body: any) {
    const base = props.serverUrl ? props.serverUrl.replace(/\/$/, '') : ''
    const url = `${base}${path}`
    const res = await fetch(url, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body),
    })
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`)
    return res.json()
  }

  // This function runs either the registration or authentication WebAuthn flow.
  async function handleMfa() {
    setStatus(null)

    if (Platform.OS !== 'web' && typeof navigator === 'undefined') {
      Alert.alert('YubiKey MFA', 'WebAuthn flows require a Web environment (web) or a native integration. Follow the README notes.')
      return
    }

    try {
      if (props.requireRegistration) {
        setStatus('Getting registration options from server...')
        // Server should return PublicKeyCredentialCreationOptions where binary fields are base64url strings
        const options = await fetchJson('/webauthn/register/options', {username, displayName: username})

        // Convert challenge and user.id from base64url to ArrayBuffer (or leave if already ArrayBuffer)
        const challengeBuf = toArrayBufferMaybe(options.publicKey.challenge)
        if (!challengeBuf) {
          notifyError('Server did not return a valid registration challenge')
          return
        }
        options.publicKey.challenge = challengeBuf

        const userIdBuf = toArrayBufferMaybe(options.publicKey.user?.id)
        if (!userIdBuf) {
          notifyError('Server did not return a valid user.id for registration')
          return
        }
        options.publicKey.user.id = userIdBuf

        if (options.publicKey.excludeCredentials) {
          for (const cred of options.publicKey.excludeCredentials) {
            const idBuf = toArrayBufferMaybe(cred.id)
            if (idBuf) cred.id = idBuf
          }
        }

        setStatus('Creating credential with authenticator (touch your YubiKey)...')
        // @ts-ignore - navigator.credentials may exist on web builds
        const credential: any = await navigator.credentials.create({publicKey: options.publicKey})

        // Prepare credential response to send back to server
        const attResponse = credential.response
        const toSend = {
          id: credential.id,
          rawId: bufferToBase64Url(credential.rawId),
          response: {
            attestationObject: bufferToBase64Url(attResponse.attestationObject),
            clientDataJSON: bufferToBase64Url(attResponse.clientDataJSON),
          },
          type: credential.type,
        }

        setStatus('Verifying registration with server...')
        const verified = await fetchJson('/webauthn/register/verify', {username, credential: toSend})
        setStatus('Registration complete')
        props.onSuccess?.(verified)
      } else {
        setStatus('Getting authentication options from server...')
        // Server returns PublicKeyCredentialRequestOptions (binary fields as base64url strings)
        const options = await fetchJson('/webauthn/authn/options', {username})
        const authnChallenge = toArrayBufferMaybe(options.publicKey.challenge)
        if (!authnChallenge) {
          notifyError('Server did not return a valid authentication challenge')
          return
        }
        options.publicKey.challenge = authnChallenge
        if (options.publicKey.allowCredentials) {
          for (const cred of options.publicKey.allowCredentials) {
            const idBuf = toArrayBufferMaybe(cred.id)
            if (idBuf) cred.id = idBuf
          }
        }

        // Show allowCredentials ids in the UI for debugging (re-encoded to base64url)
        const reencoded = options.publicKey.allowCredentials?.map((c: any) => {
          try { return bufferToBase64Url(toArrayBufferMaybe(c.id) as ArrayBuffer) } catch (e) { return String(c.id) }
        })
        console.log('Authn allowCredentials ids (re-encoded):', reencoded)
        setAllowIds(reencoded || null)

        setStatus('Requesting assertion from authenticator (touch your YubiKey)...')
        // @ts-ignore
        const assertion: any = await navigator.credentials.get({publicKey: options.publicKey})

        const authResp = assertion.response
        const toSend = {
          id: assertion.id,
          rawId: bufferToBase64Url(assertion.rawId),
          response: {
            authenticatorData: bufferToBase64Url(authResp.authenticatorData),
            clientDataJSON: bufferToBase64Url(authResp.clientDataJSON),
            signature: bufferToBase64Url(authResp.signature),
            userHandle: authResp.userHandle ? bufferToBase64Url(authResp.userHandle) : null,
          },
          type: assertion.type,
        }

        setStatus('Verifying assertion with server...')
        const verified = await fetchJson('/webauthn/authn/verify', {username, credential: toSend})
        setStatus('Authentication successful')
        props.onSuccess?.(verified)
      }
    } catch (e) {
      notifyError(e)
    }
  }

  // Open the web fallback in system browser and listen for deep link redirect
  async function openWebFallback(mode: 'authn' | 'register') {
    const base = props.serverUrl ? props.serverUrl.replace(/\/$/, '') : ''
    const scheme = 'coinbase-virtual-auth'
    const redirect = `${scheme}://webauthn` // app will receive this
    const url = `${base}/webauthn.html?mode=${mode}&username=${encodeURIComponent(username)}&redirect=${encodeURIComponent(redirect)}`

    setStatus('Opening system browser for WebAuthn...')

    const subscription = Linking.addEventListener('url', (event) => {
      try {
        const u = new URL(event.url)
        const result = u.searchParams.get('result')
        if (result) {
          const obj = JSON.parse(decodeURIComponent(result))
          if (obj.result && obj.result.verified) setStatus('Authentication verified (web fallback)')
          else if (obj.result) setStatus('Web fallback result: ' + JSON.stringify(obj.result))
          else if (obj.error) setStatus('Web fallback error: ' + obj.error)
        }
      } catch (e) {
        setStatus(String(e))
      } finally {
        WebBrowser.dismissBrowser()
        try { subscription.remove() } catch (_) {}
      }
    })

    await WebBrowser.openBrowserAsync(url)

    // Start polling the server for a posted result as a fallback when the automatic deep-link is blocked
    let stopped = false
    const pollInterval = 1000
    const maxAttempts = 30 // ~30s timeout
    let attempts = 0

    const poll = async () => {
      attempts += 1
      try {
        const res = await fetch(base + `/webauthn/result/${encodeURIComponent(username)}`)
        if (res.ok) {
          const j = await res.json()
          if (j && j.result) {
            stopped = true
            try { WebBrowser.dismissBrowser() } catch (_) {}
            try { subscription.remove() } catch (_) {}
            const obj = j.result
            if (obj.verified) setStatus('Authentication verified (web fallback)')
            else setStatus('Web fallback result: ' + JSON.stringify(obj))
            props.onSuccess?.(obj)
            return
          }
        }
      } catch (e) {
        // ignore transient fetch errors while polling
      }
      if (!stopped && attempts < maxAttempts) setTimeout(poll, pollInterval)
      if (attempts >= maxAttempts && !stopped) {
        try { subscription.remove() } catch (_) {}
        setStatus('Timed out waiting for web-fallback result')
      }
    }

    poll()
  }

  return (
    <View style={styles.container}>
      <Text style={styles.label}>Username</Text>
      <TextInput style={styles.input} value={username} onChangeText={setUsername} autoCapitalize="none" />
      <Text style={styles.label}>Password</Text>
      <TextInput style={styles.input} value={password} onChangeText={setPassword} secureTextEntry />

      <View style={styles.button}>
        <Button title={props.requireRegistration ? 'Register YubiKey' : 'Authenticate with YubiKey'} onPress={handleMfa} />
      </View>

      <View style={styles.button}>
        <Button title={props.requireRegistration ? 'Register (web fallback)' : 'Authenticate (web fallback)'} onPress={() => openWebFallback(props.requireRegistration ? 'register' : 'authn')} />
      </View>

      {status ? <Text style={styles.status}>{status}</Text> : null}
      {allowIds ? <Text style={styles.status}>AllowCredentials: {allowIds.join(', ')}</Text> : null}

      <Text style={styles.hint}>
        Note: This component expects server endpoints to provide and verify WebAuthn options. See README comments in this file for integration.
      </Text>
    </View>
  )
}

const styles = StyleSheet.create({
  container: {padding: 12},
  label: {fontSize: 14, marginTop: 8},
  input: {borderWidth: 1, borderColor: '#ccc', padding: 8, marginTop: 4, borderRadius: 6},
  button: {marginTop: 12},
  status: {marginTop: 12, color: '#333'},
  hint: {marginTop: 10, color: '#666', fontSize: 12},
})

/*
Usage and server notes:
- This component implements the client-side WebAuthn flow and expects the server to provide JSON endpoints:
  - POST /webauthn/register/options  -> returns PublicKeyCredentialCreationOptions (binary fields as base64url strings)
  - POST /webauthn/register/verify   -> accepts credential response, verifies attestation, stores credential
  - POST /webauthn/authn/options      -> returns PublicKeyCredentialRequestOptions (binary fields as base64url strings)
  - POST /webauthn/authn/verify       -> accepts assertion response, verifies signature and user

Example server libs: `@simplewebauthn/server` (Node), `webauthn` libraries in other languages.
If you want, I can add example server stubs or integrate `@simplewebauthn/browser` for nicer client helpers.
*/
