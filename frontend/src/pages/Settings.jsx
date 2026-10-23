import { useEffect, useState } from 'react'
import { api } from '../api/client'
import { useAuth } from '../hooks/useAuth'
import { useModal } from '../components/Modal'
import { useToast } from '../components/Toast'

export default function Settings({ refreshKey }) {
  const { me, setMe, logout } = useAuth()

  useEffect(() => {
    api.get('/api/auth/me').then(setMe)
  }, [refreshKey, setMe])

  if (!me) return <div className="empty" style={{ padding: 40 }}>Loading…</div>

  return (
    <>
      <div className="page-header">
        <div className="page-title">Settings</div>
        <div className="page-sub">Your account, security, team, and API access.</div>
      </div>

      <div className="s-section">
        <div className="s-head">Account</div>
        <div className="s-sub">Your account details.</div>
        <div className="panel"><div className="panel-body">
          <div className="grid-2">
            <div className="input-group"><label className="input-label">Name</label><input className="input" value={me.name || ''} readOnly /></div>
            <div className="input-group"><label className="input-label">Email</label><input className="input" value={me.email || ''} readOnly /></div>
          </div>
        </div></div>
      </div>

      <MfaSection me={me} onChanged={() => api.get('/api/auth/me').then(setMe)} />
      <TeamSection role={me.role || 'owner'} />

      <div className="s-section">
        <div className="s-head">API</div>
        <div className="s-sub">Manage CrawlBouncer programmatically.</div>
        <div className="panel"><div className="panel-body" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ fontSize: 12.5, color: 'var(--t2)' }}>Interactive API documentation with all endpoints, schemas, and examples.</div>
          <a href="/api/docs" target="_blank" rel="noreferrer" className="btn btn-outline">Open API docs</a>
        </div></div>
      </div>

      <DangerZone me={me} onDeleted={logout} />
    </>
  )
}

function MfaSection({ me, onChanged }) {
  const { showModal, closeModal } = useModal()
  const notify = useToast()

  async function openEnrollMfa() {
    let res
    try {
      res = await api.post('/api/auth/mfa/enroll', {})
    } catch (e) {
      return notify(e.message || 'Could not start 2FA enrollment')
    }
    if (!res?.secret) return notify('Could not start 2FA enrollment')

    showModal('Enable two-factor authentication', <EnrollBody secret={res.secret} />, [
      { label: 'Cancel', cls: 'btn-outline', fn: closeModal },
      { label: 'Confirm', cls: 'btn-default', fn: async () => {
        const code = document.getElementById('mfa-code').value.trim()
        try {
          await api.post('/api/auth/mfa/confirm', { code })
          closeModal(); notify('Two-factor authentication enabled'); onChanged()
        } catch (e) { notify(e.message || 'Invalid code') }
      }},
    ])
  }

  if (me.role !== 'owner') {
    // mfa_secret/mfa_enabled live on the owner's account row — a
    // member has no MFA of their own to manage here (backend enforces
    // this via require_owner; hiding it here avoids showing a member
    // a toggle for a login that isn't theirs and that they'd just get
    // a 403 clicking anyway).
    return (
      <div className="s-section">
        <div className="s-head">Security</div>
        <div className="s-sub">Two-factor authentication is managed by the account owner.</div>
      </div>
    )
  }

  return (
    <div className="s-section">
      <div className="s-head">Security</div>
      <div className="s-sub">Two-factor authentication for your login. Recommended: this account controls what reaches your sites.</div>
      <div className="panel"><div className="panel-body">
        {me.mfa_enabled ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span className="badge b-green">Enabled</span>
            <span style={{ fontSize: 12, color: 'var(--t2)' }}>Codes are required every time you log in.</span>
          </div>
        ) : (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span className="badge b-neutral">Not enabled</span>
              <span style={{ fontSize: 12, color: 'var(--t2)' }}>Add an authenticator app for a second login step.</span>
            </div>
            <button className="btn btn-default" onClick={openEnrollMfa}>Enable 2FA</button>
          </div>
        )}
      </div></div>
    </div>
  )
}

function EnrollBody({ secret }) {
  const notify = useToast()
  return (
    <>
      <p style={{ fontSize: 12.5, color: 'var(--t2)', marginBottom: 14 }}>Add this to an authenticator app (1Password, Authy, Google Authenticator), then enter the 6-digit code it shows.</p>
      <div className="dns-row">
        <div className="dns-row-inner">
          <div className="dns-step-num">1</div>
          <div style={{ flex: 1 }}>
            <div className="dns-label">Secret key</div>
            <div className="dns-hint" style={{ marginBottom: 6 }}>Add manually, or scan the code your authenticator app provides for this string.</div>
            <div className="dns-block">
              <span className="mono">{secret}</span>
              <button className="copy-btn" onClick={() => { navigator.clipboard.writeText(secret); notify('Copied') }}>Copy</button>
            </div>
          </div>
        </div>
      </div>
      <div className="input-group" style={{ marginTop: 14 }}>
        <label className="input-label">6-digit code</label>
        <input className="input mono" id="mfa-code" placeholder="000000" maxLength={6} autoComplete="one-time-code" />
      </div>
    </>
  )
}

function TeamSection({ role }) {
  const [team, setTeam] = useState(null)
  const { showModal, closeModal } = useModal()
  const notify = useToast()
  const isOwner = role === 'owner'

  const load = () => api.get('/api/team/').then((t) => setTeam(t || { owner: null, members: [] }))
  useEffect(() => { load() }, [])

  function openInviteMember() {
    showModal('Invite a team member', <InviteBody />, [
      { label: 'Cancel', cls: 'btn-outline', fn: closeModal },
      { label: 'Send invite', cls: 'btn-default', fn: async () => {
        const email = document.getElementById('invite-email').value.trim()
        if (!email) return notify('Enter an email address')
        try {
          await api.post('/api/team/invite', { email })
          closeModal(); notify(`Invite sent to ${email}`); load()
        } catch (e) { notify(e.message || 'Failed') }
      }},
    ])
  }

  function removeMember(id, email) {
    showModal('Remove team member', <p style={{ fontSize: 12.5, color: 'var(--t2)' }}>This immediately ends <strong>{email}</strong>'s access — any session they have open stops working right away.</p>, [
      { label: 'Cancel', cls: 'btn-outline', fn: closeModal },
      { label: 'Remove', cls: 'btn-danger', fn: async () => {
        try {
          await api.del(`/api/team/${id}`)
          closeModal(); notify(`${email} removed`); load()
        } catch (e) { notify(e.message || 'Failed') }
      }},
    ])
  }

  return (
    <div className="s-section">
      <div className="s-head">Team</div>
      <div className="s-sub">People who can log in and manage this account. {isOwner ? 'Members get everything you can do except inviting and removing people.' : "You're a team member — everything except inviting others."}</div>
      <div className="panel"><div className="panel-body">
        {team === null ? <div className="empty-sub">Loading…</div> : (
          <>
            <div className="tbl-wrap">
              <table>
                <thead><tr><th>Person</th><th>Role</th><th>Status</th>{isOwner && <th></th>}</tr></thead>
                <tbody>
                  {team.owner && (
                    <tr>
                      <td className="t1">{team.owner.name || team.owner.email}</td>
                      <td><span className="badge b-neutral">Owner</span></td>
                      <td><span className="badge b-green">Active</span></td>
                      {isOwner && <td></td>}
                    </tr>
                  )}
                  {team.members.map((m) => (
                    <tr key={m.id}>
                      <td className="mono t1">{m.email}</td>
                      <td><span className="badge b-neutral">Member</span></td>
                      <td>{m.status === 'active' ? <span className="badge b-green">Active</span> : <span className="badge b-neutral">Invited</span>}</td>
                      {isOwner && <td style={{ textAlign: 'right' }}><button className="btn btn-ghost" style={{ fontSize: 11.5, color: 'var(--red)' }} onClick={() => removeMember(m.id, m.email)}>Remove</button></td>}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {isOwner && <div style={{ marginTop: 12 }}><button className="btn btn-outline" onClick={openInviteMember}>Invite someone</button></div>}
          </>
        )}
      </div></div>
    </div>
  )
}

function InviteBody() {
  return (
    <div className="input-group">
      <label className="input-label">Email</label>
      <input className="input" id="invite-email" type="email" placeholder="teammate@example.com" />
      <div className="input-hint">They'll get an email with a link to set their own password. They can do everything you can except inviting and removing people.</div>
    </div>
  )
}

function DangerZone({ me, onDeleted }) {
  const { showModal, closeModal } = useModal()
  const notify = useToast()
  const isOwner = me.role === 'owner'

  function step1() {
    showModal('Delete account', (
      <>
        <p style={{ fontSize: 12.5, color: 'var(--t2)', marginBottom: 12 }}>Before you continue, here's exactly what happens:</p>
        <ul style={{ fontSize: 12.5, color: 'var(--t2)', paddingLeft: 18, lineHeight: 1.7 }}>
          <li>You and your entire team lose access immediately — everyone's logged out</li>
          <li>Every protected domain stops being served and protected right away</li>
          <li>The audit log is kept — it isn't erased</li>
          <li>This cannot be undone</li>
        </ul>
      </>
    ), [
      { label: 'Cancel', cls: 'btn-outline', fn: closeModal },
      { label: 'I understand, continue', cls: 'btn-outline', fn: step2 },
    ])
  }

  function step2() {
    showModal('Confirm your email', (
      <>
        <p style={{ fontSize: 12.5, color: 'var(--t2)', marginBottom: 12 }}>Type <strong className="mono">{me.email}</strong> to confirm you want to delete this account.</p>
        <div className="input-group">
          <input className="input mono" id="delete-email-confirm" placeholder={me.email} autoComplete="off" />
        </div>
      </>
    ), [
      { label: 'Cancel', cls: 'btn-outline', fn: closeModal },
      { label: 'Continue', cls: 'btn-outline', fn: () => {
        const typed = document.getElementById('delete-email-confirm').value.trim()
        if (typed !== me.email) return notify("That doesn't match your account email")
        step3()
      }},
    ])
  }

  function step3() {
    showModal('Delete account', (
      <>
        <p style={{ fontSize: 12.5, color: 'var(--t2)', marginBottom: 14 }}>Last step. Enter your password to permanently delete this account.</p>
        <div className="input-group">
          <label className="input-label">Password</label>
          <input className="input" id="delete-account-password" type="password" placeholder="••••••••" />
        </div>
      </>
    ), [
      { label: 'Cancel', cls: 'btn-outline', fn: closeModal },
      { label: 'Permanently delete', cls: 'btn-danger', fn: async () => {
        const password = document.getElementById('delete-account-password').value
        if (!password) return notify('Enter your password to confirm')
        try {
          await api.del('/api/auth/account', { password })
          onDeleted()
        } catch (e) { notify(e.message || 'Failed — check your password') }
      }},
    ])
  }

  return (
    <div className="s-section">
      <div className="s-head" style={{ color: 'var(--red)' }}>Danger zone</div>
      <div className="s-sub">Irreversible actions.</div>
      <div className="panel" style={{ borderColor: 'var(--border)' }}><div className="panel-body" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <div style={{ fontSize: 13, fontWeight: 500 }}>Delete account</div>
          <div style={{ fontSize: 12, color: 'var(--t2)', marginTop: 2 }}>Ends access for you and your team, stops protecting your domains, and can't be undone. The audit log is kept.</div>
        </div>
        {isOwner
          ? <button className="btn btn-danger" onClick={step1}>Delete account</button>
          : <span style={{ fontSize: 12, color: 'var(--t3)' }}>Only the account owner can do this</span>}
      </div></div>
    </div>
  )
}
