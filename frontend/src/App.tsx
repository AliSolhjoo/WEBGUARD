import { useCallback, useEffect, useState } from 'react'
import type { FormEvent, ReactNode, ChangeEvent, CSSProperties } from 'react'
import { I18nProvider, useI18n } from './i18n'
import {
  Activity, AlertTriangle, ArrowDownRight, ArrowRight, ArrowUpRight, Bell, CheckCircle2,
  ChevronDown, CircleHelp, ClipboardCheck, Clock3, Cloud, Download, FileBarChart2, Fingerprint,
  Globe2, LayoutDashboard, LockKeyhole, LogOut, Plus, Radar, RefreshCw, Search, Server,
  Settings2, Shield, ShieldAlert, ShieldCheck, ShieldHalf, Sparkles, Target, Users, X, Menu,
  Palette, Monitor, Type, PanelRight, ChevronUp, Upload, RotateCcw, Check
} from 'lucide-react'
import { api, clearTokens, downloadReport, hasSession, revokeServerSession, saveTokens } from './lib/api'
import { DEFAULT_PREFERENCES, loadPreferences, normalizePreferences, parsePreferencesJson, persistPreferences, serializePreferences } from './preferences'
import type { DashboardWidget, NavigationItem, UserPreferences } from './preferences'

type Page = 'overview' | 'assets' | 'scans' | 'findings' | 'insights' | 'assistant' | 'reports' | 'team' | 'audit' | 'settings'
type Me = { id: number; email: string; full_name: string; organization: { id: number; name: string; slug: string; role: string } | null }
type Asset = { id: number; domain: string; status: 'pending' | 'verified' | 'suspended'; created_at: string; verified_at: string | null; last_scanned_at: string | null }
type Scan = { id: number; asset: number; asset_domain: string; status: string; created_at: string; started_at: string | null; finished_at: string | null; total_checks: number; passed_checks: number; failed_checks: number; info_checks: number; error_message: string; checks?: Check[] }
type Check = { id: number; check_id: string; name: string; category: string; status: string; severity: string; description: string; recommendation: string; evidence: Record<string, unknown> }
type Finding = { id: number; check_id: string; title: string; category: string; severity: string; description: string; recommendation: string; evidence: Record<string, unknown>; asset_domain: string; scan_id: number; status: string; notes: string; assigned_to: number | null; assigned_to_email: string | null; created_at: string }
type Report = { id: number; scan_id: number; domain: string; language: 'en' | 'fa'; created_at: string; download_url: string }
type Overview = { asset_count: number; verified_asset_count: number; scan_count: number; active_scans: number; open_findings: number; severity: Record<string, number>; security_score: number | null; score_method: string; recent_scans: Scan[] }
type Member = { id: number; user_id: number; email: string; full_name: string; role: string; joined_at: string }
type Notification = { id: number; level: string; title: string; message: string; href: string; metadata: Record<string, unknown>; read_at: string | null; created_at: string }
type NotificationPayload = { unread_count: number; results: Notification[] }
type Trends = { daily_scans: { date: string; scans: number; completed: number; failed: number }[]; score_history: { scan_id: number; date: string; domain: string; score: number }[]; open_findings_by_severity: Record<string, number>; period_days: number }
type AssistantResult = { engine: string; mode: string; language: string; finding_id: number; check_id: string; asset_domain: string; title: string; severity: string; priority: string; status: string; summary: string; business_impact: string; remediation_steps: string[]; validation_criteria: string; evidence: Record<string, unknown>; limitations: string }
type ScanComparison = { has_baseline: boolean; current_scan_id: number; current_score: number; previous_scan_id: number | null; previous_score?: number; score_change?: number; new_findings: string[]; resolved_findings: string[]; persistent_findings: string[] }
type Audit = { id: number; actor: string; action: string; object_type: string; object_id: string; metadata: Record<string, unknown>; created_at: string }
type Verification = { asset_id: number; domain: string; status: string; record_name: string; record_type: string; expected_value: string; verified_at: string | null }

const navigation: { key: Page; label: string; icon: typeof LayoutDashboard; group: string }[] = [
  { key: 'overview', label: 'Overview', icon: LayoutDashboard, group: 'Workspace' },
  { key: 'assets', label: 'Assets', icon: Globe2, group: 'Workspace' },
  { key: 'scans', label: 'Assessments', icon: Radar, group: 'Workspace' },
  { key: 'findings', label: 'Findings', icon: ShieldAlert, group: 'Security' },
  { key: 'insights', label: 'Security insights', icon: Activity, group: 'Security' },
  { key: 'assistant', label: 'Security assistant', icon: Sparkles, group: 'Security' },
  { key: 'reports', label: 'Reports', icon: FileBarChart2, group: 'Security' },
  { key: 'team', label: 'Team & access', icon: Users, group: 'Administration' },
  { key: 'audit', label: 'Audit trail', icon: ClipboardCheck, group: 'Administration' },
  { key: 'settings', label: 'Personalization studio', icon: Palette, group: 'Personalization' },
]

function formatDate(value?: string | null) {
  if (!value) return '—'
  const date = new Date(value)
  const locale = document.documentElement.lang === 'fa' ? 'fa-IR' : 'en-US'
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString(locale, { dateStyle: 'medium', timeStyle: 'short' })
}
function notificationMessage(item: Notification, language: 'en' | 'fa') {
  if (language !== 'fa') return item.message
  const scanId = String(item.metadata.scan_id ?? '')
  const domain = String(item.metadata.domain ?? '')
  const failed = Number(item.metadata.failed_checks ?? 0)
  const high = Number(item.metadata.high_critical_findings ?? 0)
  if (item.title === 'Assessment completed') return `اسکن شماره ${scanId} برای ${domain} تکمیل شد؛ ${failed} بررسی ناموفق و ${high} یافته با شدت زیاد یا بحرانی ثبت شد.`
  if (item.title === 'Assessment blocked') return `اسکن شماره ${scanId} به‌دلیل سیاست ایمنی هدف مسدود شد.`
  if (item.title === 'Assessment failed') return `اسکن شماره ${scanId} با خطا متوقف شد. وضعیت اسکن را بررسی و در صورت رفع مشکل دوباره تلاش کنید.`
  return item.message
}
function formatDay(value: string) {
  const date = new Date(`${value}T12:00:00`)
  const locale = document.documentElement.lang === 'fa' ? 'fa-IR' : 'en-US'
  return Number.isNaN(date.getTime()) ? value : date.toLocaleDateString(locale, { month: 'short', day: 'numeric' })
}
function initials(value: string) { return value.split(/[ @._-]/).filter(Boolean).slice(0, 2).map(x => x[0].toUpperCase()).join('') || 'WG' }
function severityClass(value: string) { return `severity severity-${value.toLowerCase()}` }
function statusClass(value: string) { return `status status-${value.toLowerCase().replaceAll('_', '-')}` }

export default function App() {
  return <I18nProvider><AppContent /></I18nProvider>
}

function AppContent() {
  const { language, t } = useI18n()
  const [authenticated, setAuthenticated] = useState(hasSession())
  const [me, setMe] = useState<Me | null>(null)
  const [page, setPage] = useState<Page>('overview')
  const [overview, setOverview] = useState<Overview | null>(null)
  const [assets, setAssets] = useState<Asset[]>([])
  const [scans, setScans] = useState<Scan[]>([])
  const [findings, setFindings] = useState<Finding[]>([])
  const [reports, setReports] = useState<Report[]>([])
  const [members, setMembers] = useState<Member[]>([])
  const [audit, setAudit] = useState<Audit[]>([])
  const [notificationPayload, setNotificationPayload] = useState<NotificationPayload>({ unread_count: 0, results: [] })
  const [trends, setTrends] = useState<Trends>({ daily_scans: [], score_history: [], open_findings_by_severity: {}, period_days: 30 })
  const [notificationOpen, setNotificationOpen] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [verifyAsset, setVerifyAsset] = useState<Verification | null>(null)
  const [verificationError, setVerificationError] = useState('')
  const [busyId, setBusyId] = useState<number | null>(null)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [preferences, setPreferences] = useState<UserPreferences>(loadPreferences)
  const [preferencesUserId, setPreferencesUserId] = useState<number | null>(null)

  const updatePreferences = (changes: Partial<UserPreferences>) => {
    setPreferences(current => normalizePreferences({ ...current, ...changes }))
  }

  useEffect(() => {
    if (me) {
      setPreferences(loadPreferences(me.id))
      setPreferencesUserId(me.id)
    } else {
      setPreferencesUserId(null)
    }
  }, [me?.id])

  useEffect(() => {
    if (me && preferencesUserId === me.id) persistPreferences(preferences, me.id)
    const root = document.documentElement
    root.dataset.theme = preferences.theme
    root.dataset.accent = preferences.accent
    root.dataset.density = preferences.density
    root.dataset.font = preferences.font
    root.dataset.fontSize = preferences.fontSize
    root.dataset.corners = preferences.corners
    root.dataset.sidebar = preferences.sidebar
    root.dataset.contentWidth = preferences.contentWidth
    root.dataset.reduceMotion = String(preferences.reduceMotion)
    const fontFamily = preferences.font === 'tahoma'
      ? 'Tahoma, Arial, sans-serif'
      : preferences.font === 'segoe'
        ? '"Segoe UI Variable", "Segoe UI", sans-serif'
        : 'Inter, system-ui, sans-serif'
    root.style.setProperty('--wg-font-family', fontFamily)
    root.style.setProperty('--wg-font-scale', preferences.fontSize === 'small' ? '0.94' : preferences.fontSize === 'large' ? '1.08' : '1')
  }, [preferences, me?.id, preferencesUserId])

  const loadData = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true)
    setError('')
    const jobs = [
      api<Overview>('/dashboard/overview/'), api<Asset[]>('/assets/'), api<Scan[]>('/scans/'),
      api<Finding[]>('/findings/'), api<Report[]>('/reports/'), api<Member[]>('/organization/members/'),
      api<Audit[]>('/audit-logs/'), api<NotificationPayload>('/notifications/'), api<Trends>('/dashboard/trends/')
    ]
    const results = await Promise.allSettled(jobs)
    const setters = [setOverview, setAssets, setScans, setFindings, setReports, setMembers, setAudit, setNotificationPayload, setTrends] as const
    let firstFailure = ''
    results.forEach((result, index) => {
      if (result.status === 'fulfilled') setters[index](result.value as never)
      else if (index !== 6 && !firstFailure) firstFailure = result.reason instanceof Error ? result.reason.message : t('Unable to load workspace data.')
    })
    if (firstFailure) { setError(firstFailure); if (!hasSession()) { setMe(null); setAuthenticated(false) } }
    if (!quiet) setLoading(false)
  }, [])

  const loadMe = useCallback(async () => {
    try {
      const user = await api<Me>('/auth/me/')
      setMe(user)
      setAuthenticated(true)
    } catch {
      clearTokens()
      setAuthenticated(false)
    }
  }, [])

  useEffect(() => { if (authenticated) void loadMe() }, [authenticated, loadMe])
  useEffect(() => { if (authenticated && me) void loadData() }, [authenticated, me, loadData])
  useEffect(() => {
    if (!authenticated || !scans.some(s => ['pending', 'running'].includes(s.status))) return
    const timer = window.setInterval(() => void loadData(true), 7000)
    return () => window.clearInterval(timer)
  }, [authenticated, scans, loadData])
  useEffect(() => {
    if (!mobileOpen) return
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === 'Escape') setMobileOpen(false) }
    window.addEventListener('keydown', closeOnEscape)
    return () => window.removeEventListener('keydown', closeOnEscape)
  }, [mobileOpen])

  const logout = async () => { try { await revokeServerSession() } catch { /* local session is still cleared if server revocation is unavailable */ } finally { clearTokens(); setMe(null); setPreferencesUserId(null); setPreferences(normalizePreferences(DEFAULT_PREFERENCES)); setAuthenticated(false); setOverview(null); setAssets([]); setScans([]); setFindings([]); setReports([]) } }
  const notify = (message: string) => { setNotice(message); window.setTimeout(() => setNotice(''), 4200) }
  async function safely(action: () => Promise<unknown>): Promise<void> {
    try { await action() }
    catch (err) { setError(err instanceof Error ? err.message : t('The requested action could not be completed.')) }
  }

  async function handleLogin(email: string, password: string, mode: 'login' | 'register', fullName = '', organizationName = '') {
    const result = mode === 'login'
      ? await api<{ access: string; refresh: string }>('/auth/login/', { method: 'POST', body: JSON.stringify({ email, password }) })
      : await api<{ access: string; refresh: string }>('/auth/register/', { method: 'POST', body: JSON.stringify({ email, password, full_name: fullName, organization_name: organizationName }) })
    saveTokens(result)
    setAuthenticated(true)
  }

  async function addAsset(domain: string) {
    setVerificationError('')
    const asset = await api<Asset>('/assets/', { method: 'POST', body: JSON.stringify({ domain }) })
    const verification = await api<Verification>(`/assets/${asset.id}/verification/`)
    setVerifyAsset(verification)
    await loadData(true)
    notify(t('Asset added. Publish the DNS TXT challenge to verify ownership.'))
  }
  async function refreshVerification(assetId: number) {
    setVerificationError('')
    const verification = await api<Verification>(`/assets/${assetId}/verification/`)
    setVerifyAsset(verification)
  }
  async function verifyAssetNow() {
    if (!verifyAsset) return
    setBusyId(verifyAsset.asset_id)
    setVerificationError('')
    try {
      const result = await api<{ status?: string }>(`/assets/${verifyAsset.asset_id}/verification/`, { method: 'POST', body: JSON.stringify({}) })
      if (result.status !== 'verified') throw new Error(t('Verification failed. Correct the DNS record and try again.'))
      setVerifyAsset(null)
      setVerificationError('')
      await loadData(true)
      notify(t('Domain ownership verified. Passive assessments are now enabled.'))
    } catch (err) {
      setVerificationError(err instanceof Error ? t(err.message) : t('Verification failed. Correct the DNS record and try again.'))
    } finally { setBusyId(null) }
  }
  async function startScan(assetId: number) {
    setBusyId(assetId)
    try {
      await api('/scans/', { method: 'POST', body: JSON.stringify({ asset: assetId, profile: 'passive' }) })
      await loadData(true)
      notify(t('Assessment queued. Keep the worker terminal running to process it.'))
      setPage('scans')
    } finally { setBusyId(null) }
  }
  async function cancelScan(scanId: number) {
    await api(`/scans/${scanId}/`, { method: 'POST', body: JSON.stringify({ action: 'cancel' }) })
    await loadData(true)
    notify(`${t('Assessment #')}${scanId} ${t('cancelled.')}`)
  }
  async function updateFinding(finding: Finding, changes: Partial<Pick<Finding, 'status' | 'notes' | 'assigned_to'>>) {
    await api(`/findings/${finding.id}/`, { method: 'PATCH', body: JSON.stringify(changes) })
    await loadData(true)
    notify(t('Finding updated.'))
  }
  async function createReport(scanId: number) {
    await api('/reports/', { method: 'POST', body: JSON.stringify({ scan: scanId, language }) })
    await loadData(true)
    notify(t('PDF report generated.'))
  }
  async function deleteAsset(assetId: number) {
    await api(`/assets/${assetId}/`, { method: 'DELETE' })
    await loadData(true)
    notify(t('Asset removed from this workspace.'))
  }
  async function addMember(email: string, role: string) {
    await api('/organization/members/', { method: 'POST', body: JSON.stringify({ email, role }) })
    await loadData(true)
    notify(t('Organization membership saved.'))
  }

  async function compareScan(scanId: number) {
    return api<ScanComparison>(`/scans/${scanId}/comparison/`)
  }

  async function analyzeFinding(findingId: number) {
    return api<AssistantResult>('/assistant/analyze/', {
      method: 'POST',
      body: JSON.stringify({ finding_id: findingId, language }),
    })
  }

  async function openNotification(item: Notification) {
    try {
      await api(`/notifications/${item.id}/read/`, { method: 'POST', body: JSON.stringify({}) })
      setNotificationPayload(previous => ({
        unread_count: Math.max(0, previous.unread_count - (item.read_at ? 0 : 1)),
        results: previous.results.map(row => row.id === item.id ? { ...row, read_at: row.read_at || new Date().toISOString() } : row),
      }))
      if (item.href === '/findings') setPage('findings')
      else if (item.href === '/scans') setPage('scans')
    } catch (err) {
      setError(err instanceof Error ? err.message : t('The notification could not be opened.'))
    } finally {
      setNotificationOpen(false)
    }
  }

  if (!authenticated) return <AuthScreen onSubmit={handleLogin} />
  if (!me) return <div className="boot-screen"><div className="brand-mark"><ShieldCheck /></div><span>{t('Loading secure workspace…')}</span></div>

  const pageTitle = t(navigation.find(item => item.key === page)?.label || 'Overview')
  const openFindings = findings.filter(f => f.status === 'open').length
  const canWrite = ['owner', 'admin', 'analyst'].includes(me.organization?.role || '')

  function applyPreset(preset: 'analyst' | 'executive' | 'minimal') {
    const presets: Record<typeof preset, UserPreferences> = {
      analyst: { ...DEFAULT_PREFERENCES, accent: 'cyan', density: 'compact', contentWidth: 'wide', navigationItems: ['overview', 'assets', 'scans', 'findings', 'insights', 'assistant', 'reports'] },
      executive: { ...DEFAULT_PREFERENCES, theme: 'graphite', accent: 'violet', density: 'comfortable', dashboardColumns: 2, navigationItems: ['overview', 'assets', 'scans', 'findings', 'insights', 'reports', 'team', 'audit'] },
      minimal: { ...DEFAULT_PREFERENCES, theme: 'light', accent: 'emerald', density: 'spacious', sidebar: 'compact', contentWidth: 'wide', dashboardWidgets: ['snapshot', 'metrics', 'risk', 'activity'], navigationItems: ['overview', 'assets', 'scans', 'findings', 'reports'] },
    }
    setPreferences(normalizePreferences(presets[preset]))
  }

  function exportPreferences() {
    const blob = new Blob([serializePreferences(preferences)], { type: 'application/json;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = 'webguard-preferences.json'
    document.body.appendChild(anchor)
    anchor.click()
    anchor.remove()
    window.setTimeout(() => URL.revokeObjectURL(url), 1000)
    notify(t('Settings exported.'))
  }

  async function importPreferences(file: File) {
    const imported = parsePreferencesJson(await file.text())
    setPreferences(imported)
    notify(t('Settings imported successfully.'))
  }

  return <div className="app-shell" dir={language === 'fa' ? 'rtl' : 'ltr'} lang={language} data-theme={preferences.theme} data-accent={preferences.accent} data-density={preferences.density} data-font={preferences.font} data-font-size={preferences.fontSize} data-corners={preferences.corners} data-sidebar={preferences.sidebar} data-content-width={preferences.contentWidth} data-reduce-motion={String(preferences.reduceMotion)}>
    {mobileOpen && <button className="sidebar-scrim" aria-label={t("Close navigation")} onClick={() => setMobileOpen(false)} />}
    <aside className={`sidebar ${mobileOpen ? 'sidebar-open' : ''}`}>
      <div className="brand"><div className="brand-mark"><ShieldCheck size={22} /></div><div><strong>{t('WEBGUARD')}</strong><span>{t('SECURITY PLATFORM')}</span></div></div>
      <div className="workspace-switch"><div className="workspace-icon">{initials(me.organization?.name || 'WG')}</div><div className="workspace-copy"><strong>{me.organization?.name || 'Workspace'}</strong><span>{t('Assessment workspace')}</span></div><ChevronDown className="workspace-chevron" size={15} /></div>
      <nav className="nav-menu">
        {(['Workspace', 'Security', 'Administration', 'Personalization'] as const).map(group => {
          const groupItems = navigation
            .filter(item => item.group === group && (item.key === 'settings' || preferences.navigationItems.includes(item.key as NavigationItem)))
            .sort((a, b) => {
              if (a.key === 'settings' || b.key === 'settings') return 0
              return preferences.navigationOrder.indexOf(a.key as NavigationItem) - preferences.navigationOrder.indexOf(b.key as NavigationItem)
            })
          if (!groupItems.length) return null
          return <div className="nav-group" key={group}>
            <div className="nav-label">{t(group)}</div>
            {groupItems.map(item => {
              const Icon = item.icon
              return <button key={item.key} title={t(item.label)} aria-label={t(item.label)} className={`nav-item ${page === item.key ? 'active' : ''}`} onClick={() => { setPage(item.key); setMobileOpen(false) }}><Icon size={17} strokeWidth={1.8} /><span>{t(item.label)}</span>{item.key === 'findings' && openFindings > 0 && <b className="nav-count">{openFindings}</b>}</button>
            })}
          </div>
        })}
      </nav>
      <div className="sidebar-bottom">
        <div className="environment-pill"><span className="pulse-dot" />{t('LOCAL ENVIRONMENT')}<span className="env-state">{t('DEV')}</span></div>
        <div className="profile-row"><div className="avatar">{initials(me.full_name || me.email)}</div><div className="profile-info"><strong>{me.full_name || me.email.split('@')[0]}</strong><span>{t(me.organization?.role || 'member')}</span></div><button className="icon-button subtle" title={t("Sign out")} onClick={() => void logout()}><LogOut size={17} /></button></div>
      </div>
    </aside>

    <main className="main-area">
      <header className="topbar">
        <button className="mobile-menu-button icon-button" aria-label={t("Open navigation")} onClick={() => setMobileOpen(true)}><Menu size={19} /></button>
        <div className="breadcrumbs"><span>{t('Workspace')}</span><ArrowRight size={13} /><strong>{pageTitle}</strong></div>
        <div className="top-actions"><div className="system-status"><span className="pulse-dot" /> {t('SECURE SESSION')}</div><LanguageSwitcher /><div className="notification-anchor"><button className="icon-button notification-trigger" title={t('Notifications')} aria-label={t('Notifications')} aria-expanded={notificationOpen} onClick={() => setNotificationOpen(value => !value)}><Bell size={17} />{notificationPayload.unread_count > 0 && <span className="notification-count">{notificationPayload.unread_count > 99 ? '99+' : notificationPayload.unread_count}</span>}</button>{notificationOpen && <div className="notification-popover"><div className="notification-popover-head"><strong>{t('Notifications')}</strong><span>{notificationPayload.unread_count} {t('unread')}</span></div>{notificationPayload.results.length ? notificationPayload.results.slice(0, 8).map(item => <button key={item.id} className={`notification-item ${item.read_at ? 'is-read' : 'is-unread'}`} onClick={() => void openNotification(item)}><span className={`notification-level level-${item.level}`} /><span className="notification-copy"><strong>{t(item.title)}</strong><small>{notificationMessage(item, language)}</small><em>{formatDate(item.created_at)}</em></span></button>) : <div className="notification-empty">{t('You are all caught up.')}</div>}</div>}</div><button className="icon-button" title={t("Refresh data")} onClick={() => void loadData()}><RefreshCw size={17} className={loading ? 'spin' : ''} /></button><div className="top-divider" /><div className="top-user"><div className="avatar small">{initials(me.email)}</div><span>{me.email}</span></div></div>
      </header>
      <div className="page-content">
        {error && <div className="alert alert-error"><AlertTriangle size={16} />{error}<button onClick={() => setError('')}><X size={15} /></button></div>}
        {notice && <div className="toast"><CheckCircle2 size={16} />{notice}</div>}
        {page === 'overview' && <OverviewPage overview={overview} scans={scans} assets={assets} findings={findings} onNavigate={setPage} onRefresh={() => void loadData()} preferences={preferences} />}
        {page === 'assets' && <AssetsPage assets={assets} canWrite={canWrite} onAdd={(domain) => safely(() => addAsset(domain))} onVerify={(id) => safely(() => refreshVerification(id))} onScan={(id) => safely(() => startScan(id))} onDelete={(id) => safely(() => deleteAsset(id))} busyId={busyId} />}
        {page === 'scans' && <ScansPage scans={scans} assets={assets} canWrite={canWrite} onStart={(id) => safely(() => startScan(id))} onCancel={(id) => safely(() => cancelScan(id))} onCompare={compareScan} busyId={busyId} />}
        {page === 'findings' && <FindingsPage findings={findings} members={members} canWrite={canWrite} onUpdate={(finding, changes) => safely(() => updateFinding(finding, changes))} />}
        {page === 'insights' && <InsightsPage trends={trends} onNavigate={setPage} />}
        {page === 'assistant' && <AssistantPage findings={findings} onAnalyze={analyzeFinding} />}
        {page === 'reports' && <ReportsPage reports={reports} scans={scans} canWrite={canWrite} language={language} onCreate={(id) => safely(() => createReport(id))} onDownload={(id) => safely(() => downloadReport(id))} />}
        {page === 'team' && <TeamPage members={members} role={me.organization?.role || 'viewer'} onAdd={(email, role) => safely(() => addMember(email, role))} />}
        {page === 'audit' && <AuditPage rows={audit} role={me.organization?.role || 'viewer'} />}
        {page === 'settings' && <PersonalizationPage preferences={preferences} onChange={updatePreferences} onReset={() => setPreferences(normalizePreferences(DEFAULT_PREFERENCES))} onExport={exportPreferences} onImport={importPreferences} onPreset={applyPreset} />}
      </div>
    </main>
    {verifyAsset && <VerificationModal verification={verifyAsset} busy={busyId === verifyAsset.asset_id} error={verificationError} onVerify={verifyAssetNow} onClose={() => { setVerifyAsset(null); setVerificationError('') }} />}
  </div>
}

function LanguageSwitcher() {
  const { language, setLanguage, t } = useI18n()
  return <div className="language-switcher" role="group" aria-label={t('Language')} title={t('Language')}>
    <button type="button" className={language === 'en' ? 'selected' : ''} aria-label={t('English')} title={t('English')} aria-pressed={language === 'en'} onClick={() => setLanguage('en')}>EN</button>
    <button type="button" className={language === 'fa' ? 'selected' : ''} aria-label={t('Persian')} title={t('Persian')} aria-pressed={language === 'fa'} onClick={() => setLanguage('fa')}>فارسی</button>
  </div>
}

function AuthScreen({ onSubmit }: { onSubmit: (email: string, password: string, mode: 'login' | 'register', fullName?: string, organizationName?: string) => Promise<void> }) {
  const { language, t } = useI18n()
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [fullName, setFullName] = useState('')
  const [organizationName, setOrganizationName] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  async function submit(e: FormEvent) {
    e.preventDefault(); setBusy(true); setError('')
    try { await onSubmit(email, password, mode, fullName, organizationName) }
    catch (err) { setError(err instanceof Error ? err.message : t('Authentication failed.')) }
    finally { setBusy(false) }
  }
  return <div className="auth-shell" dir={language === 'fa' ? 'rtl' : 'ltr'} lang={language}>
    <div className="auth-art">
      <div className="auth-glow glow-one" /><div className="auth-glow glow-two" />
      <div className="auth-brand"><div className="brand-mark"><ShieldCheck size={24} /></div><div><strong>{t('WEBGUARD')}</strong><span>{t('SECURITY PLATFORM')}</span></div></div>
      <div className="auth-hero"><div className="eyebrow"><span className="pulse-dot" />{t('AUTHORIZED SECURITY ASSESSMENT')}</div><h1>{t('See your attack')}<br /><em>{t('surface clearly.')}</em></h1><p>{t('Continuous visibility. Evidence-backed findings. A stronger security posture for every verified asset.')}</p>
        <div className="auth-visual"><div className="orbit orbit-a" /><div className="orbit orbit-b" /><div className="orbit orbit-c" /><div className="orbit-core"><ShieldCheck size={45} /></div><div className="orbit-node node-a"><Globe2 size={17} /></div><div className="orbit-node node-b"><LockKeyhole size={17} /></div><div className="orbit-node node-c"><Radar size={17} /></div><div className="orbit-node node-d"><Activity size={17} /></div></div>
      </div>
      <div className="auth-footer"><span>{t('PASSIVE BY DESIGN')}</span><span>·</span><span>{t('VERIFIED ASSETS ONLY')}</span><span>·</span><span>{t('EVIDENCE FIRST')}</span></div>
    </div>
    <div className="auth-panel"><div className="auth-panel-inner"><div className="auth-tools"><LanguageSwitcher /></div><div className="mobile-auth-brand"><div className="brand-mark"><ShieldCheck /></div><strong>{t('WEBGUARD')}</strong></div><div className="auth-kicker">{t('SECURE WORKSPACE ACCESS')}</div><h2>{t(mode === 'login' ? 'Welcome back' : 'Create your workspace')}</h2><p className="auth-subtitle">{t(mode === 'login' ? 'Sign in to manage your verified assets and assessments.' : 'Start your security assessment workspace in minutes.')}</p>
      <form onSubmit={submit} className="auth-form">
        {mode === 'register' && <><label>{t('Full name')}<input value={fullName} onChange={e => setFullName(e.target.value)} placeholder={t('Your name')} autoComplete="name" required /></label><label>{t('Organization')}<input value={organizationName} onChange={e => setOrganizationName(e.target.value)} placeholder={t('Company or lab name')} required /></label></>}
        <label>{t('Work email')}<div className="input-with-icon"><span>@</span><input type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="you@company.com" autoComplete="email" required /></div></label>
        <label>{t('Password')}<input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder={t(mode === 'register' ? 'At least 12 characters' : 'Enter your password')} autoComplete={mode === 'login' ? 'current-password' : 'new-password'} minLength={mode === 'register' ? 12 : 1} required /></label>
        {error && <div className="inline-error"><AlertTriangle size={15} />{error}</div>}
        <button className="button-primary auth-submit" disabled={busy}>{busy ? <RefreshCw size={16} className="spin" /> : <>{t(mode === 'login' ? 'Sign in to workspace' : 'Create secure workspace')} <ArrowRight size={17} /></>}</button>
      </form>
      <div className="auth-switch">{t(mode === 'login' ? 'New to WEBGUARD?' : 'Already have a workspace?')} <button onClick={() => { setMode(mode === 'login' ? 'register' : 'login'); setError('') }}>{t(mode === 'login' ? 'Create account' : 'Sign in')}</button></div>
      <div className="auth-compliance"><LockKeyhole size={14} />{t('Your session is protected with short-lived access tokens.')}</div>
    </div></div>
  </div>
}

function PageHeading({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: ReactNode }) {
  const { t } = useI18n()
  return <div className="page-heading"><div><div className="eyebrow-text">{t(eyebrow)}</div><h1>{t(title)}</h1><p>{t(description)}</p></div>{action && <div>{action}</div>}</div>
}
function MetricCard({ label, value, detail, icon: Icon, tone = 'blue', trend }: { label: string; value: string | number; detail: string; icon: typeof Activity; tone?: string; trend?: string }) {
  const { t } = useI18n()
  return <div className="metric-card"><div className={`metric-icon tone-${tone}`}><Icon size={19} /></div><div className="metric-label">{t(label)}</div><div className="metric-value">{value}</div><div className="metric-bottom"><span>{t(detail)}</span>{trend && <span className="metric-trend">{t(trend)}</span>}</div></div>
}
function OverviewPage({ overview, scans, assets, findings, onNavigate, onRefresh, preferences }: { overview: Overview | null; scans: Scan[]; assets: Asset[]; findings: Finding[]; onNavigate: (page: Page) => void; onRefresh: () => void; preferences: UserPreferences }) {
  const { t } = useI18n()
  const severity = overview?.severity || {}
  const max = Math.max(1, ...Object.values(severity))
  const widgets: Record<DashboardWidget, ReactNode> = {
    snapshot: <div className="overview-banner"><div className="banner-pattern" /><div className="banner-copy"><div className="banner-label"><Sparkles size={14} />{t('SECURITY POSTURE SNAPSHOT')}</div><h2>{overview?.security_score === null || overview?.security_score === undefined ? t('Your baseline starts here.') : `${t('Your security score is')} ${overview.security_score}/100.`}</h2><p>{overview?.security_score === null || overview?.security_score === undefined ? t('Verify a domain and run your first passive assessment to establish a baseline.') : t('This heuristic score is based on the latest completed assessment and helps track remediation progress.')}</p></div><div className="banner-score"><span>{t('LAST BASELINE')}</span><strong>{overview?.security_score ?? '—'}<small>{overview?.security_score == null ? '' : '/100'}</small></strong><div className="score-track"><i style={{ width: `${overview?.security_score ?? 0}%` }} /></div></div></div>,
    metrics: <div className="metrics-grid">
      <MetricCard label="Total assets" value={overview?.asset_count ?? assets.length} detail={`${overview?.verified_asset_count ?? assets.filter(a => a.status === 'verified').length} ${t('verified')}`} icon={Globe2} tone="blue" />
      <MetricCard label="Assessments" value={overview?.scan_count ?? scans.length} detail={`${overview?.active_scans ?? 0} ${t('in progress')}`} icon={Radar} tone="purple" />
      <MetricCard label="Open findings" value={overview?.open_findings ?? findings.filter(f => f.status === 'open').length} detail="Require review" icon={ShieldAlert} tone="red" />
      <MetricCard label="Critical findings" value={severity.critical ?? 0} detail={`${severity.high ?? 0} ${t('high severity')}`} icon={AlertTriangle} tone="orange" />
    </div>,
    risk: <section className="panel"><div className="panel-heading"><div><span className="eyebrow-text">{t('RISK DISTRIBUTION')}</span><h3>{t('Open findings by severity')}</h3></div><button className="text-button" onClick={() => onNavigate('findings')}>{t('View findings')}<ArrowRight size={14} /></button></div>
      <div className="severity-chart">{(['critical', 'high', 'medium', 'low'] as const).map(level => <div className="severity-row" key={level}><div className="severity-row-label"><span className={`severity-dot dot-${level}`} />{t(level)}<strong>{severity[level] ?? 0}</strong></div><div className="severity-bar"><i className={`bar-${level}`} style={{ width: `${((severity[level] ?? 0) / max) * 100}%` }} /></div></div>)}</div>
      <div className="panel-footnote"><ShieldHalf size={14} />{t('Severity is assigned by individual WEBGUARD checks; review evidence before prioritizing remediation.')}</div>
    </section>,
    assets: <section className="panel"><div className="panel-heading"><div><span className="eyebrow-text">{t('ASSET COVERAGE')}</span><h3>{t('Verified targets')}</h3></div><button className="text-button" onClick={() => onNavigate('assets')}>{t('Manage assets')}<ArrowRight size={14} /></button></div>
      <div className="asset-overview-list">{assets.slice(0, 5).map(asset => <div className="asset-overview-row" key={asset.id}><div className="asset-favicon"><Globe2 size={16} /></div><div className="asset-row-copy"><strong>{asset.domain}</strong><span>{t('Added')} {formatDate(asset.created_at)}</span></div><span className={statusClass(asset.status)}>{t(asset.status)}</span></div>)}{assets.length === 0 && <EmptyState icon={Globe2} title={t('No assets yet')} text="Add a domain you own or are authorized to assess." action="Add your first asset" onClick={() => onNavigate('assets')} />}</div>
    </section>,
    activity: <section className="panel recent-panel"><div className="panel-heading"><div><span className="eyebrow-text">{t('LATEST ACTIVITY')}</span><h3>{t('Recent assessments')}</h3></div><button className="text-button" onClick={() => onNavigate('scans')}>{t('All assessments')}<ArrowRight size={14} /></button></div><ScanTable scans={scans.slice(0, 5)} compact /></section>,
    footnote: <div className="footnote"><LockKeyhole size={13} />{t('WEBGUARD runs non-invasive, passive checks against domains verified by DNS TXT challenge. Findings are indicators for review, not proof of exploitability.')}</div>,
  }
  return <>
    <PageHeading eyebrow="SECURITY OPERATIONS / OVERVIEW" title="Security posture" description="A consolidated view of your verified assets, assessment activity and outstanding risk." action={<button className="button-secondary" onClick={onRefresh}><RefreshCw size={15} />{t('Refresh data')}</button>} />
    <div className={`dashboard-layout ${preferences.dashboardColumns === 1 ? 'dashboard-one-column' : 'dashboard-two-columns'}`}>
      {preferences.dashboardOrder.filter(widget => preferences.dashboardWidgets.includes(widget)).map(widget => <div className={`dashboard-widget dashboard-widget-${widget}`} data-widget={widget} key={widget}>{widgets[widget]}</div>)}
      {!preferences.dashboardWidgets.length && <div className="panel dashboard-empty"><EmptyState icon={LayoutDashboard} title="Your dashboard is clear" text="Enable one or more dashboard widgets in Personalization studio." action="Open personalization" onClick={() => onNavigate('settings')} /></div>}
    </div>
  </>
}

function EmptyState({ icon: Icon, title, text, action, onClick }: { icon: typeof Activity; title: string; text: string; action?: string; onClick?: () => void }) {
  const { t } = useI18n()
  return <div className="empty-state"><div className="empty-icon"><Icon size={22} /></div><strong>{t(title)}</strong><p>{t(text)}</p>{action && onClick && <button className="button-secondary small-button" onClick={onClick}>{t(action)}</button>}</div>
}
function AssetsPage({ assets, canWrite, onAdd, onVerify, onScan, onDelete, busyId }: { assets: Asset[]; canWrite: boolean; onAdd: (domain: string) => Promise<void>; onVerify: (id: number) => Promise<void>; onScan: (id: number) => Promise<void>; onDelete: (id: number) => Promise<void>; busyId: number | null }) {
  const { t } = useI18n()
  const [domain, setDomain] = useState('')
  const [search, setSearch] = useState('')
  const filteredAssets = assets.filter(asset => asset.domain.toLowerCase().includes(search.toLowerCase()))
  const [adding, setAdding] = useState(false)
  const [localError, setLocalError] = useState('')
  async function submit(e: FormEvent) { e.preventDefault(); setAdding(true); setLocalError(''); try { await onAdd(domain); setDomain('') } catch (err) { setLocalError(err instanceof Error ? err.message : t('Could not add asset.')) } finally { setAdding(false) } }
  return <>
    <PageHeading eyebrow="ASSET MANAGEMENT" title="Attack surface" description="Register domains, prove ownership and control which assets can be assessed." action={<div className="scope-chip"><LockKeyhole size={14} />{t('VERIFIED SCOPE ONLY')}</div>} />
    {canWrite ? <div className="asset-add-card"><div className="add-card-intro"><div className="metric-icon tone-blue"><Target size={20} /></div><div><h3>{t('Register a new asset')}</h3><p>{t('Enter a hostname only. WEBGUARD will issue a DNS TXT ownership challenge.')}</p></div></div><form className="add-asset-form" onSubmit={submit}><div className="domain-input"><Globe2 size={17} /><input value={domain} onChange={e => setDomain(e.target.value)} placeholder="example.com" required /><span>{t('DOMAIN')}</span></div><button className="button-primary" disabled={adding || !domain.trim()}>{adding ? <RefreshCw className="spin" size={16} /> : <><Plus size={16} />{t('Add asset')}</>}</button></form>{localError && <div className="inline-error"><AlertTriangle size={15} />{localError}</div>}</div> : <div className="info-strip"><LockKeyhole size={18} /><div><strong>{t('Read-only workspace role')}</strong><span>{t('Your current role can review assets but cannot register, verify or remove them.')}</span></div></div>}
    <div className="section-caption asset-section-caption"><div><span className="eyebrow-text">{t('YOUR INVENTORY')}</span><h3>{t('Registered assets')}<span className="count-bubble">{assets.length}</span></h3></div><div className="asset-toolbar"><label className="search-field"><Search size={15} /><input value={search} onChange={e => setSearch(e.target.value)} placeholder={t('Search domains')} /></label><span className="muted-caption">{t('Only verified assets can be scanned')}</span></div></div>
    {filteredAssets.length ? <div className="asset-grid">{filteredAssets.map(asset => <div className="asset-card" key={asset.id}><div className="asset-card-top"><div className="asset-favicon large"><Globe2 size={19} /></div><span className={statusClass(asset.status)}>{t(asset.status === 'pending' ? 'verification pending' : asset.status)}</span></div><h3>{asset.domain}</h3><p>{t('Created')} {formatDate(asset.created_at)}</p><div className="asset-card-meta"><div><span>{t('LAST ASSESSMENT')}</span><strong>{formatDate(asset.last_scanned_at)}</strong></div><div><span>{t('OWNERSHIP')}</span><strong>{t(asset.status === 'verified' ? 'DNS verified' : 'Action required')}</strong></div></div><div className="asset-card-actions">{asset.status === 'verified' ? <button className="button-primary full-button" onClick={() => void onScan(asset.id)} disabled={!canWrite || busyId === asset.id}>{busyId === asset.id ? <RefreshCw size={15} className="spin" /> : <><Radar size={15} />{t('Run passive assessment')}</>}</button> : <button className="button-secondary full-button" onClick={() => void onVerify(asset.id)} disabled={!canWrite}><Fingerprint size={15} />{t('View DNS challenge')}</button>}{canWrite && <button className="asset-delete-button" onClick={() => { if (window.confirm(`${t('Remove asset')} ${asset.domain}?`)) void onDelete(asset.id) }}><X size={14} />{t('Remove asset')}</button>}</div></div>)}</div> : <div className="panel"><EmptyState icon={Globe2} title={t(search ? 'No matching assets' : 'Your asset inventory is empty')} text={t(search ? 'Try a different domain search.' : 'Register your first domain to begin building a verified security scope.')} /></div>}
    <div className="info-strip"><ShieldCheck size={18} /><div><strong>{t('Built-in scope protection')}</strong><span>{t('WEBGUARD rejects local and reserved domains, pins each connection to validated public DNS addresses and will not follow redirects to a different hostname.')}</span></div></div>
  </>
}

function ScansPage({ scans, assets, canWrite, onStart, onCancel, onCompare, busyId }: { scans: Scan[]; assets: Asset[]; canWrite: boolean; onStart: (id: number) => Promise<void>; onCancel: (id: number) => Promise<void>; onCompare: (id: number) => Promise<ScanComparison>; busyId: number | null }) {
  const { t } = useI18n()
  const [assetId, setAssetId] = useState('')
  const [viewScan, setViewScan] = useState<Scan | null>(null)
  const [comparison, setComparison] = useState<ScanComparison | null>(null)
  const [comparisonBusy, setComparisonBusy] = useState(false)
  const [comparisonError, setComparisonError] = useState('')
  const verified = assets.filter(a => a.status === 'verified')
  async function compare(id: number) {
    setComparisonBusy(true); setComparisonError('')
    try { setComparison(await onCompare(id)) }
    catch (error) { setComparisonError(error instanceof Error ? error.message : t('Comparison could not be loaded.')) }
    finally { setComparisonBusy(false) }
  }
  return <>
    <PageHeading eyebrow="ASSESSMENT ENGINE" title="Assessments" description="Queue and review safe, passive configuration checks for verified assets." action={<span className="scope-chip"><Activity size={14} />{t('PASSIVE PROFILE')}</span>} />
    {canWrite ? <div className="scan-launch-card"><div className="launch-icon"><Radar size={23} /></div><div className="launch-copy"><h3>{t('Start a new assessment')}</h3><p>{t('Checks the root endpoint using bounded HEAD requests; no payloads, brute force or exploitation.')}</p></div><div className="launch-controls"><select value={assetId} onChange={e => setAssetId(e.target.value)}><option value="">{t('Select verified asset')}</option>{verified.map(a => <option key={a.id} value={a.id}>{a.domain}</option>)}</select><button className="button-primary" disabled={!assetId || busyId !== null} onClick={() => void onStart(Number(assetId))}><Radar size={16} />{t('Run scan')}</button></div></div> : <div className="info-strip"><LockKeyhole size={18} /><div><strong>{t('Read-only access')}</strong><span>{t('Your role can review assessment history but cannot queue or cancel assessments.')}</span></div></div>}
    <div className="section-caption"><div><span className="eyebrow-text">{t('EXECUTION HISTORY')}</span><h3>{t('All assessments')}<span className="count-bubble">{scans.length}</span></h3></div><span className="muted-caption"><span className="pulse-dot" />{t('Worker status is managed locally')}</span></div>
    <div className="panel table-panel"><ScanTable scans={scans} onCancel={canWrite ? onCancel : undefined} onView={setViewScan} onCompare={(scan) => void compare(scan.id)} busyId={busyId} /></div>
    <div className="info-strip"><Clock3 size={18} /><div><strong>{t('Local worker required')}</strong><span>{t('Keep the scanner worker running:')} <code>python manage.py run_scan_worker</code>. {t('Pending jobs remain queued until a worker processes them.')}</span></div></div>
    {comparisonError && <div className="alert alert-error"><AlertTriangle size={15} />{comparisonError}<button onClick={() => setComparisonError('')}><X size={14} /></button></div>}
    {comparisonBusy && <div className="comparison-loading"><RefreshCw size={15} className="spin" />{t('Comparing assessment history…')}</div>}
    {comparison && <ScanComparisonModal comparison={comparison} onClose={() => setComparison(null)} />}
    {viewScan && <ScanDetailsModal scan={viewScan} onClose={() => setViewScan(null)} />}
  </>
}

function ScanTable({ scans, compact = false, onCancel, onView, onCompare, busyId }: { scans: Scan[]; compact?: boolean; onCancel?: (id: number) => Promise<void>; onView?: (scan: Scan) => void; onCompare?: (scan: Scan) => void; busyId?: number | null }) {
  const { t } = useI18n()
  if (!scans.length) return <EmptyState icon={Radar} title={t('No assessments yet')} text="Once a verified asset is assessed, its execution history will appear here." />
  return <div className="table-wrap"><table><thead><tr><th>{t('ASSESSMENT')}</th><th>{t('STATUS')}</th><th>{t('CHECKS')}</th><th>{t('FINDINGS')}</th><th>{t('CREATED')}</th>{!compact && <th>{t('ACTIONS')}</th>}</tr></thead><tbody>{scans.map(scan => <tr key={scan.id}><td><div className="table-primary"><span className="scan-mini-icon"><Radar size={15} /></span><div><strong>{scan.asset_domain}</strong><small>{t('Assessment')} #{scan.id} · {t('passive baseline')}</small></div></div></td><td><span className={statusClass(scan.status)}>{t(scan.status)}</span></td><td><div className="check-count"><strong>{scan.total_checks}</strong><span>{scan.passed_checks} {t('passed')}</span></div></td><td><span className={scan.failed_checks ? 'finding-number has-findings' : 'finding-number'}>{scan.failed_checks}</span></td><td className="date-cell">{formatDate(scan.created_at)}</td>{!compact && <td className="actions-cell">{onView && <button className="text-button" onClick={() => onView(scan)}>{t('Details')}</button>}{onCompare && scan.status === 'completed' && <button className="text-button" onClick={() => onCompare(scan)}>{t('Compare')}</button>}{onCancel && ['pending', 'running'].includes(scan.status) && <button className="text-button danger-text" disabled={busyId === scan.id} onClick={() => void onCancel(scan.id)}>{t('Cancel')}</button>}</td>}</tr>)}</tbody></table></div>
}



function ScanComparisonModal({ comparison, onClose }: { comparison: ScanComparison; onClose: () => void }) {
  const { t } = useI18n()
  const groups = [
    { key: 'new', title: t('New findings'), values: comparison.new_findings, tone: 'new' },
    { key: 'resolved', title: t('Resolved findings'), values: comparison.resolved_findings, tone: 'resolved' },
    { key: 'persistent', title: t('Persistent findings'), values: comparison.persistent_findings, tone: 'persistent' },
  ]
  return <div className="modal-backdrop" role="presentation" onMouseDown={event => { if (event.target === event.currentTarget) onClose() }}><div className="comparison-modal panel" role="dialog" aria-modal="true" aria-labelledby="comparison-title"><div className="modal-top"><div><div className="eyebrow-text">{t('ASSESSMENT COMPARISON')}</div><h2 id="comparison-title">{t('Security posture comparison')}</h2></div><button className="icon-button" onClick={onClose} aria-label={t('Close')}><X size={18} /></button></div><div className="comparison-score-grid"><div><span>{t('Current score')}</span><strong>{comparison.current_score}</strong><small>#{comparison.current_scan_id}</small></div><div><span>{t('Previous score')}</span><strong>{comparison.has_baseline ? comparison.previous_score : '—'}</strong><small>{comparison.previous_scan_id ? `#${comparison.previous_scan_id}` : t('No previous baseline')}</small></div><div><span>{t('Score change')}</span><strong className={comparison.score_change === undefined ? '' : comparison.score_change >= 0 ? 'green-text' : 'red-text'}>{comparison.score_change === undefined ? '—' : `${comparison.score_change > 0 ? '+' : ''}${comparison.score_change}`}</strong><small>{t('WEBGUARD heuristic score')}</small></div></div>{!comparison.has_baseline && <div className="info-strip"><Activity size={17} /><div><strong>{t('No previous baseline')}</strong><span>{t('This is the first completed assessment for this asset. Future completed assessments can be compared against it.')}</span></div></div>}<div className="comparison-groups">{groups.map(group => <section className={`comparison-group ${group.tone}`} key={group.key}><div><strong>{group.title}</strong><b>{group.values.length}</b></div>{group.values.length ? <ul>{group.values.map(value => <li key={value}><code>{value}</code></li>)}</ul> : <p>{t('None')}</p>}</section>)}</div><div className="comparison-footnote">{t('A finding is compared by its stable check identifier. Scores are heuristic and are not CVSS.')}</div></div></div>
}

function ScanDetailsModal({ scan, onClose }: { scan: Scan; onClose: () => void }) {
  const { t } = useI18n()
  const checks = scan.checks || []
  return <div className="modal-backdrop" role="presentation" onMouseDown={e => { if (e.target === e.currentTarget) onClose() }}><div className="scan-details-modal" role="dialog" aria-modal="true" aria-labelledby="scan-detail-title"><div className="modal-top"><div className="modal-icon"><Radar size={21} /></div><button className="icon-button" onClick={onClose}><X size={18} /></button></div><div className="eyebrow-text">{t('ASSESSMENT')} #{scan.id}</div><h2 id="scan-detail-title">{scan.asset_domain}</h2><div className="scan-detail-summary"><div><span>{t('STATUS')}</span><strong className={statusClass(scan.status)}>{t(scan.status)}</strong></div><div><span>{t('CHECKS')}</span><strong>{scan.total_checks}</strong></div><div><span>{t('PASSED')}</span><strong className="green-text">{scan.passed_checks}</strong></div><div><span>{t('FAILED')}</span><strong className="red-text">{scan.failed_checks}</strong></div></div><p className="scan-detail-date">{t('Created')} {formatDate(scan.created_at)} · {t('Finished')} {formatDate(scan.finished_at)}</p>{scan.error_message && <div className="inline-error"><AlertTriangle size={14} />{scan.error_message}</div>}<div className="scan-check-list">{checks.map(check => <div className="scan-check-row" key={check.check_id}><div className={`check-result-icon result-${check.status}`}>{check.status === 'pass' ? <CheckCircle2 size={15} /> : check.status === 'fail' ? <AlertTriangle size={15} /> : <CircleHelp size={15} />}</div><div className="scan-check-copy"><div><strong>{t(check.name)}</strong><span>{check.check_id} · {t(check.category)}</span></div><p>{t(check.description)}</p>{check.status === 'fail' && <p className="check-recommendation">{t('Fix:')} {t(check.recommendation)}</p>}<details><summary>{t('Evidence')}</summary><pre>{JSON.stringify(check.evidence, null, 2)}</pre></details></div><span className={severityClass(check.severity)}>{t(check.severity)}</span></div>)}{checks.length === 0 && <EmptyState icon={Clock3} title={t('No check results yet')} text="This assessment is queued, running, or ended before checks were stored." />}</div><div className="modal-actions"><button className="button-primary" onClick={onClose}>{t('Close details')}</button></div></div></div>
}

function FindingsPage({ findings, members, canWrite, onUpdate }: { findings: Finding[]; members: Member[]; canWrite: boolean; onUpdate: (finding: Finding, changes: Partial<Pick<Finding, 'status' | 'notes' | 'assigned_to'>>) => Promise<void> }) {
  const { t } = useI18n()
  const [filter, setFilter] = useState('all')
  const [search, setSearch] = useState('')
  const filtered = findings.filter(f => {
    const matchesFilter = filter === 'all' || f.severity === filter || f.status === filter
    const haystack = `${f.title} ${f.asset_domain} ${f.check_id} ${f.category}`.toLowerCase()
    return matchesFilter && haystack.includes(search.toLowerCase())
  })
  const filters = ['all', 'critical', 'high', 'medium', 'low', 'open', 'accepted', 'fixed', 'false_positive']
  return <>
    <PageHeading eyebrow="VULNERABILITY MANAGEMENT" title="Security findings" description="Evidence-backed configuration weaknesses from completed assessments. Validate findings before remediation decisions." action={<div className="finding-total"><strong>{findings.filter(f => f.status === 'open').length}</strong><span>{t('OPEN FINDINGS')}</span></div>} />
    <div className="filter-bar"><div className="filter-label"><Search size={16} />{t('Filter findings')}</div><div className="filter-chips">{filters.map(x => <button key={x} className={filter === x ? 'filter-chip selected' : 'filter-chip'} onClick={() => setFilter(x)}>{t(x === 'false_positive' ? 'False positive' : x)}</button>)}</div><label className="search-field finding-search"><Search size={14} /><input value={search} onChange={e => setSearch(e.target.value)} placeholder={t('Search by domain, check or title')} /></label></div>
    <div className="finding-list">{filtered.map(finding => <article className="finding-card" key={finding.id}><div className="finding-severity-rail" data-severity={finding.severity} /><div className="finding-content"><div className="finding-card-head"><div className="finding-title-group"><span className={severityClass(finding.severity)}>{t(finding.severity)}</span><span className="finding-id">{finding.check_id}</span><span className={statusClass(finding.status)}>{t(finding.status.replace('_', ' '))}</span></div><select className="finding-status-select" value={finding.status} disabled={!canWrite} onChange={e => void onUpdate(finding, { status: e.target.value })}><option value="open">{t('Open')}</option><option value="accepted">{t('Risk accepted')}</option><option value="fixed">{t('Fixed')}</option><option value="false_positive">{t('False positive')}</option></select></div><h3>{t(finding.title)}</h3><div className="finding-meta"><span><Globe2 size={13} /> {finding.asset_domain}</span><span><Target size={13} /> {t(finding.category)}</span><span><Clock3 size={13} /> {formatDate(finding.created_at)}</span></div><p className="finding-description">{t(finding.description)}</p><div className="recommendation-box"><div><CheckCircle2 size={15} /><strong>{t('Recommended remediation')}</strong></div><p>{t(finding.recommendation)}</p></div><div className="remediation-controls"><label>{t('Assigned to')}<select value={finding.assigned_to ?? ''} disabled={!canWrite} onChange={e => void onUpdate(finding, { assigned_to: e.target.value ? Number(e.target.value) : null })}><option value="">{t('Unassigned')}</option>{members.filter(member => member.role !== 'viewer').map(member => <option key={member.user_id} value={member.user_id}>{member.full_name || member.email}</option>)}</select></label><label>{t('Remediation notes')}<textarea defaultValue={finding.notes} maxLength={3000} disabled={!canWrite} placeholder={t('Document the remediation decision or validation notes.')} onBlur={e => { if (e.currentTarget.value !== finding.notes) void onUpdate(finding, { notes: e.currentTarget.value }) }} /></label></div><details className="evidence-details"><summary>{t('View technical evidence')}<ChevronDown size={14} /></summary><pre>{JSON.stringify(finding.evidence, null, 2)}</pre></details></div></article>)}{filtered.length === 0 && <div className="panel"><EmptyState icon={ShieldCheck} title={t('No findings in this view')} text={findings.length ? 'Try another filter. There are no findings matching this selection.' : 'Run a passive assessment on a verified asset to populate findings.'} /></div>}</div>
    <div className="footnote"><CircleHelp size={14} />{t('Missing headers and metadata are indicators. WEBGUARD does not assert exploitability or scan authenticated application paths.')}</div>
  </>
}


function InsightsPage({ trends, onNavigate }: { trends: Trends; onNavigate: (page: Page) => void }) {
  const { t } = useI18n()
  const daily = trends.daily_scans.slice(-14)
  const maxScans = Math.max(1, ...daily.map(item => item.scans))
  const history = trends.score_history.slice(-10)
  return <>
    <PageHeading eyebrow="SECURITY INTELLIGENCE" title="Security insights" description="Review assessment activity, posture score movement and the current open-risk distribution." action={<button className="button-secondary" onClick={() => onNavigate('findings')}><ShieldAlert size={15} />{t('Review findings')}</button>} />
    <div className="insight-grid">
      <section className="panel insight-panel"><div className="panel-heading"><div><span className="eyebrow-text">{t('LAST 14 DAYS')}</span><h3>{t('Assessment activity')}</h3></div><Radar size={18} /></div><div className="activity-bars">{daily.length ? daily.map(item => <div className="activity-bar-column" key={item.date} title={`${item.date}: ${item.scans} ${t('scans')}`}><div className="activity-bar-track"><i style={{ height: `${Math.max(5, item.scans / maxScans * 100)}%` }} /></div><small>{formatDay(item.date)}</small></div>) : <EmptyState icon={Activity} title="No trend data yet" text="Run assessments to begin building your security activity history." />}</div><div className="insight-legend"><span><i className="legend-dot" />{t('Scans per day')}</span><span>{t('Completed')}: {daily.reduce((sum, item) => sum + item.completed, 0)}</span></div></section>
      <section className="panel insight-panel"><div className="panel-heading"><div><span className="eyebrow-text">{t('POSTURE HISTORY')}</span><h3>{t('Security score trend')}</h3></div><Activity size={18} /></div>{history.length ? <div className="score-history-list">{history.map(item => <div className="score-history-row" key={item.scan_id}><div><strong>{item.domain}</strong><small>#{item.scan_id} · {formatDay(item.date)}</small></div><div className="score-history-track"><i style={{ width: `${item.score}%` }} /></div><b>{item.score}</b></div>)}</div> : <EmptyState icon={Activity} title="No completed assessments" text="A score history appears after the first completed assessment." />}</section>
    </div>
    <section className="panel insight-panel"><div className="panel-heading"><div><span className="eyebrow-text">{t('OPEN RISK')}</span><h3>{t('Current findings by severity')}</h3></div><button className="text-button" onClick={() => onNavigate('findings')}>{t('View findings')}<ArrowRight size={14} /></button></div><div className="severity-chart">{(['critical', 'high', 'medium', 'low', 'informational'] as const).map(level => { const value = trends.open_findings_by_severity[level] || 0; const max = Math.max(1, ...Object.values(trends.open_findings_by_severity)); return <div className="severity-row" key={level}><div className="severity-row-label"><span className={`severity-dot dot-${level}`} />{t(level)}<strong>{value}</strong></div><div className="severity-bar"><i className={`bar-${level}`} style={{ width: `${value / max * 100}%` }} /></div></div> })}</div></section>
  </>
}

function AssistantPage({ findings, onAnalyze }: { findings: Finding[]; onAnalyze: (findingId: number) => Promise<AssistantResult> }) {
  const { t } = useI18n()
  const [findingId, setFindingId] = useState('')
  const [result, setResult] = useState<AssistantResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  async function submit() {
    if (!findingId) return
    setBusy(true); setError('')
    try { setResult(await onAnalyze(Number(findingId))) }
    catch (err) { setError(err instanceof Error ? err.message : t('Analysis could not be generated.')) }
    finally { setBusy(false) }
  }
  return <>
    <PageHeading eyebrow="REMEDIATION INTELLIGENCE" title="Security assistant" description="Generate an offline, explainable remediation plan grounded in a stored WEBGUARD finding. No external AI service or API key is used." />
    <section className="panel assistant-launch"><div className="assistant-launch-icon"><Sparkles size={22} /></div><div className="assistant-launch-copy"><h3>{t('Analyze a security finding')}</h3><p>{t('Choose a finding to receive a prioritized impact summary, practical remediation steps and validation criteria.')}</p></div><div className="assistant-controls"><select value={findingId} onChange={e => setFindingId(e.target.value)}><option value="">{t('Select a finding')}</option>{findings.map(item => <option key={item.id} value={item.id}>#{item.id} · {item.asset_domain} · {item.check_id}</option>)}</select><button className="button-primary" disabled={!findingId || busy} onClick={() => void submit()}>{busy ? <RefreshCw size={15} className="spin" /> : <Sparkles size={15} />}{t('Generate guidance')}</button></div>{error && <div className="inline-error">{error}</div>}</section>
    {result && <div className="assistant-result"><section className="panel assistant-summary"><div className="assistant-result-head"><div><span className="eyebrow-text">{t('RULE-BASED ANALYSIS')}</span><h2>{result.title}</h2><span className="assistant-target">{result.asset_domain} · {result.check_id}</span></div><div className="assistant-priority"><small>{t('REMEDIATION PRIORITY')}</small><strong>{result.priority}</strong><span className={severityClass(result.severity)}>{t(result.severity)}</span></div></div><p>{result.summary}</p><div className="assistant-impact"><strong>{t('Business impact')}</strong><p>{result.business_impact}</p></div></section><div className="content-grid two-col"><section className="panel"><div className="panel-heading"><h3>{t('Recommended action plan')}</h3><ClipboardCheck size={17} /></div><ol className="assistant-steps">{result.remediation_steps.map((step, index) => <li key={index}><span>{index + 1}</span><p>{step}</p></li>)}</ol></section><section className="panel"><div className="panel-heading"><h3>{t('Validation criteria')}</h3><CheckCircle2 size={17} /></div><p className="assistant-validation">{result.validation_criteria}</p><div className="assistant-limitations"><strong>{t('Analysis limitations')}</strong><p>{result.limitations}</p><small>{result.engine} · {t('Offline rule-based')}</small></div></section></div></div>}
    {!result && <div className="info-strip"><ShieldCheck size={18} /><div><strong>{t('Evidence-grounded guidance')}</strong><span>{t('The assistant does not invent scan evidence, execute changes or claim exploitability. It explains known check categories and their recommended validation.')}</span></div></div>}
  </>
}

function ReportsPage({ reports, scans, canWrite, language, onCreate, onDownload }: { reports: Report[]; scans: Scan[]; canWrite: boolean; language: 'en' | 'fa'; onCreate: (id: number) => Promise<void>; onDownload: (id: number) => Promise<void> }) {
  const { t } = useI18n()
  const [scanId, setScanId] = useState('')
  const completed = scans.filter(s => s.status === 'completed')
  return <>
    <PageHeading eyebrow="REPORTING CENTER" title="Security reports" description="Generate portable PDF summaries with severity, evidence, remediation guidance and scope limitations." />
    {canWrite && <div className="report-create panel"><div className="report-create-icon"><FileBarChart2 size={24} /></div><div className="report-create-copy"><h3>{t('Generate assessment report')}</h3><p>{t('Choose a completed assessment to generate a downloadable PDF document.')} · {language === 'fa' ? t('Persian report') : t('English report')}</p></div><div className="report-create-controls"><select value={scanId} onChange={e => setScanId(e.target.value)}><option value="">{t('Select completed scan')}</option>{completed.map(s => <option value={s.id} key={s.id}>#{s.id} · {s.asset_domain} · {formatDate(s.finished_at)}</option>)}</select><button className="button-primary" disabled={!scanId} onClick={() => void onCreate(Number(scanId))}><Plus size={16} />{t('Generate PDF')}</button></div></div>}
    <div className="section-caption"><div><span className="eyebrow-text">{t('DOCUMENT LIBRARY')}</span><h3>{t('Generated reports')}<span className="count-bubble">{reports.length}</span></h3></div></div>
    {reports.length ? <div className="report-list">{reports.map(report => <div className="report-row" key={report.id}><div className="pdf-icon">PDF</div><div className="report-row-copy"><strong>{report.domain} — Assessment #{report.scan_id}</strong><span>{t('Generated')} {formatDate(report.created_at)}</span></div><span className="report-ready"><CheckCircle2 size={14} />{report.language === 'fa' ? t('Persian PDF') : t('English PDF')}</span><button className="button-secondary small-button" onClick={() => void onDownload(report.id)}><Download size={15} />{t('Download')}</button></div>)}</div> : <div className="panel"><EmptyState icon={FileBarChart2} title={t('No reports generated')} text="Completed assessments can be converted into a PDF security report." /></div>}
  </>
}

function TeamPage({ members, role, onAdd }: { members: Member[]; role: string; onAdd: (email: string, role: string) => Promise<void> }) {
  const { t } = useI18n()
  const [email, setEmail] = useState('')
  const [memberRole, setMemberRole] = useState('analyst')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  async function submit(e: FormEvent) { e.preventDefault(); setBusy(true); setErr(''); try { await onAdd(email, memberRole); setEmail('') } catch (error) { setErr(error instanceof Error ? error.message : t('Unable to save membership.')) } finally { setBusy(false) } }
  return <>
    <PageHeading eyebrow="IDENTITY & ACCESS" title="Team & access" description="Manage workspace membership and keep assessment permissions aligned with team responsibilities." />
    <div className="panel access-summary"><div className="access-summary-icon"><LockKeyhole size={20} /></div><div><strong>{t('Role-based access control')}</strong><p>{t('Owners and admins can manage membership. Analysts can manage assets and assessments. Viewers have read-only access.')}</p></div><span className="role-pill">{t('YOUR ROLE ·')} {t(role)}</span></div>
    {['owner', 'admin'].includes(role) && <form className="panel invite-form" onSubmit={submit}><div><h3>{t('Add existing user')}</h3><p>{t('The user must create an account before being added to this workspace.')}</p></div><input type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="teammate@company.com" required /><select value={memberRole} onChange={e => setMemberRole(e.target.value)}><option value="analyst">{t('Analyst')}</option><option value="viewer">{t('Viewer')}</option><option value="admin">{t('Admin')}</option></select><button className="button-primary" disabled={busy}><Plus size={15} />{t('Add member')}</button>{err && <div className="inline-error">{err}</div>}</form>}
    <div className="section-caption"><div><span className="eyebrow-text">{t('WORKSPACE MEMBERS')}</span><h3>{t('People')}<span className="count-bubble">{members.length}</span></h3></div></div>
    <div className="panel member-list">{members.map(member => <div className="member-row" key={member.id}><div className="avatar">{initials(member.full_name || member.email)}</div><div className="member-copy"><strong>{member.full_name || member.email.split('@')[0]}</strong><span>{member.email}</span></div><span className="role-pill">{t(member.role)}</span><span className="member-date">{t('Joined')} {formatDate(member.joined_at)}</span></div>)}{!members.length && <EmptyState icon={Users} title={t('No members')} text="Workspace membership will appear here." />}</div>
  </>
}

function AuditPage({ rows, role }: { rows: Audit[]; role: string }) {
  const { t } = useI18n()
  if (!['owner', 'admin'].includes(role)) return <><PageHeading eyebrow="GOVERNANCE" title={t('Audit trail')} description="A record of key workspace and assessment actions." /><div className="panel"><EmptyState icon={LockKeyhole} title={t('Administrator access required')} text="Only workspace owners and admins can view the audit trail." /></div></>
  return <><PageHeading eyebrow="GOVERNANCE & ACCOUNTABILITY" title={t('Audit trail')} description="A chronological log of security-sensitive actions performed in this workspace." /><div className="panel table-panel"><div className="table-wrap"><table><thead><tr><th>{t('ACTOR')}</th><th>{t('ACTION')}</th><th>{t('OBJECT')}</th><th>{t('DETAILS')}</th><th>{t('TIMESTAMP')}</th></tr></thead><tbody>{rows.map(row => <tr key={row.id}><td><strong>{row.actor}</strong></td><td><span className="audit-action">{row.action}</span></td><td>{row.object_type || '—'} {row.object_id && `#${row.object_id}`}</td><td><code>{JSON.stringify(row.metadata)}</code></td><td className="date-cell">{formatDate(row.created_at)}</td></tr>)}</tbody></table>{!rows.length && <EmptyState icon={ClipboardCheck} title={t('No activity yet')} text="Workspace events will be recorded here." />}</div></div></>
}

type PersonalizationPageProps = {
  preferences: UserPreferences
  onChange: (changes: Partial<UserPreferences>) => void
  onReset: () => void
  onExport: () => void
  onImport: (file: File) => Promise<void>
  onPreset: (preset: 'analyst' | 'executive' | 'minimal') => void
}

const widgetDetails: { id: DashboardWidget; title: string; detail: string }[] = [
  { id: 'snapshot', title: 'Security posture snapshot', detail: 'The security score and baseline summary.' },
  { id: 'metrics', title: 'Key metrics', detail: 'Asset, assessment and finding counters.' },
  { id: 'risk', title: 'Risk distribution', detail: 'Open findings grouped by severity.' },
  { id: 'assets', title: 'Verified assets', detail: 'A quick list of verified domains.' },
  { id: 'activity', title: 'Recent assessments', detail: 'The latest assessment activity.' },
  { id: 'footnote', title: 'Scope and safety note', detail: 'The passive assessment scope reminder.' },
]

const navigationDetails: { id: NavigationItem; title: string; detail: string; group: 'Workspace' | 'Security' | 'Administration' }[] = [
  { id: 'overview', title: 'Overview', detail: 'Your security posture and workspace summary.', group: 'Workspace' },
  { id: 'assets', title: 'Assets', detail: 'Verified domains and ownership challenges.', group: 'Workspace' },
  { id: 'scans', title: 'Assessments', detail: 'Scan queue, history and comparisons.', group: 'Workspace' },
  { id: 'findings', title: 'Findings', detail: 'Security issues and remediation tracking.', group: 'Security' },
  { id: 'insights', title: 'Security insights', detail: 'Risk trends and assessment analytics.', group: 'Security' },
  { id: 'assistant', title: 'Security assistant', detail: 'Offline, evidence-based remediation guidance.', group: 'Security' },
  { id: 'reports', title: 'Reports', detail: 'Generated PDF reports and downloads.', group: 'Security' },
  { id: 'team', title: 'Team & access', detail: 'Workspace members and assigned roles.', group: 'Administration' },
  { id: 'audit', title: 'Audit trail', detail: 'Administrative activity and accountability.', group: 'Administration' },
]

function PersonalizationPage({ preferences, onChange, onReset, onExport, onImport, onPreset }: PersonalizationPageProps) {
  const { t } = useI18n()
  const [importError, setImportError] = useState('')
  const [importSuccess, setImportSuccess] = useState(false)

  async function handleImport(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file) return
    setImportError('')
    setImportSuccess(false)
    if (file.size > 128 * 1024) { setImportError(t('Settings file is too large.')); return }
    try {
      await onImport(file)
      setImportSuccess(true)
    } catch (error) {
      setImportError(error instanceof Error ? t(error.message) : t('Could not import settings.'))
    }
  }

  function toggleWidget(id: DashboardWidget, checked: boolean) {
    const next = checked ? [...preferences.dashboardWidgets, id] : preferences.dashboardWidgets.filter(item => item !== id)
    onChange({ dashboardWidgets: next })
  }

  function moveWidget(id: DashboardWidget, direction: -1 | 1) {
    const current = [...preferences.dashboardOrder]
    const index = current.indexOf(id)
    const target = index + direction
    if (index < 0 || target < 0 || target >= current.length) return
    ;[current[index], current[target]] = [current[target], current[index]]
    onChange({ dashboardOrder: current })
  }

  function toggleNavigation(id: NavigationItem, checked: boolean) {
    if (id === 'overview' && !checked) return
    const next = checked ? [...preferences.navigationItems, id] : preferences.navigationItems.filter(item => item !== id)
    onChange({ navigationItems: next })
  }

  function moveNavigation(id: NavigationItem, direction: -1 | 1) {
    const current = [...preferences.navigationOrder]
    const index = current.indexOf(id)
    const target = index + direction
    if (index < 0 || target < 0 || target >= current.length) return
    const currentGroup = navigationDetails.find(entry => entry.id === id)?.group
    const targetGroup = navigationDetails.find(entry => entry.id === current[target])?.group
    if (!currentGroup || currentGroup !== targetGroup) return
    ;[current[index], current[target]] = [current[target], current[index]]
    onChange({ navigationOrder: current })
  }

  const accentOptions: { id: UserPreferences['accent']; color: string; label: string }[] = [
    { id: 'blue', color: '#3d9cf4', label: 'Ocean blue' },
    { id: 'cyan', color: '#20c5d7', label: 'Arctic cyan' },
    { id: 'violet', color: '#9b7cff', label: 'Electric violet' },
    { id: 'emerald', color: '#18b981', label: 'Emerald' },
    { id: 'rose', color: '#f06f96', label: 'Rose' },
    { id: 'amber', color: '#e6a33c', label: 'Amber' },
  ]
  const themeOptions: { id: UserPreferences['theme']; label: string; detail: string; swatches: string[] }[] = [
    { id: 'midnight', label: 'Midnight', detail: 'Deep navy · high contrast', swatches: ['#080d17', '#12253d', '#3d9cf4'] },
    { id: 'graphite', label: 'Graphite', detail: 'Neutral charcoal · calm', swatches: ['#17191f', '#282d38', '#8a9bb5'] },
    { id: 'light', label: 'Light', detail: 'Bright canvas · daylight', swatches: ['#f2f5fa', '#ffffff', '#337bd4'] },
  ]
  return <>
    <PageHeading eyebrow="YOUR WORKSPACE, YOUR RULES" title="Personalization studio" description="Shape the workspace around the way you work. Your preferences are saved in this browser and can be exported to another device." />
    <div className="personalization-hero panel">
      <div className="personalization-hero-icon"><Palette size={22} /></div>
      <div className="personalization-hero-copy"><span className="eyebrow-text">{t('PERSONAL WORKSPACE')}</span><h2>{t('Make WEBGUARD feel like yours.')}</h2><p>{t('Tune the visual system, navigation, density and dashboard layout without changing security data or workspace permissions.')}</p></div>
      <div className="personalization-live"><span className="live-dot" />{t('Changes apply instantly')}</div>
    </div>

    <div className="personalization-grid">
      <div className="personalization-main">
        <section className="panel customization-section">
          <div className="custom-section-heading"><div className="custom-section-icon"><Monitor size={18} /></div><div><h3>{t('Appearance')}</h3><p>{t('Choose the canvas and accent that define your workspace.')}</p></div></div>
          <div className="custom-label-row"><strong>{t('Color theme')}</strong><span>{t('Switch the full interface palette')}</span></div>
          <div className="theme-options">{themeOptions.map(theme => <button type="button" key={theme.id} className={`theme-option ${preferences.theme === theme.id ? 'selected' : ''}`} aria-pressed={preferences.theme === theme.id} onClick={() => onChange({ theme: theme.id })}><span className="theme-preview" style={{ background: theme.swatches[0] }}><i style={{ background: theme.swatches[1] }} /><b style={{ background: theme.swatches[2] }} /></span><span className="theme-option-copy"><strong>{t(theme.label)}</strong><small>{t(theme.detail)}</small></span><span className="theme-selected-mark"><Check size={13} /></span></button>)}</div>
          <div className="custom-divider" />
          <div className="custom-label-row"><strong>{t('Accent color')}</strong><span>{t('Used for active navigation and primary actions')}</span></div>
          <div className="accent-options">{accentOptions.map(option => <button type="button" key={option.id} className={`accent-swatch ${preferences.accent === option.id ? 'selected' : ''}`} style={{ '--swatch': option.color } as CSSProperties} aria-label={t(option.label)} aria-pressed={preferences.accent === option.id} title={t(option.label)} onClick={() => onChange({ accent: option.id })}><span /><Check size={13} /></button>)}</div>
        </section>

        <section className="panel customization-section">
          <div className="custom-section-heading"><div className="custom-section-icon"><Settings2 size={18} /></div><div><h3>{t('Layout and density')}</h3><p>{t('Control how much information fits on screen and how the workspace is arranged.')}</p></div></div>
          <div className="custom-field-grid">
            <ChoiceField title="Interface density" description="Space between controls and cards" value={preferences.density} choices={[['compact', 'Compact'], ['comfortable', 'Comfortable'], ['spacious', 'Spacious']]} onChange={value => onChange({ density: value as UserPreferences['density'] })} t={t} />
            <ChoiceField title="Sidebar width" description="Keep labels visible or prioritize canvas space" value={preferences.sidebar} choices={[['expanded', 'Expanded'], ['compact', 'Compact']]} onChange={value => onChange({ sidebar: value as UserPreferences['sidebar'] })} t={t} />
            <ChoiceField title="Content width" description="Choose the maximum page canvas width" value={preferences.contentWidth} choices={[['standard', 'Standard'], ['wide', 'Wide']]} onChange={value => onChange({ contentWidth: value as UserPreferences['contentWidth'] })} t={t} />
            <ChoiceField title="Corner style" description="Adjust the shape of cards and controls" value={preferences.corners} choices={[['sharp', 'Sharp'], ['balanced', 'Balanced'], ['rounded', 'Rounded']]} onChange={value => onChange({ corners: value as UserPreferences['corners'] })} t={t} />
            <ChoiceField title="Text size" description="Improve readability across the interface" value={preferences.fontSize} choices={[['small', 'Small'], ['standard', 'Standard'], ['large', 'Large']]} onChange={value => onChange({ fontSize: value as UserPreferences['fontSize'] })} t={t} />
            <ChoiceField title="Font family" description="Choose a system font with Persian support" value={preferences.font} choices={[['system', 'System'], ['segoe', 'Segoe UI'], ['tahoma', 'Tahoma']]} onChange={value => onChange({ font: value as UserPreferences['font'] })} t={t} />
          </div>
          <label className="preference-toggle"><span className="preference-toggle-icon"><Type size={17} /></span><span className="preference-toggle-copy"><strong>{t('Reduce motion')}</strong><small>{t('Minimize transitions and animations for a calmer interface.')}</small></span><input type="checkbox" checked={preferences.reduceMotion} onChange={event => onChange({ reduceMotion: event.target.checked })} /><i /></label>
        </section>

        <section className="panel customization-section">
          <div className="custom-section-heading"><div className="custom-section-icon"><LayoutDashboard size={18} /></div><div><h3>{t('Dashboard builder')}</h3><p>{t('Choose what appears on Overview, then arrange the cards in your preferred order.')}</p></div></div>
          <ChoiceField title="Dashboard columns" description="Wide screens only; mobile remains single-column" value={String(preferences.dashboardColumns)} choices={[[ '1', 'One column' ], ['2', 'Two columns']]} onChange={value => onChange({ dashboardColumns: value === '1' ? 1 : 2 })} t={t} />
          <div className="widget-list">{preferences.dashboardOrder.map((id, index) => {
            const item = widgetDetails.find(widget => widget.id === id)!
            const enabled = preferences.dashboardWidgets.includes(id)
            return <div className={`widget-config-row ${enabled ? '' : 'is-disabled'}`} key={id}><label className="widget-config-main"><input type="checkbox" checked={enabled} onChange={event => toggleWidget(id, event.target.checked)} /><span className="widget-checkmark"><Check size={12} /></span><span><strong>{t(item.title)}</strong><small>{t(item.detail)}</small></span></label><div className="widget-order-controls"><span>{index + 1}</span><button type="button" className="icon-button" title={t('Move up')} aria-label={`${t('Move up')}: ${t(item.title)}`} disabled={index === 0} onClick={() => moveWidget(id, -1)}><ChevronUp size={15} /></button><button type="button" className="icon-button" title={t('Move down')} aria-label={`${t('Move down')}: ${t(item.title)}`} disabled={index === preferences.dashboardOrder.length - 1} onClick={() => moveWidget(id, 1)}><ChevronDown size={15} /></button></div></div>
          })}</div>
          <div className="widget-list-footnote">{t('Hidden widgets stay saved and can be restored at any time.')}</div>
        </section>

        <section className="panel customization-section">
          <div className="custom-section-heading"><div className="custom-section-icon"><PanelRight size={18} /></div><div><h3>{t('Navigation builder')}</h3><p>{t('Hide pages you do not use and arrange the sidebar around your workflow. Personalization always stays available.')}</p></div></div>
          <div className="widget-list navigation-config-list">{preferences.navigationOrder.map((id, index) => {
            const item = navigationDetails.find(entry => entry.id === id)!
            const enabled = preferences.navigationItems.includes(id)
            const required = id === 'overview'
            return <div className={`widget-config-row ${enabled ? '' : 'is-disabled'}`} key={id}><label className="widget-config-main"><input type="checkbox" checked={enabled} disabled={required} onChange={event => toggleNavigation(id, event.target.checked)} /><span className="widget-checkmark"><Check size={12} /></span><span><strong>{t(item.title)}</strong><small>{t(item.detail)}</small></span></label><div className="widget-order-controls"><span>{index + 1}</span><button type="button" className="icon-button" title={t('Move up within section')} aria-label={`${t('Move up')}: ${t(item.title)}`} disabled={index === 0 || navigationDetails.find(entry => entry.id === preferences.navigationOrder[index - 1])?.group !== item.group} onClick={() => moveNavigation(id, -1)}><ChevronUp size={15} /></button><button type="button" className="icon-button" title={t('Move down within section')} aria-label={`${t('Move down')}: ${t(item.title)}`} disabled={index === preferences.navigationOrder.length - 1 || navigationDetails.find(entry => entry.id === preferences.navigationOrder[index + 1])?.group !== item.group} onClick={() => moveNavigation(id, 1)}><ChevronDown size={15} /></button></div></div>
          })}</div>
          <div className="widget-list-footnote">{t('Overview cannot be hidden. The Personalization studio remains available so you can always restore your navigation.')}</div>
        </section>
      </div>

      <aside className="personalization-aside">
        <section className="panel live-preview-panel">
          <div className="panel-heading"><div><span className="eyebrow-text">{t('LIVE PREVIEW')}</span><h3>{t('Your current style')}</h3></div><span className="preview-live-pill">{t('LIVE')}</span></div>
          <div className={`mini-preview mini-preview-${preferences.theme}`} data-accent={preferences.accent}>
            <div className="mini-preview-top"><span /><span /><span /><b>WEBGUARD</b></div>
            <div className="mini-preview-body"><div className="mini-preview-sidebar"><i /><i /><i className="active" /><i /><i /></div><div className="mini-preview-content"><div className="mini-preview-heading" /><div className="mini-preview-cards"><i /><i /><i /></div><div className="mini-preview-panel"><i /><i /><i /></div></div></div>
          </div>
          <div className="preview-meta"><span>{t('Theme')}<strong>{t(preferences.theme === 'midnight' ? 'Midnight' : preferences.theme === 'graphite' ? 'Graphite' : 'Light')}</strong></span><span>{t('Accent')}<strong>{t(accentOptions.find(option => option.id === preferences.accent)?.label || 'Ocean blue')}</strong></span><span>{t('Density')}<strong>{t(preferences.density === 'compact' ? 'Compact' : preferences.density === 'spacious' ? 'Spacious' : 'Comfortable')}</strong></span></div>
        </section>
        <section className="panel preset-panel">
          <div className="panel-heading"><div><span className="eyebrow-text">{t('QUICK START')}</span><h3>{t('Curated profiles')}</h3></div><Sparkles size={17} /></div>
          <button type="button" className="preset-button" onClick={() => onPreset('analyst')}><span className="preset-avatar preset-analyst"><Shield size={16} /></span><span><strong>{t('Security analyst')}</strong><small>{t('Dense, data-first workspace')}</small></span><ArrowRight size={15} /></button>
          <button type="button" className="preset-button" onClick={() => onPreset('executive')}><span className="preset-avatar preset-executive"><Activity size={16} /></span><span><strong>{t('Executive')}</strong><small>{t('Balanced overview and insights')}</small></span><ArrowRight size={15} /></button>
          <button type="button" className="preset-button" onClick={() => onPreset('minimal')}><span className="preset-avatar preset-minimal"><LayoutDashboard size={16} /></span><span><strong>{t('Minimal')}</strong><small>{t('Bright, focused and compact navigation')}</small></span><ArrowRight size={15} /></button>
        </section>
        <section className="panel preferences-transfer">
          <div className="panel-heading"><div><span className="eyebrow-text">{t('PORTABILITY')}</span><h3>{t('Your preferences')}</h3></div><PanelRight size={17} /></div>
          <p>{t('Export your current setup or import a WEBGUARD settings JSON file on another device.')}</p>
          <button type="button" className="button-secondary full-button" onClick={onExport}><Download size={15} />{t('Export settings')}</button>
          <label className="button-secondary full-button import-settings-button"><Upload size={15} />{t('Import settings')}<input type="file" accept="application/json,.json" onChange={event => void handleImport(event)} /></label>
          {importError && <div className="inline-error" role="alert">{importError}</div>}
          {importSuccess && <div className="import-success" role="status"><Check size={14} />{t('Settings imported successfully.')}</div>}
          <button type="button" className="text-button reset-preferences" onClick={() => { if (window.confirm(t('Reset all appearance and dashboard preferences to defaults?'))) onReset() }}><RotateCcw size={14} />{t('Reset to defaults')}</button>
        </section>
      </aside>
    </div>
  </>
}

function ChoiceField({ title, description, value, choices, onChange, t }: { title: string; description: string; value: string; choices: [string, string][]; onChange: (value: string) => void; t: (value: string) => string }) {
  return <div className="choice-field"><div><strong>{t(title)}</strong><small>{t(description)}</small></div><div className="choice-buttons" role="group" aria-label={t(title)}>{choices.map(([id, label]) => <button type="button" key={id} className={value === id ? 'selected' : ''} aria-pressed={value === id} onClick={() => onChange(id)}>{t(label)}</button>)}</div></div>
}

function VerificationModal({ verification, busy, error, onVerify, onClose }: { verification: Verification; busy: boolean; error: string; onVerify: () => Promise<void>; onClose: () => void }) {
  const { t } = useI18n()
  const [copied, setCopied] = useState('')
  const [copyError, setCopyError] = useState('')
  async function copy(value: string, key: string) {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(key)
      setCopyError('')
      window.setTimeout(() => setCopied(''), 1800)
    } catch {
      setCopyError(t('Clipboard access is unavailable. Select and copy the value manually.'))
    }
  }
  return <div className="modal-backdrop" role="presentation" onMouseDown={e => { if (e.target === e.currentTarget && !busy) onClose() }}>
    <div className="verification-modal" role="dialog" aria-modal="true" aria-labelledby="verify-title">
      <div className="modal-top"><div className="modal-icon"><Fingerprint size={21} /></div><button className="icon-button" onClick={onClose} disabled={busy} aria-label={t('Close')}><X size={18} /></button></div>
      <div className="eyebrow-text">{t('DOMAIN OWNERSHIP VERIFICATION')}</div>
      <h2 id="verify-title">{t('Prove control of')} {verification.domain}</h2>
      <p className="modal-intro">{t('Create the DNS TXT record below at your authoritative DNS provider. This proves control of the domain before any network assessment is permitted.')}</p>
      <div className="verification-provider-hint"><strong>{t('Before you continue')}</strong><span>{t('This challenge is not verified automatically. Add the TXT record at your DNS provider, wait for DNS publication, then click Verify DNS record.')}</span></div>
      <div className="dns-field"><label>{t('RECORD TYPE')}</label><div><strong>{verification.record_type}</strong></div></div>
      <div className="dns-field"><label>{t('HOST / NAME')}</label><div><code>{verification.record_name}</code><button className="copy-button" onClick={() => void copy(verification.record_name, 'name')}>{copied === 'name' ? <CheckCircle2 size={15} /> : <ClipboardCheck size={15} />}{t(copied === 'name' ? 'Copied' : 'Copy')}</button></div></div>
      <div className="dns-field"><label>{t('TXT VALUE')}</label><div><code>{verification.expected_value}</code><button className="copy-button" onClick={() => void copy(verification.expected_value, 'value')}>{copied === 'value' ? <CheckCircle2 size={15} /> : <ClipboardCheck size={15} />}{t(copied === 'value' ? 'Copied' : 'Copy')}</button></div></div>
      <p className="verification-host-hint">{t('If your DNS provider automatically appends the domain name, enter only _webguard-verify in the Host field.')}</p>
      {copyError && <div className="inline-error verification-error" role="status"><AlertTriangle size={15} />{copyError}</div>}
      <div className="verification-note"><Clock3 size={15} /><span>{t('DNS propagation can take several minutes depending on your provider and TTL.')}</span></div>
      {error && <div className="inline-error verification-error" role="alert"><AlertTriangle size={15} /><span>{error}</span></div>}
      <div className="modal-actions"><button className="button-secondary" onClick={onClose} disabled={busy}>{t('Close')}</button><button className="button-primary" onClick={() => void onVerify()} disabled={busy}>{busy ? <RefreshCw size={15} className="spin" /> : <><ShieldCheck size={16} />{t('Verify DNS record')}</>}</button></div>
    </div>
  </div>
}
