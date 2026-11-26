export type ThemeName = 'midnight' | 'graphite' | 'light'
export type AccentName = 'blue' | 'cyan' | 'violet' | 'emerald' | 'rose' | 'amber'
export type DensityName = 'compact' | 'comfortable' | 'spacious'
export type FontName = 'system' | 'segoe' | 'tahoma'
export type FontSizeName = 'small' | 'standard' | 'large'
export type CornerName = 'sharp' | 'balanced' | 'rounded'
export type SidebarName = 'expanded' | 'compact'
export type ContentWidthName = 'standard' | 'wide'
export type DashboardWidget = 'snapshot' | 'metrics' | 'risk' | 'assets' | 'activity' | 'footnote'
export type NavigationItem = 'overview' | 'assets' | 'scans' | 'findings' | 'insights' | 'assistant' | 'reports' | 'team' | 'audit'

export interface UserPreferences {
  version: 1
  theme: ThemeName
  accent: AccentName
  density: DensityName
  font: FontName
  fontSize: FontSizeName
  corners: CornerName
  sidebar: SidebarName
  contentWidth: ContentWidthName
  dashboardColumns: 1 | 2
  reduceMotion: boolean
  dashboardWidgets: DashboardWidget[]
  dashboardOrder: DashboardWidget[]
  navigationItems: NavigationItem[]
  navigationOrder: NavigationItem[]
}

export const PREFERENCES_STORAGE_KEY = 'webguard-preferences-v1'

export const DEFAULT_PREFERENCES: UserPreferences = {
  version: 1,
  theme: 'midnight',
  accent: 'blue',
  density: 'comfortable',
  font: 'system',
  fontSize: 'standard',
  corners: 'balanced',
  sidebar: 'expanded',
  contentWidth: 'standard',
  dashboardColumns: 2,
  reduceMotion: false,
  dashboardWidgets: ['snapshot', 'metrics', 'risk', 'assets', 'activity', 'footnote'],
  dashboardOrder: ['snapshot', 'metrics', 'risk', 'assets', 'activity', 'footnote'],
  navigationItems: ['overview', 'assets', 'scans', 'findings', 'insights', 'assistant', 'reports', 'team', 'audit'],
  navigationOrder: ['overview', 'assets', 'scans', 'findings', 'insights', 'assistant', 'reports', 'team', 'audit'],
}

const choices = {
  theme: ['midnight', 'graphite', 'light'],
  accent: ['blue', 'cyan', 'violet', 'emerald', 'rose', 'amber'],
  density: ['compact', 'comfortable', 'spacious'],
  font: ['system', 'segoe', 'tahoma'],
  fontSize: ['small', 'standard', 'large'],
  corners: ['sharp', 'balanced', 'rounded'],
  sidebar: ['expanded', 'compact'],
  contentWidth: ['standard', 'wide'],
  dashboardWidget: ['snapshot', 'metrics', 'risk', 'assets', 'activity', 'footnote'],
  navigationItem: ['overview', 'assets', 'scans', 'findings', 'insights', 'assistant', 'reports', 'team', 'audit'],
} as const

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function choose<T extends string>(value: unknown, allowed: readonly T[], fallback: T): T {
  return typeof value === 'string' && (allowed as readonly string[]).includes(value) ? value as T : fallback
}

function uniqueWidgets(value: unknown, fallback: DashboardWidget[]): DashboardWidget[] {
  if (!Array.isArray(value)) return [...fallback]
  const picked = value.filter((item): item is DashboardWidget =>
    typeof item === 'string' && (choices.dashboardWidget as readonly string[]).includes(item),
  )
  return [...new Set(picked)]
}

function uniqueNavigation(value: unknown, fallback: NavigationItem[]): NavigationItem[] {
  if (!Array.isArray(value)) return [...fallback]
  const picked = value.filter((item): item is NavigationItem =>
    typeof item === 'string' && (choices.navigationItem as readonly string[]).includes(item),
  )
  return [...new Set(picked)]
}

function navigationGroupRank(item: NavigationItem): number {
  if (item === 'overview' || item === 'assets' || item === 'scans') return 0
  if (item === 'findings' || item === 'insights' || item === 'assistant' || item === 'reports') return 1
  return 2
}

export function normalizePreferences(value: unknown): UserPreferences {
  if (!isRecord(value)) return { ...DEFAULT_PREFERENCES, dashboardWidgets: [...DEFAULT_PREFERENCES.dashboardWidgets], dashboardOrder: [...DEFAULT_PREFERENCES.dashboardOrder], navigationItems: [...DEFAULT_PREFERENCES.navigationItems], navigationOrder: [...DEFAULT_PREFERENCES.navigationOrder] }
  const dashboardWidgets = uniqueWidgets(value.dashboardWidgets, DEFAULT_PREFERENCES.dashboardWidgets)
  const suppliedOrder = uniqueWidgets(value.dashboardOrder, DEFAULT_PREFERENCES.dashboardOrder)
  const dashboardOrder = [...suppliedOrder, ...choices.dashboardWidget.filter(item => !suppliedOrder.includes(item))]
  const navigationItems = uniqueNavigation(value.navigationItems, DEFAULT_PREFERENCES.navigationItems)
  if (!navigationItems.includes('overview')) navigationItems.unshift('overview')
  const suppliedNavigationOrder = uniqueNavigation(value.navigationOrder, DEFAULT_PREFERENCES.navigationOrder)
  const completeNavigationOrder = [...suppliedNavigationOrder, ...choices.navigationItem.filter(item => !suppliedNavigationOrder.includes(item))]
  const navigationPosition = new Map(completeNavigationOrder.map((item, index) => [item, index]))
  const navigationOrder = [...completeNavigationOrder].sort((a, b) => navigationGroupRank(a) - navigationGroupRank(b) || (navigationPosition.get(a) ?? 0) - (navigationPosition.get(b) ?? 0))
  return {
    version: 1,
    theme: choose(value.theme, choices.theme, DEFAULT_PREFERENCES.theme),
    accent: choose(value.accent, choices.accent, DEFAULT_PREFERENCES.accent),
    density: choose(value.density, choices.density, DEFAULT_PREFERENCES.density),
    font: choose(value.font, choices.font, DEFAULT_PREFERENCES.font),
    fontSize: choose(value.fontSize, choices.fontSize, DEFAULT_PREFERENCES.fontSize),
    corners: choose(value.corners, choices.corners, DEFAULT_PREFERENCES.corners),
    sidebar: choose(value.sidebar, choices.sidebar, DEFAULT_PREFERENCES.sidebar),
    contentWidth: choose(value.contentWidth, choices.contentWidth, DEFAULT_PREFERENCES.contentWidth),
    dashboardColumns: value.dashboardColumns === 1 ? 1 : 2,
    reduceMotion: value.reduceMotion === true,
    dashboardWidgets,
    dashboardOrder,
    navigationItems,
    navigationOrder,
  }
}

export function parsePreferencesJson(text: string): UserPreferences {
  const parsed: unknown = JSON.parse(text)
  if (!isRecord(parsed)) throw new Error('The settings file must contain a JSON object.')
  if (parsed.version !== 1) throw new Error('Unsupported settings version. Export a new settings file from this WEBGUARD version.')
  return normalizePreferences(parsed)
}

export function serializePreferences(value: unknown): string {
  return `${JSON.stringify(normalizePreferences(value), null, 2)}\n`
}

function storageKey(userId?: number): string {
  return typeof userId === 'number' && Number.isFinite(userId) && userId > 0
    ? `${PREFERENCES_STORAGE_KEY}-user-${userId}`
    : PREFERENCES_STORAGE_KEY
}

export function loadPreferences(userId?: number): UserPreferences {
  try {
    const stored = window.localStorage.getItem(storageKey(userId))
    if (!stored) return normalizePreferences(DEFAULT_PREFERENCES)
    return normalizePreferences(JSON.parse(stored) as unknown)
  } catch {
    return normalizePreferences(DEFAULT_PREFERENCES)
  }
}

export function persistPreferences(value: unknown, userId?: number): void {
  try {
    window.localStorage.setItem(storageKey(userId), serializePreferences(value))
  } catch {
    // Keep the in-memory experience usable when browser storage is unavailable or full.
  }
}
