import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import ts from 'typescript'

const source = await readFile(new URL('../src/preferences.ts', import.meta.url), 'utf8')
const compiled = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 },
}).outputText
const moduleUrl = `data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`
const preferencesModule = await import(moduleUrl)
const {
  DEFAULT_PREFERENCES,
  normalizePreferences,
  parsePreferencesJson,
  serializePreferences,
  loadPreferences,
  persistPreferences,
} = preferencesModule

test('defaults are complete and independently cloned', () => {
  const first = normalizePreferences(DEFAULT_PREFERENCES)
  const second = normalizePreferences(DEFAULT_PREFERENCES)
  assert.deepEqual(first, DEFAULT_PREFERENCES)
  assert.notEqual(first.dashboardWidgets, second.dashboardWidgets)
  assert.notEqual(first.dashboardOrder, second.dashboardOrder)
  assert.notEqual(first.navigationItems, second.navigationItems)
  assert.notEqual(first.navigationOrder, second.navigationOrder)
})

test('all supported themes, accents, density and font modes survive normalization', () => {
  for (const theme of ['midnight', 'graphite', 'light']) {
    assert.equal(normalizePreferences({ theme }).theme, theme)
  }
  for (const accent of ['blue', 'cyan', 'violet', 'emerald', 'rose', 'amber']) {
    assert.equal(normalizePreferences({ accent }).accent, accent)
  }
  for (const density of ['compact', 'comfortable', 'spacious']) {
    assert.equal(normalizePreferences({ density }).density, density)
  }
  for (const font of ['system', 'segoe', 'tahoma']) {
    assert.equal(normalizePreferences({ font }).font, font)
  }
})

test('every visual and layout mode is accepted and normalized', () => {
  for (const fontSize of ['small', 'standard', 'large']) assert.equal(normalizePreferences({ fontSize }).fontSize, fontSize)
  for (const corners of ['sharp', 'balanced', 'rounded']) assert.equal(normalizePreferences({ corners }).corners, corners)
  for (const sidebar of ['expanded', 'compact']) assert.equal(normalizePreferences({ sidebar }).sidebar, sidebar)
  for (const contentWidth of ['standard', 'wide']) assert.equal(normalizePreferences({ contentWidth }).contentWidth, contentWidth)
  assert.equal(normalizePreferences({ dashboardColumns: 1 }).dashboardColumns, 1)
  assert.equal(normalizePreferences({ dashboardColumns: 2 }).dashboardColumns, 2)
  assert.equal(normalizePreferences({ reduceMotion: true }).reduceMotion, true)
  assert.equal(normalizePreferences({ reduceMotion: false }).reduceMotion, false)
})

test('all supported appearance combinations preserve only allow-listed values', () => {
  const dimensions = [
    ['midnight', 'graphite', 'light'],
    ['blue', 'cyan', 'violet', 'emerald', 'rose', 'amber'],
    ['compact', 'comfortable', 'spacious'],
    ['system', 'segoe', 'tahoma'],
    ['small', 'standard', 'large'],
    ['sharp', 'balanced', 'rounded'],
    ['expanded', 'compact'],
    ['standard', 'wide'],
    [1, 2],
    [true, false],
  ]
  let checked = 0
  for (const theme of dimensions[0]) for (const accent of dimensions[1])
  for (const density of dimensions[2]) for (const font of dimensions[3])
  for (const fontSize of dimensions[4]) for (const corners of dimensions[5])
  for (const sidebar of dimensions[6]) for (const contentWidth of dimensions[7])
  for (const dashboardColumns of dimensions[8]) for (const reduceMotion of dimensions[9]) {
    const result = normalizePreferences({ theme, accent, density, font, fontSize, corners, sidebar, contentWidth, dashboardColumns, reduceMotion })
    assert.equal(result.theme, theme)
    assert.equal(result.accent, accent)
    assert.equal(result.density, density)
    assert.equal(result.font, font)
    assert.equal(result.fontSize, fontSize)
    assert.equal(result.corners, corners)
    assert.equal(result.sidebar, sidebar)
    assert.equal(result.contentWidth, contentWidth)
    assert.equal(result.dashboardColumns, dashboardColumns)
    assert.equal(result.reduceMotion, reduceMotion)
    checked += 1
  }
  assert.equal(checked, 23328)
})

test('unsupported and malformed imported values fall back safely', () => {
  const result = normalizePreferences({ theme: 'remote-theme', accent: 'red', density: 'huge', font: 'external-font', dashboardColumns: 9, reduceMotion: 'yes' })
  assert.equal(result.theme, DEFAULT_PREFERENCES.theme)
  assert.equal(result.accent, DEFAULT_PREFERENCES.accent)
  assert.equal(result.density, DEFAULT_PREFERENCES.density)
  assert.equal(result.font, DEFAULT_PREFERENCES.font)
  assert.equal(result.dashboardColumns, 2)
  assert.equal(result.reduceMotion, false)
  assert.deepEqual(normalizePreferences(null), DEFAULT_PREFERENCES)
  assert.deepEqual(normalizePreferences(['invalid']), DEFAULT_PREFERENCES)
})

test('dashboard order filters unknown ids, removes duplicates and restores missing widgets', () => {
  const result = normalizePreferences({ dashboardOrder: ['risk', 'risk', 'unsafe', 'activity'] })
  assert.equal(new Set(result.dashboardOrder).size, 6)
  assert.equal(result.dashboardOrder[0], 'risk')
  assert.equal(result.dashboardOrder[1], 'activity')
  assert.deepEqual(result.dashboardWidgets, DEFAULT_PREFERENCES.dashboardWidgets)
})

test('dashboard visibility can be empty without destroying the saved order', () => {
  const result = normalizePreferences({ dashboardWidgets: [], dashboardOrder: ['assets', 'risk'] })
  assert.deepEqual(result.dashboardWidgets, [])
  assert.equal(result.dashboardOrder[0], 'assets')
  assert.equal(result.dashboardOrder[1], 'risk')
  assert.equal(result.dashboardOrder.length, 6)
})

test('export and import round-trip preserves the complete preferences profile', () => {
  const custom = normalizePreferences({
    theme: 'light', accent: 'violet', density: 'spacious', font: 'tahoma', fontSize: 'large',
    corners: 'rounded', sidebar: 'compact', contentWidth: 'wide', dashboardColumns: 1,
    reduceMotion: true, dashboardWidgets: ['risk', 'activity'], dashboardOrder: ['activity', 'risk'],
  })
  const imported = parsePreferencesJson(serializePreferences(custom))
  assert.deepEqual(imported, custom)
})

test('import rejects malformed JSON and unsupported schema versions', () => {
  assert.throws(() => parsePreferencesJson('{not-json'), SyntaxError)
  assert.throws(() => parsePreferencesJson(JSON.stringify({ version: 2 })), /Unsupported settings version/)
  assert.throws(() => parsePreferencesJson(JSON.stringify(['not', 'an', 'object'])), /JSON object/)
})

test('import ignores unknown properties and never accepts them into the stored profile', () => {
  const imported = parsePreferencesJson(JSON.stringify({ version: 1, theme: 'graphite', serverCommand: 'rm -rf', accessToken: 'secret' }))
  assert.equal(imported.theme, 'graphite')
  assert.equal('serverCommand' in imported, false)
  assert.equal('accessToken' in imported, false)
})


test('navigation visibility and ordering are normalized safely', () => {
  const result = normalizePreferences({
    navigationItems: ['reports', 'reports', 'unknown'],
    navigationOrder: ['audit', 'assets', 'audit', 'unsafe'],
  })
  assert.deepEqual(result.navigationItems, ['overview', 'reports'])
  assert.equal(new Set(result.navigationOrder).size, 9)
  assert.equal(result.navigationOrder[0], 'assets')
  assert.ok(result.navigationOrder.indexOf('findings') < result.navigationOrder.indexOf('audit'))
  assert.ok(result.navigationOrder.indexOf('assets') < result.navigationOrder.indexOf('findings'))
})

test('overview is always available and cannot be removed by imported preferences', () => {
  const result = normalizePreferences({ navigationItems: ['assets', 'findings'] })
  assert.ok(result.navigationItems.includes('overview'))
  assert.deepEqual(normalizePreferences({ navigationItems: [] }).navigationItems, ['overview'])
})

test('navigation customization survives export and import', () => {
  const custom = normalizePreferences({
    navigationItems: ['overview', 'assets', 'reports'],
    navigationOrder: ['reports', 'assets', 'overview'],
  })
  assert.deepEqual(parsePreferencesJson(serializePreferences(custom)), custom)
})

test('browser persistence is isolated by user id', () => {
  const values = new Map()
  globalThis.window = { localStorage: {
    getItem: key => values.has(key) ? values.get(key) : null,
    setItem: (key, value) => values.set(key, value),
  } }
  try {
    persistPreferences({ ...DEFAULT_PREFERENCES, theme: 'light' }, 101)
    persistPreferences({ ...DEFAULT_PREFERENCES, theme: 'graphite' }, 202)
    assert.equal(loadPreferences(101).theme, 'light')
    assert.equal(loadPreferences(202).theme, 'graphite')
    assert.equal(loadPreferences(303).theme, 'midnight')
  } finally {
    delete globalThis.window
  }
})
