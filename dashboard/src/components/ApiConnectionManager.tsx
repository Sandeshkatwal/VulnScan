import { useEffect, useState } from 'react'
import { apiBaseUrl, apiKeyConfigured, getHealth, getJobs, getVersion } from '../api/client'
import type { VersionResponse } from '../types/api'

interface ApiConnectionManagerProps {
  refreshLoading?: boolean
  onRefreshDashboard: () => void
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Request failed.'
}

function statusText(value?: string | null): string {
  return value && value.trim() ? value : 'Not available'
}

export function ApiConnectionManager({ refreshLoading = false, onRefreshDashboard }: ApiConnectionManagerProps) {
  const [version, setVersion] = useState<VersionResponse | null>(null)
  const [healthMessage, setHealthMessage] = useState<string | null>(null)
  const [versionMessage, setVersionMessage] = useState<string | null>(null)
  const [protectedMessage, setProtectedMessage] = useState<string | null>(null)
  const [testingHealth, setTestingHealth] = useState(false)
  const [testingVersion, setTestingVersion] = useState(false)
  const [testingProtected, setTestingProtected] = useState(false)
  const [refreshInterval, setRefreshInterval] = useState('manual')

  useEffect(() => {
    setRefreshInterval(localStorage.getItem('refreshIntervalSeconds') || 'manual')
  }, [])

  function saveRefreshInterval(nextValue: string) {
    setRefreshInterval(nextValue)
    if (nextValue === 'manual') {
      localStorage.removeItem('refreshIntervalSeconds')
      return
    }
    localStorage.setItem('refreshIntervalSeconds', nextValue)
  }

  async function testHealth() {
    setTestingHealth(true)
    setHealthMessage(null)
    try {
      const response = await getHealth()
      setHealthMessage(response.status === 'ok' ? 'Online' : 'API responded with a non-ok status.')
    } catch (caught) {
      setHealthMessage(`Offline: ${errorMessage(caught)}`)
    } finally {
      setTestingHealth(false)
    }
  }

  async function testVersion() {
    setTestingVersion(true)
    setVersionMessage(null)
    try {
      const response = await getVersion()
      setVersion(response)
      setVersionMessage('Version endpoint reachable.')
    } catch (caught) {
      setVersion(null)
      setVersionMessage(`Version unavailable: ${errorMessage(caught)}`)
    } finally {
      setTestingVersion(false)
    }
  }

  async function testProtectedEndpoint() {
    setTestingProtected(true)
    setProtectedMessage(null)
    try {
      await getJobs({ limit: 1 })
      setProtectedMessage('Protected endpoint reachable.')
    } catch (caught) {
      const suffix = apiKeyConfigured ? 'Check that the configured API key matches the backend.' : 'Configure VITE_VULSCAN_API_KEY if the backend requires an API key.'
      setProtectedMessage(`${errorMessage(caught)} ${suffix}`)
    } finally {
      setTestingProtected(false)
    }
  }

  return (
    <div className="connection-manager">
      <div className="connection-grid">
        <article className="connection-status-card">
          <span>API URL</span>
          <strong className="mono">{apiBaseUrl}</strong>
        </article>
        <article className="connection-status-card">
          <span>API Key</span>
          <strong>{apiKeyConfigured ? 'Configured' : 'Not configured'}</strong>
        </article>
        <article className="connection-status-card">
          <span>Dashboard Mode</span>
          <strong>Local development</strong>
        </article>
      </div>

      <div className="connection-actions">
        <button className="secondary-button" type="button" onClick={() => void testHealth()} disabled={testingHealth}>
          {testingHealth ? 'Testing...' : 'Test connection'}
        </button>
        <button className="secondary-button" type="button" onClick={() => void testVersion()} disabled={testingVersion}>
          {testingVersion ? 'Testing...' : 'Test version'}
        </button>
        <button className="secondary-button" type="button" onClick={() => void testProtectedEndpoint()} disabled={testingProtected}>
          {testingProtected ? 'Testing...' : 'Test protected endpoint'}
        </button>
        <button className="ghost-button" type="button" onClick={onRefreshDashboard} disabled={refreshLoading}>
          {refreshLoading ? 'Refreshing...' : 'Refresh dashboard data'}
        </button>
      </div>

      <div className="connection-results">
        <div className="info-message">Connection: {healthMessage || 'Not tested'}</div>
        <div className="info-message">Version: {versionMessage || 'Not tested'} {version ? `Scanner ${statusText(version.version || version.scanner)} / API ${statusText(version.api_version)}` : ''}</div>
        <div className="info-message">Protected endpoint: {protectedMessage || 'Not tested'}</div>
      </div>

      <label className="refresh-setting-row">
        <span>Refresh interval preference</span>
        <select value={refreshInterval} onChange={(event) => saveRefreshInterval(event.target.value)}>
          <option value="manual">Manual only</option>
          <option value="30">30 seconds</option>
          <option value="60">60 seconds</option>
          <option value="300">5 minutes</option>
        </select>
      </label>

      <dl className="settings-list settings-list--links">
        <div><dt>Backend Docs</dt><dd><a href={`${apiBaseUrl}/docs`} target="_blank" rel="noreferrer">{apiBaseUrl}/docs</a></dd></div>
        <div><dt>OpenAPI</dt><dd><a href={`${apiBaseUrl}/openapi.json`} target="_blank" rel="noreferrer">{apiBaseUrl}/openapi.json</a></dd></div>
      </dl>
    </div>
  )
}
