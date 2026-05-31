import { useEffect, useMemo, useState } from 'react'
import { checkDuplicate, getDuplicateGroup, getDuplicateGroups } from '../api/client'
import type { DuplicateCheckResponse, DuplicateGroup, DuplicateGroupsResponse, DuplicateSummary } from '../types/api'

interface DuplicateDetectionViewProps {
  apiOnline: boolean
  demoMode?: boolean
}

const demoSummary: DuplicateSummary = {
  enabled: true,
  total_fingerprints: 8,
  unique_findings: 5,
  exact_duplicates: 1,
  likely_duplicates: 1,
  related_findings: 1,
  duplicate_groups_count: 3,
  limitations: ['Demo data only. Duplicate Detection is metadata-based and requires manual review.'],
}

const demoGroups: DuplicateGroup[] = [
  {
    duplicate_group_id: 'dg_demo_idor',
    duplicate_status: 'likely_duplicate',
    confidence: 'High',
    title: 'idor on /account/{id}',
    member_count: 2,
    updated_at: 'Demo data only',
    members: [
      { fingerprint_id: 'fp_demo_1', relationship: 'primary', confidence: 'High', reason: 'Same host, path, issue type, and parameter name.' },
      { fingerprint_id: 'fp_demo_2', relationship: 'likely_duplicate', confidence: 'High', reason: 'Different value, same metadata fingerprint pattern.' },
    ],
  },
]

function message(error: unknown): string {
  return error instanceof Error ? error.message : 'Duplicate Detection request failed.'
}

export function DuplicateDetectionView({ apiOnline, demoMode = false }: DuplicateDetectionViewProps) {
  const [url, setUrl] = useState('http://127.0.0.1:8000/account?id=123')
  const [issueType, setIssueType] = useState('idor_candidate')
  const [parameters, setParameters] = useState('id')
  const [source, setSource] = useState('endpoint_discovery')
  const [summary, setSummary] = useState<DuplicateSummary | undefined>(demoMode ? demoSummary : undefined)
  const [groups, setGroups] = useState<DuplicateGroup[]>(demoMode ? demoGroups : [])
  const [selectedGroup, setSelectedGroup] = useState<DuplicateGroup | null>(demoMode ? demoGroups[0] : null)
  const [result, setResult] = useState<DuplicateCheckResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (demoMode || !apiOnline) return
    getDuplicateGroups()
      .then((response: DuplicateGroupsResponse) => {
        setSummary(response.summary)
        setGroups(response.groups || [])
        setSelectedGroup(response.groups?.[0] || null)
      })
      .catch((caught) => setError(message(caught)))
  }, [apiOnline, demoMode])

  const parameterNames = useMemo(
    () => parameters.split(',').map((item) => item.trim()).filter(Boolean),
    [parameters],
  )

  async function runCheck() {
    if (demoMode) {
      setResult({
        fingerprint: {
          fingerprint_id: 'fp_demo_check',
          fingerprint_short: '6f2a91c8d314',
          host: '127.0.0.1',
          path_normalised: '/account',
          issue_type: 'idor',
          parameter_names: parameterNames,
          source,
        },
        duplicate_result: {
          duplicate_status: 'likely_duplicate',
          duplicate_confidence: 'High',
          duplicate_reason: 'Demo data only. Same host, normalised path, issue type, and parameter name.',
          duplicate_group_id: 'dg_demo_idor',
        },
      })
      return
    }
    setLoading(true)
    setError(null)
    try {
      const response = await checkDuplicate({ url, issue_type: issueType, parameter_names: parameterNames, source, item_type: 'candidate' })
      setResult(response)
      const refreshed = await getDuplicateGroups()
      setSummary(refreshed.summary)
      setGroups(refreshed.groups || [])
    } catch (caught) {
      setError(message(caught))
    } finally {
      setLoading(false)
    }
  }

  async function selectGroup(group: DuplicateGroup) {
    if (!group.duplicate_group_id || demoMode) {
      setSelectedGroup(group)
      return
    }
    try {
      setSelectedGroup(await getDuplicateGroup(group.duplicate_group_id))
    } catch {
      setSelectedGroup(group)
    }
  }

  return (
    <div className="duplicate-view">
      <div className="workflow-safety-notice">
        <strong>Duplicate Detection is metadata-only.</strong>
        <span>VulScan fingerprints finding context, not parameter values or secrets. Duplicate status is a review indicator, not a confirmed platform decision.</span>
      </div>

      {demoMode ? <div className="panel-message">Demo data only.</div> : null}
      {!apiOnline && !demoMode ? <div className="panel-message panel-message--error">API offline. Duplicate Detection data is unavailable.</div> : null}
      {error ? <div className="panel-message panel-message--error">{error}</div> : null}

      <div className="duplicate-summary-grid">
        {[
          ['Fingerprints', summary?.total_fingerprints],
          ['Unique', summary?.unique_findings],
          ['Exact duplicates', summary?.exact_duplicates],
          ['Likely duplicates', summary?.likely_duplicates],
          ['Related', summary?.related_findings],
          ['Groups', summary?.duplicate_groups_count],
        ].map(([label, value]) => (
          <div className="duplicate-summary-card" key={String(label)}>
            <span>{label}</span>
            <strong>{value ?? 0}</strong>
          </div>
        ))}
      </div>

      <div className="duplicate-grid">
        <section className="panel duplicate-checker">
          <div className="panel-heading">
            <h2>Fingerprint Checker</h2>
            <p>Check a candidate against local finding fingerprints.</p>
          </div>
          <label><span>URL</span><input value={url} onChange={(event) => setUrl(event.target.value)} /></label>
          <label><span>Issue type</span><input value={issueType} onChange={(event) => setIssueType(event.target.value)} /></label>
          <label><span>Parameter names</span><input value={parameters} onChange={(event) => setParameters(event.target.value)} placeholder="id, account_id" /></label>
          <label><span>Source</span><input value={source} onChange={(event) => setSource(event.target.value)} /></label>
          <button className="primary-button" onClick={runCheck} disabled={loading || (!apiOnline && !demoMode)}>{loading ? 'Checking...' : 'Check Duplicate'}</button>
        </section>

        <section className="panel duplicate-result-panel">
          <div className="panel-heading">
            <h2>Duplicate Result</h2>
            <p>Manual review required for all duplicate indicators.</p>
          </div>
          {result ? (
            <dl className="detail-list">
              <div><dt>Fingerprint</dt><dd><span className="fingerprint-badge">{result.fingerprint.fingerprint_short || result.fingerprint.fingerprint_id}</span></dd></div>
              <div><dt>Status</dt><dd><span className={`duplicate-status duplicate-status--${result.duplicate_result.duplicate_status || 'unique'}`}>{result.duplicate_result.duplicate_status}</span></dd></div>
              <div><dt>Confidence</dt><dd>{result.duplicate_result.duplicate_confidence}</dd></div>
              <div><dt>Reason</dt><dd>{result.duplicate_result.duplicate_reason}</dd></div>
              <div><dt>Normalised path</dt><dd>{result.fingerprint.path_normalised}</dd></div>
              <div><dt>Parameters</dt><dd>{result.fingerprint.parameter_names?.join(', ') || 'None'}</dd></div>
            </dl>
          ) : <div className="empty-state">Run a duplicate check to see fingerprint and duplicate metadata.</div>}
        </section>
      </div>

      <section className="panel">
        <div className="panel-heading">
          <h2>Duplicate Groups</h2>
          <p>Existing metadata groups for exact, likely, related, and unique finding fingerprints.</p>
        </div>
        <div className="table-wrap">
          <table className="duplicate-table">
            <thead><tr><th>Group ID</th><th>Status</th><th>Confidence</th><th>Title</th><th>Members</th><th>Updated</th></tr></thead>
            <tbody>
              {groups.map((group) => (
                <tr key={group.duplicate_group_id} onClick={() => selectGroup(group)}>
                  <td>{group.duplicate_group_id}</td>
                  <td><span className={`duplicate-status duplicate-status--${group.duplicate_status || 'unique'}`}>{group.duplicate_status}</span></td>
                  <td>{group.confidence}</td>
                  <td>{group.title}</td>
                  <td>{group.member_count ?? group.members?.length ?? 0}</td>
                  <td>{group.updated_at}</td>
                </tr>
              ))}
              {!groups.length ? <tr><td colSpan={6}>No duplicate groups yet.</td></tr> : null}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel">
        <div className="panel-heading">
          <h2>Group Detail</h2>
          <p>Relationships are derived from stable metadata and may need manual resolution.</p>
        </div>
        {selectedGroup?.members?.length ? (
          <div className="duplicate-member-list">
            {selectedGroup.members.map((member) => (
              <div className="duplicate-member" key={`${member.fingerprint_id}-${member.relationship}`}>
                <strong>{member.relationship}</strong>
                <span>{member.fingerprint_id}</span>
                <small>{member.reason}</small>
              </div>
            ))}
          </div>
        ) : <div className="empty-state">Select a duplicate group to inspect members.</div>}
      </section>
    </div>
  )
}
