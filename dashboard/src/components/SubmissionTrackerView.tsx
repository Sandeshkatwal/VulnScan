import { useEffect, useState } from 'react'
import { createRetest, createSubmission, getSubmission, getSubmissionSummary, getSubmissions, updateRetest, updateSubmissionStatus } from '../api/client'
import type { RetestRecord, SubmissionRecord, SubmissionSummary } from '../types/api'
import { ErrorAlert } from './ErrorAlert'

interface SubmissionTrackerViewProps {
  apiOnline: boolean
  demoMode?: boolean
}

const statusOptions = ['draft', 'ready_for_review', 'submitted', 'triaged', 'accepted', 'duplicate', 'informative', 'not_applicable', 'resolved', 'paid', 'closed']
const retestStatusOptions = ['not_required', 'retest_required', 'retest_in_progress', 'retest_passed', 'retest_failed', 'retest_blocked']

const demoSubmission: SubmissionRecord = {
  submission_id: 'sub_demo',
  report_id: 'REPORT_ID',
  finding_title: 'Demo Security Finding Report',
  program_name: 'Demo Program',
  platform: 'manual',
  status: 'draft',
  severity_submitted: 'Medium',
  updated_at: 'demo-local',
  notes: 'Tracking only. Manual validation required.',
  timeline: [{ event_type: 'created', new_status: 'draft', note: 'Demo record created.', created_at: 'demo-local' }],
  retests: [],
}

function formatBounty(summary?: SubmissionSummary | null): string {
  const totals = summary?.total_bounty_amount_by_currency || {}
  return Object.entries(totals).map(([currency, amount]) => `${amount} ${currency}`).join(', ') || 'None'
}

export function SubmissionTrackerView({ apiOnline, demoMode = false }: SubmissionTrackerViewProps) {
  const [summary, setSummary] = useState<SubmissionSummary | null>(demoMode ? { total_count: 1, draft_count: 1, total_bounty_amount_by_currency: {} } : null)
  const [submissions, setSubmissions] = useState<SubmissionRecord[]>(demoMode ? [demoSubmission] : [])
  const [selected, setSelected] = useState<SubmissionRecord | null>(demoMode ? demoSubmission : null)
  const [form, setForm] = useState({ report_id: 'REPORT_ID', finding_title: '', program_name: 'Demo Program', platform: 'manual', status: 'draft', severity_submitted: 'Medium', notes: '' })
  const [statusForm, setStatusForm] = useState({ status: 'submitted', note: '' })
  const [retestForm, setRetestForm] = useState({ status: 'retest_required', retest_result: '', notes: '', evidence_id: '' })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function loadData() {
    if (demoMode) return
    if (!apiOnline) return
    setLoading(true)
    setError(null)
    try {
      const [nextSummary, response] = await Promise.all([getSubmissionSummary(), getSubmissions()])
      setSummary(nextSummary)
      setSubmissions(response.submissions)
      if (response.submissions[0]?.submission_id) {
        setSelected(await getSubmission(response.submissions[0].submission_id))
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Submission tracker request failed.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void loadData()
  }, [apiOnline, demoMode])

  async function createRecord() {
    if (demoMode) return
    setLoading(true)
    setError(null)
    try {
      const record = await createSubmission(form)
      setSelected(record)
      await loadData()
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Create submission failed.')
    } finally {
      setLoading(false)
    }
  }

  async function changeStatus() {
    if (demoMode || !selected?.submission_id) return
    setLoading(true)
    setError(null)
    try {
      setSelected(await updateSubmissionStatus(selected.submission_id, statusForm))
      await loadData()
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Status update failed.')
    } finally {
      setLoading(false)
    }
  }

  async function createOrUpdateRetest() {
    if (demoMode || !selected?.submission_id) return
    setLoading(true)
    setError(null)
    try {
      const existing = selected.retests?.[0]
      if (existing?.retest_id) {
        await updateRetest(existing.retest_id, retestForm)
      } else {
        await createRetest({ ...retestForm, submission_id: selected.submission_id, report_id: selected.report_id })
      }
      setSelected(await getSubmission(selected.submission_id))
      await loadData()
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Retest update failed.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <section className="content-grid">
      <article className="panel panel--wide">
        <div className="panel-heading">
          <h2>Submission and Retest Tracking</h2>
          <p>Tracking only. VulScan does not submit reports or modify targets.</p>
        </div>
        <div className="panel-message panel-message--warning">Do not store platform credentials, API tokens, session cookies, passwords, or private keys in notes.</div>
        <ErrorAlert message={error} />
        <div className="summary-grid">
          <div><span>Draft</span><strong>{summary?.draft_count || 0}</strong></div>
          <div><span>Submitted</span><strong>{summary?.submitted_count || 0}</strong></div>
          <div><span>Triaged</span><strong>{summary?.triaged_count || 0}</strong></div>
          <div><span>Accepted</span><strong>{summary?.accepted_count || 0}</strong></div>
          <div><span>Duplicate</span><strong>{summary?.duplicate_count || 0}</strong></div>
          <div><span>Resolved</span><strong>{summary?.resolved_count || 0}</strong></div>
          <div><span>Paid</span><strong>{summary?.paid_count || 0}</strong></div>
          <div><span>Retest Required</span><strong>{summary?.retest_required_count || 0}</strong></div>
          <div><span>Total Bounty</span><strong>{formatBounty(summary)}</strong></div>
        </div>
      </article>

      <article className="panel">
        <div className="panel-heading"><h2>Submission Form</h2><p>Create local workflow records only.</p></div>
        <div className="recon-form">
          <label><span>Report ID</span><input value={form.report_id} onChange={(event) => setForm({ ...form, report_id: event.target.value })} /></label>
          <label><span>Finding/report title</span><input value={form.finding_title} onChange={(event) => setForm({ ...form, finding_title: event.target.value })} /></label>
          <label><span>Program</span><input value={form.program_name} onChange={(event) => setForm({ ...form, program_name: event.target.value })} /></label>
          <label><span>Platform</span><input value={form.platform} onChange={(event) => setForm({ ...form, platform: event.target.value })} /></label>
          <label><span>Status</span><select value={form.status} onChange={(event) => setForm({ ...form, status: event.target.value })}>{statusOptions.map((status) => <option key={status} value={status}>{status}</option>)}</select></label>
          <label><span>Submitted severity</span><input value={form.severity_submitted} onChange={(event) => setForm({ ...form, severity_submitted: event.target.value })} /></label>
          <label><span>Notes</span><textarea value={form.notes} onChange={(event) => setForm({ ...form, notes: event.target.value })} /></label>
          <button className="primary-button" type="button" disabled={loading || demoMode} onClick={() => void createRecord()}>Create Submission</button>
        </div>
      </article>

      <article className="panel panel--wide">
        <div className="panel-heading"><h2>Submissions</h2><p>Security Finding Report tracking records.</p></div>
        <div className="table-scroll">
          <table><thead><tr><th>Title</th><th>Program</th><th>Platform</th><th>Status</th><th>Submitted</th><th>Accepted</th><th>Bounty</th><th>Follow-up</th><th>Updated</th></tr></thead>
            <tbody>{submissions.map((record) => (
              <tr key={record.submission_id} onClick={() => record.submission_id && getSubmission(record.submission_id).then(setSelected).catch(() => setSelected(record))}>
                <td>{record.finding_title || record.report_id || record.submission_id}</td><td>{record.program_name}</td><td>{record.platform}</td><td><span className="status-pill">{record.status}</span></td><td>{record.severity_submitted}</td><td>{record.severity_accepted}</td><td>{[record.bounty_amount, record.bounty_currency].filter(Boolean).join(' ')}</td><td>{record.next_follow_up_date}</td><td>{record.updated_at}</td>
              </tr>
            ))}</tbody></table>
        </div>
      </article>

      <article className="panel">
        <div className="panel-heading"><h2>Detail</h2><p>Evidence references, notes, timeline, and retests.</p></div>
        {selected ? (
          <div className="detail-stack">
            <div className="empty-state">Report: {selected.report_id || 'None'} | Evidence: {(selected.evidence_ids || []).join(', ') || 'None'}</div>
            <p>{selected.notes || 'No notes.'}</p>
            {selected.safe_notes_redacted ? <div className="panel-message panel-message--warning">Sensitive note content was redacted.</div> : null}
            <label><span>New status</span><select value={statusForm.status} onChange={(event) => setStatusForm({ ...statusForm, status: event.target.value })}>{statusOptions.map((status) => <option key={status} value={status}>{status}</option>)}</select></label>
            <label><span>Status note</span><textarea value={statusForm.note} onChange={(event) => setStatusForm({ ...statusForm, note: event.target.value })} /></label>
            <button className="secondary-button" type="button" disabled={loading || demoMode} onClick={() => void changeStatus()}>Update Status</button>
            <h3>Retest Checklist</h3>
            <label><span>Retest status</span><select value={retestForm.status} onChange={(event) => setRetestForm({ ...retestForm, status: event.target.value })}>{retestStatusOptions.map((status) => <option key={status} value={status}>{status}</option>)}</select></label>
            <label><span>Retest result</span><input value={retestForm.retest_result} onChange={(event) => setRetestForm({ ...retestForm, retest_result: event.target.value })} placeholder="issue_no_longer_reproducible" /></label>
            <label><span>Evidence ID</span><input value={retestForm.evidence_id} onChange={(event) => setRetestForm({ ...retestForm, evidence_id: event.target.value })} /></label>
            <label><span>Retest notes</span><textarea value={retestForm.notes} onChange={(event) => setRetestForm({ ...retestForm, notes: event.target.value })} /></label>
            <button className="secondary-button" type="button" disabled={loading || demoMode} onClick={() => void createOrUpdateRetest()}>Save Retest</button>
            <h3>Follow-up Timeline</h3>
            {(selected.timeline || []).map((event) => <div className="empty-state" key={event.event_id || `${event.event_type}-${event.created_at}`}>{event.created_at} | {event.event_type} | {event.old_status || ''} {event.new_status || ''} | {event.note || ''}</div>)}
            {(selected.retests || []).map((record: RetestRecord) => <div className="empty-state" key={record.retest_id}>{record.status}: {record.retest_result || 'No result'} {record.evidence_id ? `| Evidence ${record.evidence_id}` : ''}</div>)}
          </div>
        ) : <div className="empty-state">Select or create a submission record.</div>}
      </article>
    </section>
  )
}
