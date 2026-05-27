import { useState, type FormEvent } from 'react'
import type { ScanRequest, ScanResponse } from '../types/api'
import { ErrorAlert } from './ErrorAlert'
import { LoadingSpinner } from './LoadingSpinner'

interface ScanJobFormProps {
  onSubmit: (request: ScanRequest) => Promise<ScanResponse>
}

const initialRequest: ScanRequest = {
  target: '',
  scan_mode: 'safe',
  json_report: true,
  html_report: false,
  save_db: true,
  prioritise: false,
  fix_first_dashboard: false,
}

export function ScanJobForm({ onSubmit }: ScanJobFormProps) {
  const [request, setRequest] = useState<ScanRequest>(initialRequest)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [jobId, setJobId] = useState<string | null>(null)

  async function submitForm(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const target = request.target.trim()
    if (!target) {
      setError('Target is required.')
      return
    }

    setSubmitting(true)
    setError(null)
    setJobId(null)
    try {
      const response = await onSubmit({ ...request, target, scan_mode: 'safe' })
      setJobId(response.job_id || null)
      setRequest((current) => ({ ...current, target }))
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Could not create scan job.')
    } finally {
      setSubmitting(false)
    }
  }

  function setBooleanField(field: keyof ScanRequest, checked: boolean) {
    setRequest((current) => ({ ...current, [field]: checked }))
  }

  return (
    <form className="scan-form" onSubmit={submitForm}>
      <ErrorAlert message={error} />
      <label className="field">
        <span>Target</span>
        <input
          type="text"
          value={request.target}
          required
          placeholder="127.0.0.1"
          onChange={(event) => setRequest((current) => ({ ...current, target: event.target.value }))}
        />
      </label>

      <div className="checkbox-grid" aria-label="Safe scan options">
        <label>
          <input
            type="checkbox"
            checked={Boolean(request.json_report)}
            onChange={(event) => setBooleanField('json_report', event.target.checked)}
          />
          JSON report
        </label>
        <label>
          <input
            type="checkbox"
            checked={Boolean(request.html_report)}
            onChange={(event) => setBooleanField('html_report', event.target.checked)}
          />
          HTML report
        </label>
        <label>
          <input
            type="checkbox"
            checked={Boolean(request.save_db)}
            onChange={(event) => setBooleanField('save_db', event.target.checked)}
          />
          Save DB
        </label>
        <label>
          <input
            type="checkbox"
            checked={Boolean(request.prioritise)}
            onChange={(event) => setBooleanField('prioritise', event.target.checked)}
          />
          Prioritise
        </label>
        <label>
          <input
            type="checkbox"
            checked={Boolean(request.fix_first_dashboard)}
            onChange={(event) => setBooleanField('fix_first_dashboard', event.target.checked)}
          />
          Fix-first dashboard
        </label>
      </div>

      <div className="form-actions">
        <button className="primary-button" type="submit" disabled={submitting}>
          {submitting ? <LoadingSpinner label="Creating job" /> : 'Create Safe Scan Job'}
        </button>
        <span className="safe-mode-note">scan_mode: safe</span>
      </div>

      {jobId ? <div className="success-message">Created job {jobId}</div> : null}
    </form>
  )
}
