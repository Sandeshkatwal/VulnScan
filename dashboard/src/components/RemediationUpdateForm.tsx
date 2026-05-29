import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import type { RemediationRecord, RemediationStatus, RemediationUpdatePayload } from '../types/api'

interface RemediationUpdateFormProps {
  record?: RemediationRecord | null
  findingKey?: string | null
  loading?: boolean
  onSubmit: (findingKey: string, payload: RemediationUpdatePayload) => Promise<void> | void
}

const statuses: Array<{ value: RemediationStatus; label: string }> = [
  { value: 'open', label: 'Open' },
  { value: 'in_progress', label: 'In Progress' },
  { value: 'fixed', label: 'Fixed' },
  { value: 'accepted_risk', label: 'Accepted Risk' },
  { value: 'false_positive', label: 'False Positive' },
]

export function RemediationUpdateForm({ record, findingKey, loading = false, onSubmit }: RemediationUpdateFormProps) {
  const [status, setStatus] = useState<RemediationStatus>('open')
  const [note, setNote] = useState('')
  const [owner, setOwner] = useState('')
  const [dueDate, setDueDate] = useState('')

  useEffect(() => {
    setStatus((record?.status as RemediationStatus) || 'open')
    setNote(record?.note || '')
    setOwner(record?.owner || '')
    setDueDate(record?.due_date ? String(record.due_date).slice(0, 10) : '')
  }, [record])

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!findingKey) return
    await onSubmit(findingKey, {
      status,
      note: note.trim() || undefined,
      owner: owner.trim() || undefined,
      due_date: dueDate || undefined,
    })
  }

  return (
    <form className="remediation-update-form" onSubmit={(event) => void handleSubmit(event)}>
      <div className="info-message">This action only updates tracking status. It does not change the target system.</div>
      <label>
        <span>Status</span>
        <select value={status} onChange={(event) => setStatus(event.target.value as RemediationStatus)} disabled={loading || !findingKey}>
          {statuses.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
        </select>
      </label>
      <label>
        <span>Owner</span>
        <input value={owner} maxLength={255} onChange={(event) => setOwner(event.target.value)} disabled={loading || !findingKey} />
      </label>
      <label>
        <span>Due date</span>
        <input type="date" value={dueDate} onChange={(event) => setDueDate(event.target.value)} disabled={loading || !findingKey} />
      </label>
      <label className="remediation-note-field">
        <span>Note</span>
        <textarea value={note} maxLength={1000} rows={4} onChange={(event) => setNote(event.target.value)} disabled={loading || !findingKey} />
        <small>{note.length}/1000. Do not include secrets or credentials.</small>
      </label>
      <button className="secondary-button" type="submit" disabled={loading || !findingKey}>
        {loading ? 'Updating...' : 'Update tracking'}
      </button>
      {!findingKey ? <div className="panel-message panel-message--error">Finding key is missing, remediation tracking is unavailable for this item.</div> : null}
    </form>
  )
}
