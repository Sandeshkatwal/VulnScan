interface ValidationTargetInputProps {
  url: string
  candidateType: string
  parameter: string
  disabled?: boolean
  onUrlChange: (value: string) => void
  onCandidateTypeChange: (value: string) => void
  onParameterChange: (value: string) => void
}

const candidateTypes = ['reflected_input', 'open_redirect', 'cors', 'directory_listing', 'default_file', 'http_methods']

export function ValidationTargetInput({ url, candidateType, parameter, disabled = false, onUrlChange, onCandidateTypeChange, onParameterChange }: ValidationTargetInputProps) {
  return (
    <div className="recon-options-grid">
      <label>
        <span>URL</span>
        <input value={url} disabled={disabled} onChange={(event) => onUrlChange(event.target.value)} />
      </label>
      <label>
        <span>Candidate type</span>
        <select value={candidateType} disabled={disabled} onChange={(event) => onCandidateTypeChange(event.target.value)}>
          {candidateTypes.map((item) => <option key={item} value={item}>{item}</option>)}
        </select>
      </label>
      <label>
        <span>Parameter</span>
        <input value={parameter} disabled={disabled} onChange={(event) => onParameterChange(event.target.value)} />
      </label>
    </div>
  )
}
