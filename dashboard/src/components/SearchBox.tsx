interface SearchBoxProps {
  value: string
  onChange: (value: string) => void
  disabled?: boolean
}

export function SearchBox({ value, onChange, disabled = false }: SearchBoxProps) {
  return (
    <label className="search-box">
      <span>Search loaded findings</span>
      <input
        type="text"
        value={value}
        disabled={disabled}
        placeholder="Title, source, category, evidence, recommendation, CVE"
        onChange={(event) => onChange(event.target.value)}
      />
    </label>
  )
}
