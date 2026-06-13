interface Props {
  value: number
  disabled?: boolean
  onChange: (value: number) => void
}

export function ApiPageSizeSelector({ value, disabled = false, onChange }: Props) {
  return (
    <label className="api-page-size-selector">
      <span>Page size</span>
      <select value={value} disabled={disabled} onChange={(event) => onChange(Number(event.target.value))}>
        {[10, 25, 50, 100].map((size) => (
          <option key={size} value={size}>{size}</option>
        ))}
      </select>
    </label>
  )
}
