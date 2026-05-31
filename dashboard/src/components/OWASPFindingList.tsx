import type { OWASPMappedItem } from '../types/api'
import { OWASPBadge } from './OWASPBadge'

interface OWASPFindingListProps {
  items: OWASPMappedItem[]
}

export function OWASPFindingList({ items }: OWASPFindingListProps) {
  if (!items.length) return <div className="panel-message">No OWASP indicators are available for the selected result.</div>
  return (
    <div className="table-shell">
      <table>
        <thead>
          <tr>
            <th>Item</th>
            <th>Source</th>
            <th>OWASP Category</th>
            <th>Confidence</th>
            <th>Reason</th>
            <th>Manual validation</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={`${item.item_key}-${item.owasp_id}`}>
              <td>{item.title}</td>
              <td>{item.source}</td>
              <td>{item.owasp_id} {item.owasp_name}</td>
              <td><OWASPBadge confidence={item.confidence} /></td>
              <td>{item.mapping_reason}</td>
              <td>{item.manual_validation_required ? 'Manual validation required' : 'Indicator only'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
