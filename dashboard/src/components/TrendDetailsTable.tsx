import { useState } from 'react'
import type { TrendDetailItem } from '../types/api'
import { formatSignedNumber, formatValue } from '../utils/format'

interface TrendDetailsTableProps {
  title: string
  items?: TrendDetailItem[]
}

const defaultLimit = 10

export function TrendDetailsTable({ title, items = [] }: TrendDetailsTableProps) {
  const [expanded, setExpanded] = useState(false)
  const visibleItems = expanded ? items : items.slice(0, defaultLimit)

  return (
    <section className="trend-detail-section">
      <div className="trend-detail-section__header">
        <h3>{title}</h3>
        <span>{items.length}</span>
      </div>

      {items.length === 0 ? (
        <div className="panel-message">No items in this trend category.</div>
      ) : (
        <>
          <div className="table-wrap">
            <table className="trend-details-table">
              <thead>
                <tr>
                  <th>Title</th>
                  <th>Source</th>
                  <th>Category</th>
                  <th>Previous Priority</th>
                  <th>Current Priority</th>
                  <th>Previous Score</th>
                  <th>Current Score</th>
                  <th>Delta</th>
                  <th>Reason</th>
                </tr>
              </thead>
              <tbody>
                {visibleItems.map((item, index) => (
                  <tr key={`${item.stable_key || item.title || title}-${index}`}>
                    <td>{formatValue(item.title)}</td>
                    <td>{formatValue(item.source)}</td>
                    <td>{formatValue(item.category)}</td>
                    <td>{formatValue(item.previous_priority_label)}</td>
                    <td>{formatValue(item.current_priority_label)}</td>
                    <td>{formatValue(item.previous_priority_score)}</td>
                    <td>{formatValue(item.current_priority_score)}</td>
                    <td>{formatSignedNumber(item.score_delta)}</td>
                    <td>{formatValue(item.reason_summary)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {items.length > defaultLimit ? (
            <div className="button-row button-row--right">
              <button className="secondary-button compact-button" type="button" onClick={() => setExpanded((current) => !current)}>
                {expanded ? 'Show less' : 'Show more'}
              </button>
            </div>
          ) : null}
        </>
      )}
    </section>
  )
}
