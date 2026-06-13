import type { ReactNode } from 'react'

interface Props<T> {
  items: T[]
  limit?: number
  renderItem: (item: T, index: number) => ReactNode
  getKey: (item: T, index: number) => string
}

export function VirtualList<T>({ items, limit = 100, renderItem, getKey }: Props<T>) {
  const visible = items.slice(0, limit)
  return (
    <div className="virtual-list">
      {visible.map((item, index) => (
        <div className="virtual-list__item" key={getKey(item, index)}>
          {renderItem(item, index)}
        </div>
      ))}
      {items.length > visible.length ? <div className="panel-message">{items.length - visible.length} more records available through pagination.</div> : null}
    </div>
  )
}
