export interface NavigationItem {
  id: string
  label: string
  group?: string
}

interface SidebarProps {
  items: NavigationItem[]
  activeItem: string
  onSelect: (item: string) => void
}

export function Sidebar({ items, activeItem, onSelect }: SidebarProps) {
  const groups = items.reduce<Array<{ group: string; items: NavigationItem[] }>>((acc, item) => {
    const group = item.group || 'Dashboard'
    const existing = acc.find((entry) => entry.group === group)
    if (existing) existing.items.push(item)
    else acc.push({ group, items: [item] })
    return acc
  }, [])

  return (
    <aside className="dashboard-sidebar" aria-label="Dashboard sections">
      <div className="sidebar-brand">
        <strong>VulScan</strong>
        <span>Portfolio Console</span>
      </div>
      <nav className="sidebar-nav">
        {groups.map((group) => (
          <div className="sidebar-group" key={group.group}>
            <span className="sidebar-group__label">{group.group}</span>
            {group.items.map((item) => (
              <button
                className={item.id === activeItem ? 'sidebar-nav__item sidebar-nav__item--active' : 'sidebar-nav__item'}
                key={item.id}
                type="button"
                onClick={() => onSelect(item.id)}
              >
                {item.label}
              </button>
            ))}
          </div>
        ))}
      </nav>
      <p className="sidebar-notice">Local development dashboard. Use only with authorised scans.</p>
    </aside>
  )
}
