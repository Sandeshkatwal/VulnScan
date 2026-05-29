export interface NavigationItem {
  id: string
  label: string
}

interface SidebarProps {
  items: NavigationItem[]
  activeItem: string
  onSelect: (item: string) => void
}

export function Sidebar({ items, activeItem, onSelect }: SidebarProps) {
  return (
    <aside className="dashboard-sidebar" aria-label="Dashboard sections">
      <div className="sidebar-brand">
        <strong>VulScan</strong>
        <span>Local Console</span>
      </div>
      <nav className="sidebar-nav">
        {items.map((item) => (
          <button
            className={item.id === activeItem ? 'sidebar-nav__item sidebar-nav__item--active' : 'sidebar-nav__item'}
            key={item.id}
            type="button"
            onClick={() => onSelect(item.id)}
          >
            {item.label}
          </button>
        ))}
      </nav>
      <p className="sidebar-notice">Local development dashboard. Use only with authorised scans.</p>
    </aside>
  )
}
