const cards = [
  'Discovery Engine',
  'Credentialed Audit',
  'Web DAST',
  'Vulnerability Intelligence',
  'Prioritisation',
  'API and Dashboard',
]

export function ProductHero() {
  return (
    <section className="product-hero">
      <div>
        <h1>VulScan Dashboard</h1>
        <p>Local vulnerability scanning, intelligence, prioritisation, and remediation tracking dashboard.</p>
      </div>
      <div className="product-hero__cards">
        {cards.map((card) => <span key={card}>{card}</span>)}
      </div>
    </section>
  )
}
