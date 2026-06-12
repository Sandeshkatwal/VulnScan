export function PortfolioLandingPage() {
  return (
    <div className="portfolio-landing">
      <section className="home-hero">
        <div>
          <h2>VulScan Portfolio Walkthrough</h2>
          <p>OWASP-focused assessment workflows, authenticated assessment safety, Evidence Vault controls, and professional report composition in one local platform.</p>
        </div>
      </section>
      <div className="module-grid">
        {['OWASP coverage', 'Authenticated assessment safety', 'Evidence Vault', 'Professional reports', 'Python 3.11 + FastAPI', 'React + TypeScript'].map((item) => <article key={item}>{item}</article>)}
      </div>
      <p className="notice-box">Use Portfolio Demo Mode for interviews. It is Local Demo Only and uses simulated redacted data.</p>
    </div>
  )
}

