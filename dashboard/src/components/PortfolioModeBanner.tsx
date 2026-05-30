import { DEMO_MODE_MESSAGE } from '../utils/demoMode'

interface PortfolioModeBannerProps {
  demoMode: boolean
  portfolioMode: boolean
}

export function PortfolioModeBanner({ demoMode, portfolioMode }: PortfolioModeBannerProps) {
  if (!demoMode && !portfolioMode) return null
  return (
    <div className="portfolio-banner">
      <strong>{demoMode ? DEMO_MODE_MESSAGE : 'Portfolio Mode'}</strong>
      <span>Local authorised security assessment dashboard. Demo data is fake sample data only.</span>
    </div>
  )
}
