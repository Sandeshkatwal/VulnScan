import { useState } from 'react'
import { buildDemoReport, getDemoDashboard } from '../api/client'
import { portfolioDemoDataset } from '../demo/portfolioDemoData'
import type { DemoDataset } from '../types/api'
import { DemoReportPreview } from './DemoReportPreview'
import { DemoSafetyNotice } from './DemoSafetyNotice'
import { FeatureTour } from './FeatureTour'
import { LoadingState } from './LoadingState'
import { SafeActionButton } from './SafeActionButton'

interface Props {
  apiOnline: boolean
  demoMode: boolean
  dataset: DemoDataset
  onDataset: (dataset: DemoDataset) => void
  onEnableDemo: () => void
}

export function PortfolioDemoMode({ apiOnline, demoMode, dataset, onDataset, onEnableDemo }: Props) {
  const [loading, setLoading] = useState(false)
  const [message, setMessage] = useState<string | null>(null)

  async function loadDataset() {
    setLoading(true)
    try {
      const response = apiOnline ? await getDemoDashboard() : { demo_dataset: portfolioDemoDataset }
      onDataset(response.demo_dataset || portfolioDemoDataset)
      onEnableDemo()
      setMessage('Safe Demo Dataset loaded.')
    } catch {
      onDataset(portfolioDemoDataset)
      onEnableDemo()
      setMessage('API unavailable. Frontend fallback Safe Demo Dataset loaded.')
    } finally {
      setLoading(false)
    }
  }

  async function generateReport() {
    setLoading(true)
    try {
      const response = apiOnline ? await buildDemoReport({ markdown: true, html: true, json: true }) : { export_paths: { markdown: 'frontend-demo-only.md' } }
      setMessage(`Demo Report ready: ${Object.keys(response.export_paths || {}).join(', ') || 'frontend preview'}`)
    } catch (caught) {
      setMessage(caught instanceof Error ? caught.message : 'Demo Report generation failed.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="dashboard-grid">
      <section className="panel panel-wide">
        <DemoSafetyNotice />
        {loading ? <LoadingState message="Loading Safe Demo Dataset..." /> : null}
        {message ? <p className="inline-message">{message}</p> : null}
        <div className="button-row">
          <SafeActionButton demoMode={demoMode} onClick={loadDataset}>Load Safe Demo Dataset</SafeActionButton>
          <SafeActionButton demoMode={demoMode} onClick={generateReport}>Generate Demo Report</SafeActionButton>
        </div>
      </section>
      <section className="panel">
        <h3>Portfolio Demo Mode</h3>
        <p>Use this mode for screenshots, GitHub project review, and Interview Walkthrough sessions. All records are simulated and redacted.</p>
      </section>
      <section className="panel">
        <DemoReportPreview dataset={dataset} />
      </section>
      <section className="panel panel-wide">
        <FeatureTour steps={dataset.feature_tour || []} />
      </section>
    </div>
  )
}

