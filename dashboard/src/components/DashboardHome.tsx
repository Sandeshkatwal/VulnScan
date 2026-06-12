import type { DemoDataset, JobSummary, ScanSummary } from '../types/api'
import { DemoDatasetBadge } from './DemoDatasetBadge'
import { DemoSafetyNotice } from './DemoSafetyNotice'
import { EmptyState } from './EmptyState'
import { FeatureTour } from './FeatureTour'
import { MetricCard } from './MetricCard'

interface Props {
  demoMode: boolean
  dataset: DemoDataset
  jobs: JobSummary[]
  scans: ScanSummary[]
  onNavigate: (section: string) => void
  onEnableDemo: () => void
}

export function DashboardHome({ demoMode, dataset, jobs, scans, onNavigate, onEnableDemo }: Props) {
  const summary = dataset.dashboard_summary || {}
  const metrics = demoMode
    ? [
        ['Assets assessed', summary.assets_assessed || 0],
        ['Findings', summary.findings || 0],
        ['OWASP categories covered', summary.owasp_categories_covered || 0],
        ['Evidence items', summary.evidence_items || 0],
        ['Reports generated', summary.reports_generated || 0],
        ['Manual plans', summary.manual_plans || 0],
      ]
    : [
        ['Assets assessed', scans.length],
        ['Findings', jobs.reduce((total, job) => total + Number(job.result_summary?.total_findings || 0), 0)],
        ['OWASP categories covered', 0],
        ['Evidence items', 0],
        ['Reports generated', jobs.filter((job) => job.result_path || job.html_report_path).length],
        ['Manual plans', 0],
      ]

  const modules = ['Discovery', 'Web DAST', 'OWASP Assessment', 'Authenticated Assessment', 'Role Mapping', 'Manual Test Planner', 'Evidence Vault', 'Finding Builder', 'Report Composer']
  const workflow = ['Discover target', 'Run passive web assessment', 'Review OWASP indicators', 'Add authenticated context', 'Plan manual validation', 'Link evidence', 'Build findings', 'Compose report']

  return (
    <div className="dashboard-home">
      <section className="home-hero">
        <div>
          {demoMode ? <DemoDatasetBadge /> : null}
          <h2>VulScan — OWASP-focused vulnerability assessment and reporting platform</h2>
          <p>VulScan is designed for authorised testing, local labs, and defensive assessment workflows.</p>
        </div>
        <button type="button" onClick={() => onNavigate('portfolio-demo')}>Open Feature Tour</button>
      </section>

      <section className="metric-grid">
        {metrics.map(([label, value]) => <MetricCard key={String(label)} label={String(label)} value={String(value)} />)}
      </section>

      {!demoMode && jobs.length === 0 ? <EmptyState title="No findings yet." description="Create a safe local scan job or enable Portfolio Demo Mode to populate the dashboard with simulated redacted data." action="Enable Portfolio Demo Mode" onAction={onEnableDemo} /> : null}

      <section className="home-section">
        <h3>Platform Modules</h3>
        <div className="module-grid">
          {modules.map((module) => <button key={module} type="button" onClick={() => onNavigate(module.toLowerCase().includes('report') ? 'report-composer' : module.toLowerCase().includes('evidence') ? 'evidence-vault' : 'owasp')}>{module}</button>)}
        </div>
      </section>

      <section className="home-section">
        <h3>Recommended Workflow</h3>
        <ol className="workflow-list">
          {workflow.map((item) => <li key={item}>{item}</li>)}
        </ol>
      </section>

      {demoMode ? (
        <>
          <DemoSafetyNotice />
          <FeatureTour steps={dataset.feature_tour || []} />
        </>
      ) : null}
    </div>
  )
}

