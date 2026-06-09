import { useEffect, useMemo, useState } from 'react'
import { getRoles, mapRoleEndpoints } from '../api/client'
import type { JobResultResponse, ManualValidationPlan, PermissionMatrix, RoleEndpointMatrixRow, RoleMappingResponse, RoleProfile } from '../types/api'
import { ErrorAlert } from './ErrorAlert'

interface RolePermissionMappingViewProps {
  apiOnline: boolean
  demoMode?: boolean
  jobResult?: JobResultResponse | null
}

const demoRoles: RoleProfile[] = [
  { role_id: 'standard_user', role_name: 'standard_user', role_label: 'Standard User', user_type: 'standard_user', expected_access_level: 'own_account', linked_session_profile_name: 'Sample Redacted Session Profile', notes: 'Own-account workflows only.' },
  { role_id: 'read_only_user', role_name: 'read_only_user', role_label: 'Read Only User', user_type: 'read_only_user', expected_access_level: 'read_only', notes: 'No state-changing actions.' },
  { role_id: 'admin_user', role_name: 'admin_user', role_label: 'Admin User', user_type: 'admin_user', expected_access_level: 'administrative', notes: 'Authorised admin test role only.' },
  { role_id: 'tenant_a_user', role_name: 'tenant_a_user', role_label: 'Tenant A User', user_type: 'tenant_user', tenant_label: 'tenant-a', expected_access_level: 'tenant_a_only', notes: 'Tenant boundary planning.' },
]

const demoMatrix: PermissionMatrix = {
  matrix_id: 'demo_matrix',
  matrix_name: 'Demo Access-Control Matrix',
  target: 'local-demo',
  actions: [
    { action_id: 'view', action_name: 'View', action_type: 'view', sensitivity: 'low', state_changing: false, destructive: false, requires_manual_validation: true },
    { action_id: 'export', action_name: 'Export', action_type: 'export', sensitivity: 'high', state_changing: false, destructive: false, requires_manual_validation: true },
    { action_id: 'manage_users', action_name: 'Manage Users', action_type: 'manage_users', sensitivity: 'critical', state_changing: true, destructive: false, requires_manual_validation: true },
    { action_id: 'delete', action_name: 'Delete', action_type: 'delete', sensitivity: 'critical', state_changing: true, destructive: true, requires_manual_validation: true },
  ],
  role_action_rules: [
    { role_id: 'standard_user', action_id: 'view', expected_permission: 'allowed', validation_status: 'not_tested' },
    { role_id: 'standard_user', action_id: 'manage_users', expected_permission: 'denied', validation_status: 'not_tested' },
    { role_id: 'read_only_user', action_id: 'export', expected_permission: 'denied', validation_status: 'not_tested' },
    { role_id: 'admin_user', action_id: 'manage_users', expected_permission: 'allowed', validation_status: 'not_tested' },
    { role_id: 'tenant_a_user', action_id: 'view', expected_permission: 'conditional', validation_status: 'not_tested' },
  ],
}

const demoEndpoints = [
  { url: 'http://127.0.0.1:8000/profile', method: 'GET', endpoint_category: 'account' },
  { url: 'http://127.0.0.1:8000/admin/users', method: 'GET', endpoint_category: 'admin' },
  { url: 'http://127.0.0.1:8000/reports/export', method: 'GET', endpoint_category: 'report' },
  { url: 'http://127.0.0.1:8000/upload', method: 'POST', endpoint_category: 'upload' },
]

export function RolePermissionMappingView({ apiOnline, demoMode = false, jobResult }: RolePermissionMappingViewProps) {
  const [roles, setRoles] = useState<RoleProfile[]>(demoRoles)
  const [matrix] = useState<PermissionMatrix>(demoMatrix)
  const [mapping, setMapping] = useState<RoleMappingResponse | null>(demoMode ? null : null)
  const [selectedPlan, setSelectedPlan] = useState<ManualValidationPlan | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const resultPayload = jobResult?.result as Record<string, unknown> | null | undefined
  const endpointResults = useMemo(() => {
    const fromResult = (resultPayload?.endpoint_results as Array<Record<string, unknown>> | undefined) || []
    return fromResult.length ? fromResult : demoEndpoints
  }, [resultPayload])

  useEffect(() => {
    if (demoMode || !apiOnline) return
    getRoles().then((response) => {
      if (response.roles?.length) setRoles(response.roles)
      if (response.role_profiles?.length) setRoles(response.role_profiles)
    }).catch((caught) => setError(errorMessage(caught)))
  }, [apiOnline, demoMode])

  async function buildMatrix() {
    setLoading(true)
    setError(null)
    try {
      const response = demoMode
        ? buildDemoMapping(roles, matrix, endpointResults)
        : await mapRoleEndpoints({ roles, permission_matrix: matrix, endpoint_results: endpointResults })
      setMapping(response)
      setSelectedPlan((response.manual_validation_plans || [])[0] || null)
    } catch (caught) {
      setError(errorMessage(caught))
    } finally {
      setLoading(false)
    }
  }

  const inferredActions = mapping?.inferred_actions || []
  const rows = mapping?.role_endpoint_matrix || []
  const plans = mapping?.manual_validation_plans || []
  const roleRules = matrix.role_action_rules || []

  return (
    <section className="content-grid role-mapping-view">
      <article className="panel panel--wide">
        <div className="panel-heading">
          <div>
            <h2>Role & Permission Mapping</h2>
            <p>A01 Access-Control Planning, Access-Control Matrix, Role-Based Endpoint Review, and Manual Validation Required plans.</p>
          </div>
          <button className="primary-button" type="button" disabled={loading} onClick={() => void buildMatrix()}>Build Matrix</button>
        </div>
        <div className="auth-safety-notice">Role mapping is a planning and documentation assistant. VulScan does not perform automatic role comparison, account-to-account requests, or state-changing access checks.</div>
        <ErrorAlert message={error} />
      </article>

      <article className="panel panel--wide">
        <div className="panel-heading"><h2>Role Profiles</h2><p>Safe labels only. No usernames, passwords, session cookies, bearer tokens, or Authorization headers.</p></div>
        <div className="table-shell"><table><thead><tr><th>Role</th><th>User Type</th><th>Tenant</th><th>Linked Session Profile</th><th>Access Level</th><th>Permission Notes</th></tr></thead><tbody>
          {roles.map((role) => <tr key={role.role_id}><td>{role.role_label}</td><td>{role.user_type}</td><td>{role.tenant_label || 'None'}</td><td>{role.linked_session_profile_name || 'None'}</td><td>{role.expected_access_level}</td><td>{role.notes}</td></tr>)}
        </tbody></table></div>
      </article>

      <article className="panel panel--wide">
        <div className="panel-heading"><h2>Permission Matrix</h2><p>Allowed Action, Disallowed Action, conditional, and unknown expectations.</p></div>
        <div className="permission-grid">
          {(matrix.actions || []).map((action) => (
            <div className="permission-row" key={action.action_id}>
              <strong>{action.action_name}</strong>
              {roles.map((role) => <span key={`${role.role_id}-${action.action_id}`}>{permissionFor(role.role_id, action.action_id, roleRules)}</span>)}
            </div>
          ))}
        </div>
      </article>

      <article className="panel panel--wide">
        <div className="panel-heading"><h2>Endpoint Action Mapping</h2><p>Inference only. VulScan does not call state-changing endpoints.</p></div>
        <div className="table-shell"><table><thead><tr><th>Endpoint</th><th>Inferred Action</th><th>Sensitivity</th><th>State-Changing</th><th>Destructive</th><th>Manual Validation</th></tr></thead><tbody>
          {(inferredActions.length ? inferredActions : endpointResults).map((raw, index) => {
            const item = raw as Record<string, unknown>
            return <tr key={`${String(item.url || item.endpoint)}-${index}`}><td>{String(item.endpoint || item.url || item.normalised_url || '')}</td><td>{String(item.inferred_action || 'not mapped')}</td><td>{String(item.sensitivity || '')}</td><td>{String(item.state_changing ?? '')}</td><td>{String(item.destructive ?? '')}</td><td>{String(item.requires_manual_validation ?? 'true')}</td></tr>
          })}
        </tbody></table></div>
      </article>

      <article className="panel panel--wide">
        <div className="panel-heading"><h2>Role Endpoint Matrix</h2><p>Role-Based Endpoint Review rows linked to Manual Validation Required plans.</p></div>
        <RoleEndpointMatrix rows={rows} onSelectPlan={(planId) => setSelectedPlan(plans.find((plan) => plan.plan_id === planId) || null)} />
      </article>

      <article className="panel panel--wide">
        <div className="panel-heading"><h2>Manual Validation Plan</h2><p>Safe manual steps and redacted evidence requirements.</p></div>
        {selectedPlan ? <ManualPlan plan={selectedPlan} /> : <div className="panel-message">Build the matrix to generate Manual Validation Required plans.</div>}
      </article>

      <article className="panel panel--wide">
        <div className="panel-heading"><h2>Role Comparison Notes</h2><p>Manual notes only. VulScan does not compare accounts automatically.</p></div>
        <div className="table-shell"><table><thead><tr><th>Role A</th><th>Role B</th><th>Endpoint/Action</th><th>Expected Difference</th><th>Observed Manual Result</th><th>Status</th></tr></thead><tbody>
          <tr><td>tenant_a_user</td><td>tenant_b_user</td><td>/tenant-b/reports / view</td><td>Tenant A User should not view tenant B resources.</td><td>Not recorded</td><td>planned</td></tr>
        </tbody></table></div>
      </article>
    </section>
  )
}

function RoleEndpointMatrix({ rows, onSelectPlan }: { rows: RoleEndpointMatrixRow[]; onSelectPlan: (planId?: string) => void }) {
  if (!rows.length) return <div className="panel-message">No Role Endpoint Matrix has been built yet.</div>
  return <div className="table-shell"><table><thead><tr><th>Role</th><th>Endpoint</th><th>Expected Permission</th><th>Validation Status</th><th>Manual Plan</th></tr></thead><tbody>
    {rows.slice(0, 30).map((row) => <tr key={`${row.role_id}-${row.endpoint}-${row.action_id}`}><td>{row.role_label}</td><td>{row.endpoint}</td><td>{row.expected_permission}</td><td>{row.validation_status}</td><td><button className="secondary-button" type="button" onClick={() => onSelectPlan(row.manual_plan_id)}>View Plan</button></td></tr>)}
  </tbody></table></div>
}

function ManualPlan({ plan }: { plan: ManualValidationPlan }) {
  return <div className="manual-plan-card">
    <div><span>Role</span><strong>{plan.role_label}</strong></div>
    <div><span>Endpoint</span><strong>{plan.endpoint}</strong></div>
    <div><span>Expected Permission</span><strong>{plan.expected_permission}</strong></div>
    <div><span>Expected Secure Result</span><p>{plan.expected_secure_result}</p></div>
    <div><span>Risk If Failed</span><p>{plan.risk_if_failed}</p></div>
    <div><span>Safe Manual Steps</span><ul>{(plan.safe_manual_steps || []).map((step) => <li key={step}>{step}</li>)}</ul></div>
    <div><span>Evidence To Collect</span><ul>{(plan.evidence_to_collect || []).map((item) => <li key={item}>{item}</li>)}</ul></div>
    <div><span>Safety Notes</span><ul>{(plan.safety_notes || []).map((item) => <li key={item}>{item}</li>)}</ul></div>
  </div>
}

function permissionFor(roleId?: string, actionId?: string, rules: Array<Record<string, unknown>> = []) {
  return String(rules.find((rule) => rule.role_id === roleId && rule.action_id === actionId)?.expected_permission || 'unknown')
}

function buildDemoMapping(roles: RoleProfile[], matrix: PermissionMatrix, endpoints: Array<Record<string, unknown>>): RoleMappingResponse {
  const inferred = endpoints.map((endpoint) => {
    const url = String(endpoint.url || endpoint.normalised_url || '')
    const action = url.includes('/admin/users') ? 'manage_users' : url.includes('/export') ? 'export' : url.includes('/upload') ? 'upload' : 'view'
    return { endpoint: url, method: endpoint.method || 'GET', inferred_action: action, action_id: action, sensitivity: action === 'view' ? 'low' : action === 'manage_users' ? 'critical' : 'high', state_changing: action === 'upload' || action === 'manage_users', destructive: false, requires_manual_validation: true }
  })
  const rows = roles.flatMap((role) => inferred.map((item) => ({ role_id: role.role_id, role_label: role.role_label, tenant_label: role.tenant_label || undefined, endpoint: String(item.endpoint), inferred_action: String(item.inferred_action), action_id: String(item.action_id), expected_permission: permissionFor(role.role_id, String(item.action_id), matrix.role_action_rules || []), validation_status: 'not_tested', manual_plan_id: `demo_plan_${role.role_id}_${item.action_id}` })))
  const plans = rows.map((row) => ({ plan_id: row.manual_plan_id, role_label: row.role_label, tenant_label: row.tenant_label || undefined, endpoint: row.endpoint, inferred_action: row.inferred_action, expected_permission: row.expected_permission, expected_secure_result: `${row.inferred_action} follows the documented Access-Control Matrix expectation.`, risk_if_failed: `Potential access-control planning issue for ${row.role_label}.`, safe_manual_steps: ['Use authorised test account only.', 'Do not perform destructive actions.', 'Capture redacted evidence only.'], evidence_to_collect: ['Redacted screenshot or response metadata.', 'Role label and expected permission.'], safety_notes: ['Authorised Test Accounts Only.'], status: 'planned' }))
  return { role_mapping_summary: { enabled: true, role_count: roles.length, endpoint_count: endpoints.length, role_endpoint_rows: rows.length, manual_validation_plan_count: plans.length }, role_profiles: roles, permission_matrix: matrix, inferred_actions: inferred, role_endpoint_matrix: rows, manual_validation_plans: plans }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Request failed.'
}
