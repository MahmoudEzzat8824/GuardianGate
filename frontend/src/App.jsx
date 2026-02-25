import { useState, useEffect } from 'react'
import { Shield, Lock, AlertTriangle, Activity, Download, Database, CheckCircle, XCircle } from 'lucide-react'

// Risk Meter Gauge Component
function RiskMeter({ score }) {
  const getColor = (score) => {
    if (score >= 75) return '#ef4444' // red
    if (score >= 50) return '#f59e0b' // orange
    if (score >= 25) return '#eab308' // yellow
    return '#22c55e' // green
  }

  const getLabel = (score) => {
    if (score >= 75) return 'CRITICAL'
    if (score >= 50) return 'HIGH'
    if (score >= 25) return 'MODERATE'
    return 'LOW'
  }

  const rotation = (score / 100) * 180 - 90

  return (
    <div className="relative w-64 h-32 mx-auto">
      <svg viewBox="0 0 200 100" className="w-full h-full">
        {/* Background arc */}
        <path
          d="M 20 80 A 60 60 0 0 1 180 80"
          fill="none"
          stroke="#1f2937"
          strokeWidth="20"
          strokeLinecap="round"
        />
        {/* Colored arc */}
        <path
          d="M 20 80 A 60 60 0 0 1 180 80"
          fill="none"
          stroke={getColor(score)}
          strokeWidth="20"
          strokeLinecap="round"
          strokeDasharray={`${(score / 100) * 188.5} 188.5`}
        />
        {/* Needle */}
        <line
          x1="100"
          y1="80"
          x2="100"
          y2="30"
          stroke={getColor(score)}
          strokeWidth="3"
          strokeLinecap="round"
          transform={`rotate(${rotation} 100 80)`}
        />
        {/* Center circle */}
        <circle cx="100" cy="80" r="8" fill={getColor(score)} />
      </svg>
      <div className="absolute inset-x-0 bottom-0 text-center">
        <div className="text-3xl font-mono font-bold" style={{ color: getColor(score) }}>
          {score.toFixed(1)}
        </div>
        <div className="text-sm text-gray-400 font-mono">{getLabel(score)}</div>
      </div>
    </div>
  )
}

// Severity Badge Component
function SeverityBadge({ severity }) {
  const colors = {
    CRITICAL: 'bg-red-500/20 text-red-400 border-red-500/50',
    HIGH: 'bg-orange-500/20 text-orange-400 border-orange-500/50',
    MEDIUM: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50',
    LOW: 'bg-blue-500/20 text-blue-400 border-blue-500/50',
    INFO: 'bg-gray-500/20 text-gray-400 border-gray-500/50'
  }

  return (
    <span className={`px-2 py-1 rounded border text-xs font-mono font-bold ${colors[severity] || colors.INFO}`}>
      {severity}
    </span>
  )
}

function App() {
  const [scans, setScans] = useState([])
  const [readiness, setReadiness] = useState(null)
  const [riskScore, setRiskScore] = useState(0)
  const [loading, setLoading] = useState(true)

  const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

  useEffect(() => {
    fetchScans()
    fetchReadiness()
    const interval = setInterval(fetchScans, 10000) // Refresh every 10 seconds
    return () => clearInterval(interval)
  }, [])

  const fetchScans = async () => {
    try {
      const response = await fetch(`${API_URL}/scans`)
      const data = await response.json()
      setScans(data)
      
      // Calculate overall risk score from latest scans
      if (data.length > 0) {
        const avgRisk = data.slice(0, 5).reduce((sum, scan) => sum + scan.risk_score, 0) / Math.min(5, data.length)
        setRiskScore(avgRisk)
      }
      setLoading(false)
    } catch (error) {
      console.error('Error fetching scans:', error)
      setLoading(false)
    }
  }

  const fetchReadiness = async () => {
    try {
      const response = await fetch(`${API_URL}/readyz`)
      const data = await response.json()
      setReadiness(data)
    } catch (error) {
      console.error('Error fetching readiness:', error)
    }
  }

  const downloadReport = async (scanId) => {
    try {
      const response = await fetch(`${API_URL}/scans/${scanId}`)
      const data = await response.json()
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `scan-${scanId}-report.json`
      a.click()
    } catch (error) {
      console.error('Error downloading report:', error)
    }
  }

  // Get active alerts (scans with vulnerabilities)
  const activeAlerts = scans.filter(scan => scan.vulnerabilities_count > 0).slice(0, 10)

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 font-mono">
      {/* Header */}
      <header className="border-b border-gray-800 bg-gray-900/50 backdrop-blur">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Shield className="w-8 h-8 text-cyan-400" />
              <div>
                <h1 className="text-2xl font-bold text-cyan-400">GuardianGate</h1>
                <p className="text-xs text-gray-400">Security Orchestration Platform</p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              {readiness && (
                <div className="flex items-center space-x-2 text-sm">
                  {readiness.ready ? (
                    <>
                      <CheckCircle className="w-4 h-4 text-green-400" />
                      <span className="text-green-400">System Ready</span>
                    </>
                  ) : (
                    <>
                      <XCircle className="w-4 h-4 text-red-400" />
                      <span className="text-red-400">System Not Ready</span>
                    </>
                  )}
                </div>
              )}
              <Activity className="w-5 h-5 text-cyan-400 animate-pulse" />
            </div>
          </div>
        </div>
      </header>

      {/* Main Dashboard */}
      <main className="container mx-auto px-6 py-8">
        {loading ? (
          <div className="flex items-center justify-center h-64">
            <div className="text-cyan-400 text-lg">Loading security data...</div>
          </div>
        ) : (
          <div className="space-y-8">
            {/* Risk Meter Section */}
            <section className="bg-gray-900 border border-gray-800 rounded-lg p-6">
              <h2 className="text-xl font-bold mb-6 flex items-center">
                <Lock className="w-5 h-5 mr-2 text-cyan-400" />
                Overall Security Risk Score
              </h2>
              <RiskMeter score={riskScore} />
              <div className="mt-6 grid grid-cols-3 gap-4 text-center">
                <div className="bg-gray-800/50 rounded p-3">
                  <div className="text-2xl font-bold text-cyan-400">{scans.length}</div>
                  <div className="text-xs text-gray-400">Total Scans</div>
                </div>
                <div className="bg-gray-800/50 rounded p-3">
                  <div className="text-2xl font-bold text-orange-400">{activeAlerts.length}</div>
                  <div className="text-xs text-gray-400">Active Alerts</div>
                </div>
                <div className="bg-gray-800/50 rounded p-3">
                  <div className="text-2xl font-bold text-red-400">
                    {scans.reduce((sum, scan) => sum + scan.vulnerabilities_count, 0)}
                  </div>
                  <div className="text-xs text-gray-400">Total Vulnerabilities</div>
                </div>
              </div>
            </section>

            {/* Active Alerts Section */}
            <section className="bg-gray-900 border border-gray-800 rounded-lg p-6">
              <h2 className="text-xl font-bold mb-6 flex items-center">
                <AlertTriangle className="w-5 h-5 mr-2 text-orange-400" />
                Active Security Alerts
              </h2>
              {activeAlerts.length === 0 ? (
                <div className="text-center py-8 text-gray-500">
                  <Shield className="w-12 h-12 mx-auto mb-3 opacity-50" />
                  <p>No active alerts. All systems secure.</p>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead className="text-gray-400 border-b border-gray-800">
                      <tr>
                        <th className="text-left py-3 px-4">Repository</th>
                        <th className="text-left py-3 px-4">Scan Type</th>
                        <th className="text-left py-3 px-4">Severity</th>
                        <th className="text-right py-3 px-4">Vulnerabilities</th>
                        <th className="text-right py-3 px-4">Risk Score</th>
                        <th className="text-left py-3 px-4">Timestamp</th>
                      </tr>
                    </thead>
                    <tbody>
                      {activeAlerts.map((scan) => (
                        <tr key={scan.id} className="border-b border-gray-800 hover:bg-gray-800/30">
                          <td className="py-3 px-4 text-cyan-400">{scan.repository}</td>
                          <td className="py-3 px-4">
                            <span className="bg-gray-800 px-2 py-1 rounded text-xs uppercase">
                              {scan.scan_type}
                            </span>
                          </td>
                          <td className="py-3 px-4">
                            <SeverityBadge severity={scan.severity} />
                          </td>
                          <td className="py-3 px-4 text-right font-bold text-red-400">
                            {scan.vulnerabilities_count}
                          </td>
                          <td className="py-3 px-4 text-right font-bold">
                            {scan.risk_score.toFixed(1)}
                          </td>
                          <td className="py-3 px-4 text-gray-400 text-xs">
                            {new Date(scan.scan_timestamp).toLocaleString()}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>

            {/* Scan History Section */}
            <section className="bg-gray-900 border border-gray-800 rounded-lg p-6">
              <h2 className="text-xl font-bold mb-6 flex items-center">
                <Database className="w-5 h-5 mr-2 text-cyan-400" />
                Scan History
              </h2>
              {scans.length === 0 ? (
                <div className="text-center py-8 text-gray-500">
                  <Database className="w-12 h-12 mx-auto mb-3 opacity-50" />
                  <p>No scan history available yet.</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {scans.slice(0, 15).map((scan) => (
                    <div
                      key={scan.id}
                      className="flex items-center justify-between bg-gray-800/30 hover:bg-gray-800/50 px-4 py-3 rounded border border-gray-800"
                    >
                      <div className="flex items-center space-x-4 flex-1">
                        <Shield className="w-4 h-4 text-gray-500" />
                        <div className="flex-1">
                          <div className="font-semibold text-sm text-gray-200">{scan.repository}</div>
                          <div className="text-xs text-gray-500">
                            {scan.scan_type.toUpperCase()} • {new Date(scan.scan_timestamp).toLocaleString()}
                          </div>
                        </div>
                        <div className="flex items-center space-x-3">
                          <SeverityBadge severity={scan.severity} />
                          <div className="text-right">
                            <div className="text-sm font-bold">{scan.vulnerabilities_count} issues</div>
                            <div className="text-xs text-gray-500">Risk: {scan.risk_score.toFixed(1)}</div>
                          </div>
                        </div>
                      </div>
                      <button
                        onClick={() => downloadReport(scan.id)}
                        className="ml-4 p-2 hover:bg-gray-700 rounded transition-colors"
                        title="Download JSON report"
                      >
                        <Download className="w-4 h-4 text-cyan-400" />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </section>

            {/* Scanner Status */}
            {readiness && (
              <section className="bg-gray-900 border border-gray-800 rounded-lg p-6">
                <h2 className="text-xl font-bold mb-4">Scanner Status</h2>
                <div className="grid grid-cols-3 gap-4">
                  {Object.entries(readiness.scanners || {}).map(([scanner, available]) => (
                    <div key={scanner} className="bg-gray-800/30 rounded p-4 text-center">
                      <div className="font-mono text-lg uppercase mb-2">{scanner}</div>
                      <div className={`text-sm ${available ? 'text-green-400' : 'text-red-400'}`}>
                        {available ? '● Online' : '● Offline'}
                      </div>
                    </div>
                  ))}
                </div>
              </section>
            )}
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-gray-800 bg-gray-900/50 backdrop-blur mt-12">
        <div className="container mx-auto px-6 py-4 text-center text-gray-500 text-xs">
          GuardianGate v1.0.0 • Security Orchestration Platform • &copy; 2026
        </div>
      </footer>
    </div>
  )
}

export default App
