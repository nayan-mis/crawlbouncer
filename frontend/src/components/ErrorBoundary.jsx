import { Component } from 'react'

/**
 * Without this, any unhandled render error in any page component takes
 * the entire dashboard down to a blank white screen with no recovery
 * path — found in the audit (docs/AUDIT.md 3.1), fixed here.
 */
export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error }
  }

  componentDidCatch(error, info) {
    // eslint-disable-next-line no-console
    console.error('Dashboard error boundary caught:', error, info)
  }

  handleReload = () => window.location.reload()

  render() {
    if (!this.state.hasError) return this.props.children
    return (
      <div style={{
        display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
        minHeight: 300, gap: 12, padding: 40, textAlign: 'center',
      }}>
        <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--t1)' }}>Something went wrong</div>
        <div style={{ fontSize: 12.5, color: 'var(--t2)', maxWidth: 360 }}>
          This part of the dashboard hit an error. Your data is safe — reloading usually fixes it.
        </div>
        <button className="btn btn-default" onClick={this.handleReload}>Reload</button>
      </div>
    )
  }
}
