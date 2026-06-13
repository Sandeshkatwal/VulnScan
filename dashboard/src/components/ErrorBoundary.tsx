import { Component, type ErrorInfo, type ReactNode } from 'react'

interface ErrorBoundaryProps {
  children: ReactNode
  fallback: ReactNode
}

interface ErrorBoundaryState {
  hasError: boolean
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { hasError: false }

  static getDerivedStateFromError(): ErrorBoundaryState {
    return { hasError: true }
  }

  componentDidCatch(_error: Error, _info: ErrorInfo) {
    // Keep render failures local to the dashboard; do not log sensitive UI state.
  }

  render() {
    if (this.state.hasError) return this.props.fallback
    return this.props.children
  }
}
