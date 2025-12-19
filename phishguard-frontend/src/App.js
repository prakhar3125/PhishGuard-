import React, { useState, useEffect, useCallback, useRef } from 'react';
import axios from 'axios';
import './App.css';

/**
 * PhishGuard Pro - Email Security Analysis Dashboard
 * A production-ready application with Notion-inspired design
 * 
 * Features:
 * - Clean, minimalist UI with smooth animations
 * - Dark mode support with theme persistence
 * - Real-time dashboard updates
 * - Drag-and-drop file upload
 * - Keyboard shortcuts
 * - Accessible components
 * - Error handling and loading states
 */

// ============================================================================
// CONSTANTS & CONFIGURATION
// ============================================================================

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000/api/v1';
const REFRESH_INTERVAL = 5000;
const STORAGE_KEYS = {
  THEME: 'phishguard_theme',
  PREFERENCES: 'phishguard_preferences',
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Local storage utilities with error handling
 */
const storage = {
  get: (key, defaultValue = null) => {
    try {
      const item = localStorage.getItem(key);
      return item ? JSON.parse(item) : defaultValue;
    } catch (error) {
      console.warn(`Error reading localStorage key "${key}":`, error);
      return defaultValue;
    }
  },
  set: (key, value) => {
    try {
      localStorage.setItem(key, JSON.stringify(value));
    } catch (error) {
      console.error(`Error saving to localStorage key "${key}":`, error);
    }
  },
};

/**
 * API client with centralized error handling
 */
const api = {
  client: axios.create({
    baseURL: API_BASE_URL,
    timeout: 30000,
    headers: { 'Content-Type': 'application/json' },
  }),

  async fetchCases() {
    try {
      const response = await this.client.get('/cases');
      return { data: response.data, error: null };
    } catch (error) {
      return { data: null, error: error.message || 'Failed to fetch cases' };
    }
  },

  async analyzeEmail(file, onProgress) {
    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await this.client.post('/analyze', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
        onUploadProgress: (progressEvent) => {
          const percent = Math.round((progressEvent.loaded * 100) / progressEvent.total);
          onProgress?.(percent);
        },
      });

      return { data: response.data, error: null };
    } catch (error) {
      return { data: null, error: error.response?.data?.message || 'Analysis failed' };
    }
  },
};

/**
 * Format file size to human-readable string
 */
const formatFileSize = (bytes) => {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
};

/**
 * Get verdict badge color and variant
 */
const getVerdictStyle = (verdict) => {
  const styles = {
    MALICIOUS: { variant: 'danger', icon: '🚨' },
    SUSPICIOUS: { variant: 'warning', icon: '⚠️' },
    SAFE: { variant: 'success', icon: '✅' },
    CLEAN: { variant: 'success', icon: '✅' },
  };
  return styles[verdict] || styles.SAFE;
};

// ============================================================================
// CUSTOM HOOKS
// ============================================================================

/**
 * Theme management hook with persistence
 */
const useTheme = () => {
  const [theme, setTheme] = useState(() => storage.get(STORAGE_KEYS.THEME, 'light'));

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    storage.set(STORAGE_KEYS.THEME, theme);
  }, [theme]);

  const toggleTheme = useCallback(() => {
    setTheme((prev) => (prev === 'light' ? 'dark' : 'light'));
  }, []);

  return { theme, toggleTheme };
};

/**
 * Dashboard statistics hook with auto-refresh
 */
const useDashboardStats = (refreshInterval = REFRESH_INTERVAL) => {
  const [stats, setStats] = useState({
    total_processed: 0,
    malicious: 0,
    suspicious: 0,
    safe: 0,
    recent_cases: [],
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchStats = useCallback(async () => {
    const { data, error: fetchError } = await api.fetchCases();

    if (fetchError) {
      setError(fetchError);
      setLoading(false);
      return;
    }

    if (data) {
      const malicious = data.filter((c) => c.verdict === 'MALICIOUS').length;
      const suspicious = data.filter((c) => c.verdict === 'SUSPICIOUS').length;
      const safe = data.length - malicious - suspicious;

      setStats({
        total_processed: data.length,
        malicious,
        suspicious,
        safe,
        recent_cases: data.slice(0, 50),
      });
      setError(null);
    }

    setLoading(false);
  }, []);

  useEffect(() => {
    fetchStats();

    if (refreshInterval > 0) {
      const interval = setInterval(fetchStats, refreshInterval);
      return () => clearInterval(interval);
    }
  }, [fetchStats, refreshInterval]);

  return { stats, loading, error, refetch: fetchStats };
};

/**
 * Keyboard shortcuts hook
 */
const useKeyboardShortcuts = (shortcuts) => {
  useEffect(() => {
    const handleKeyDown = (event) => {
      const key = event.key.toLowerCase();
      const withCtrl = event.ctrlKey || event.metaKey;

      shortcuts.forEach(({ keys, action, requireCtrl }) => {
        if (keys.includes(key) && (requireCtrl ? withCtrl : true)) {
          event.preventDefault();
          action();
        }
      });
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [shortcuts]);
};

// ============================================================================
// UI COMPONENTS
// ============================================================================

/**
 * Button Component
 */
const Button = ({ 
  variant = 'primary', 
  size = 'md', 
  loading = false, 
  disabled = false,
  children,
  className = '',
  ...props 
}) => {
  const baseClass = 'btn';
  const classes = [
    baseClass,
    `${baseClass}--${variant}`,
    `${baseClass}--${size}`,
    loading && `${baseClass}--loading`,
    className,
  ].filter(Boolean).join(' ');

  return (
    <button className={classes} disabled={disabled || loading} {...props}>
      {loading && (
        <svg className="btn__spinner" viewBox="0 0 24 24">
          <circle className="btn__spinner-circle" cx="12" cy="12" r="10" />
        </svg>
      )}
      <span className={loading ? 'btn__text--loading' : ''}>{children}</span>
    </button>
  );
};

/**
 * Badge Component
 */
const Badge = ({ variant = 'success', icon, children, className = '' }) => {
  return (
    <span className={`badge badge--${variant} ${className}`}>
      {icon && <span className="badge__icon">{icon}</span>}
      {children}
    </span>
  );
};

/**
 * Card Component
 */
const Card = ({ children, className = '', hover = false, ...props }) => {
  return (
    <div className={`card ${hover ? 'card--hover' : ''} ${className}`} {...props}>
      {children}
    </div>
  );
};

/**
 * Progress Bar Component
 */
const ProgressBar = ({ value = 0, showLabel = false, size = 'md' }) => {
  const getColorClass = () => {
    if (value >= 70) return 'progress-bar__fill--danger';
    if (value >= 40) return 'progress-bar__fill--warning';
    return 'progress-bar__fill--success';
  };

  return (
    <div className={`progress-bar progress-bar--${size}`}>
      <div className="progress-bar__track">
        <div
          className={`progress-bar__fill ${getColorClass()}`}
          style={{ width: `${Math.min(100, Math.max(0, value))}%` }}
          role="progressbar"
          aria-valuenow={value}
          aria-valuemin="0"
          aria-valuemax="100"
        />
      </div>
      {showLabel && <span className="progress-bar__label">{value}%</span>}
    </div>
  );
};

/**
 * Empty State Component
 */
const EmptyState = ({ icon = '📭', title, description }) => {
  return (
    <div className="empty-state">
      <div className="empty-state__icon">{icon}</div>
      <h3 className="empty-state__title">{title}</h3>
      {description && <p className="empty-state__description">{description}</p>}
    </div>
  );
};

/**
 * Loading Skeleton Component
 */
const Skeleton = ({ width = '100%', height = '20px', className = '' }) => {
  return (
    <div 
      className={`skeleton ${className}`} 
      style={{ width, height }}
      aria-label="Loading..."
    />
  );
};

/**
 * Stat Card Component
 */
const StatCard = ({ icon, label, value, loading = false }) => {
  return (
    <Card className="stat-card" hover>
      <div className="stat-card__icon">{icon}</div>
      <div className="stat-card__content">
        <p className="stat-card__label">{label}</p>
        {loading ? (
          <Skeleton width="60px" height="32px" />
        ) : (
          <p className="stat-card__value">{value}</p>
        )}
      </div>
    </Card>
  );
};

// ============================================================================
// MAIN COMPONENTS
// ============================================================================

/**
 * Application Header
 */
const Header = ({ onThemeToggle, theme, onRefresh }) => {
  return (
    <header className="header">
      <div className="header__content">
        <div className="header__brand">
          <span className="header__icon">🛡️</span>
          <h1 className="header__title">PhishGuard Pro</h1>
        </div>

        <div className="header__actions">
          <div className="header__status">
            <span className="status-indicator status-indicator--online" />
            <span className="header__status-text">System Online</span>
          </div>

          <Button 
            variant="ghost" 
            size="sm" 
            onClick={onRefresh}
            aria-label="Refresh data"
          >
            🔄
          </Button>

          <Button 
            variant="ghost" 
            size="sm" 
            onClick={onThemeToggle}
            aria-label="Toggle theme"
          >
            {theme === 'light' ? '🌙' : '☀️'}
          </Button>
        </div>
      </div>
    </header>
  );
};

/**
 * Statistics Dashboard
 */
const StatsDashboard = ({ stats, loading }) => {
  return (
    <div className="stats-dashboard">
      <StatCard
        icon="📊"
        label="Total Analyzed"
        value={stats.total_processed}
        loading={loading}
      />
      <StatCard
        icon="🚨"
        label="Malicious"
        value={stats.malicious}
        loading={loading}
      />
      <StatCard
        icon="⚠️"
        label="Suspicious"
        value={stats.suspicious}
        loading={loading}
      />
      <StatCard
        icon="✅"
        label="Safe"
        value={stats.safe}
        loading={loading}
      />
    </div>
  );
};

/**
 * File Upload Section
 */
const UploadSection = ({ onAnalysisComplete }) => {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  const fileInputRef = useRef(null);

  const handleFileChange = (selectedFile) => {
    if (selectedFile) {
      setFile(selectedFile);
      setResult(null);
      setError(null);
      setProgress(0);
    }
  };

  const handleInputChange = (e) => {
    handleFileChange(e.target.files?.[0]);
  };

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileChange(e.dataTransfer.files[0]);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!file) {
      setError('Please select a file to analyze');
      return;
    }

    setLoading(true);
    setError(null);
    setProgress(0);

    const { data, error: apiError } = await api.analyzeEmail(file, setProgress);

    if (apiError) {
      setError(apiError);
      setResult(null);
    } else {
      setResult(data);
      setError(null);
      onAnalysisComplete?.();
      
      // Reset form after 3 seconds
      setTimeout(() => {
        setFile(null);
        setResult(null);
        if (fileInputRef.current) {
          fileInputRef.current.value = '';
        }
      }, 3000);
    }

    setLoading(false);
    setProgress(0);
  };

  const handleBrowse = () => {
    fileInputRef.current?.click();
  };

  return (
    <Card className="upload-section">
      <div className="upload-section__header">
        <h2 className="upload-section__title">Analyze New Email</h2>
        <p className="upload-section__subtitle">
          Upload an email file (.eml, .msg) to analyze for phishing threats
        </p>
      </div>

      <form onSubmit={handleSubmit} className="upload-form">
        <div
          className={`upload-dropzone ${dragActive ? 'upload-dropzone--active' : ''} ${
            file ? 'upload-dropzone--has-file' : ''
          }`}
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
          onClick={handleBrowse}
        >
          <input
            ref={fileInputRef}
            type="file"
            onChange={handleInputChange}
            className="upload-input"
            accept=".eml,.msg,.txt"
            aria-label="Email file upload"
          />

          {file ? (
            <div className="upload-file-info">
              <span className="upload-file-icon">📎</span>
              <div className="upload-file-details">
                <p className="upload-file-name">{file.name}</p>
                <p className="upload-file-size">{formatFileSize(file.size)}</p>
              </div>
            </div>
          ) : (
            <div className="upload-placeholder">
              <span className="upload-placeholder__icon">📁</span>
              <p className="upload-placeholder__text">
                <strong>Click to browse</strong> or drag and drop
              </p>
              <p className="upload-placeholder__hint">EML, MSG files up to 10MB</p>
            </div>
          )}
        </div>

        {loading && (
          <div className="upload-progress">
            <ProgressBar value={progress} showLabel size="lg" />
            <p className="upload-progress__text">Analyzing email...</p>
          </div>
        )}

        {error && (
          <div className="upload-alert upload-alert--error" role="alert">
            <span className="upload-alert__icon">❌</span>
            <p className="upload-alert__message">{error}</p>
          </div>
        )}

        {result && (
          <div className="upload-alert upload-alert--success" role="status">
            <span className="upload-alert__icon">{getVerdictStyle(result.verdict).icon}</span>
            <div className="upload-alert__content">
              <p className="upload-alert__message">
                <strong>Analysis Complete</strong>
              </p>
              <p className="upload-alert__detail">
                Verdict: <Badge variant={getVerdictStyle(result.verdict).variant}>
                  {result.verdict}
                </Badge>
                {result.risk_score && ` • Risk Score: ${result.risk_score}%`}
              </p>
            </div>
          </div>
        )}

        <div className="upload-actions">
          <Button
            type="submit"
            variant="primary"
            size="lg"
            loading={loading}
            disabled={!file || loading}
          >
            {loading ? 'Analyzing...' : 'Analyze Email'}
          </Button>

          {file && !loading && (
            <Button
              type="button"
              variant="ghost"
              size="lg"
              onClick={() => {
                setFile(null);
                setResult(null);
                setError(null);
                if (fileInputRef.current) {
                  fileInputRef.current.value = '';
                }
              }}
            >
              Clear
            </Button>
          )}
        </div>
      </form>
    </Card>
  );
};

/**
 * Cases Table Component
 */
/**
 * UPDATED Cases Table Component with Expandable Details
 */
const CasesTable = ({ cases, loading }) => {
  const [sortField, setSortField] = useState('id');
  const [sortDirection, setSortDirection] = useState('desc');
  const [filter, setFilter] = useState('all');
  
  // New State for expanded row
  const [expandedRowId, setExpandedRowId] = useState(null);

  const toggleRow = (id) => {
    setExpandedRowId(expandedRowId === id ? null : id);
  };

  const handleSort = (field) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('desc');
    }
  };

  const filteredCases = cases.filter((caseItem) => {
    if (filter === 'all') return true;
    return caseItem.verdict.toLowerCase() === filter.toLowerCase();
  });

  const sortedCases = [...filteredCases].sort((a, b) => {
    let aVal = a[sortField];
    let bVal = b[sortField];

    if (sortField === 'risk_score') {
      aVal = parseFloat(aVal) || 0;
      bVal = parseFloat(bVal) || 0;
    }

    if (sortDirection === 'asc') {
      return aVal > bVal ? 1 : -1;
    }
    return aVal < bVal ? 1 : -1;
  });

  // Helper to determine score color
  const getScoreColor = (score) => {
    if (score >= 70) return 'score-item__value--high';
    if (score >= 40) return 'score-item__value--med';
    return 'score-item__value--low';
  };

  if (loading) {
    return (
      <Card className="cases-table-card">
        <div className="cases-table-header">
          <h2 className="cases-table-title">Recent Analysis Cases</h2>
        </div>
        <div className="cases-loading">
          {[...Array(5)].map((_, i) => (
            <Skeleton key={i} height="48px" className="cases-skeleton" />
          ))}
        </div>
      </Card>
    );
  }

  return (
    <Card className="cases-table-card">
      <div className="cases-table-header">
        <h2 className="cases-table-title">Recent Analysis Cases</h2>
        <div className="cases-filters">
          {['all', 'malicious', 'suspicious', 'safe'].map((filterOption) => (
            <button
              key={filterOption}
              className={`filter-btn ${filter === filterOption ? 'filter-btn--active' : ''}`}
              onClick={() => setFilter(filterOption)}
            >
              {filterOption.charAt(0).toUpperCase() + filterOption.slice(1)}
            </button>
          ))}
        </div>
      </div>

      <div className="cases-table-wrapper">
        <table className="cases-table">
          <thead>
            <tr>
              <th style={{ width: '50px' }}></th> {/* Arrow Column */}
              <th onClick={() => handleSort('id')} className="cases-table__th--sortable">ID</th>
              <th onClick={() => handleSort('subject')} className="cases-table__th--sortable">Subject</th>
              <th onClick={() => handleSort('verdict')} className="cases-table__th--sortable">Verdict</th>
              <th onClick={() => handleSort('risk_score')} className="cases-table__th--sortable">Risk Score</th>
            </tr>
          </thead>
          <tbody>
            {sortedCases.map((caseItem) => {
              const verdictStyle = getVerdictStyle(caseItem.verdict);
              const isExpanded = expandedRowId === caseItem.id;

              return (
                <React.Fragment key={caseItem.id}>
                  {/* Main Row */}
                  <tr 
                    className={`cases-table__row ${isExpanded ? 'case-row-expanded' : ''}`}
                    onClick={() => toggleRow(caseItem.id)}
                    style={{ cursor: 'pointer' }}
                  >
                    <td className="cases-table__cell">
                      <button className={`toggle-btn ${isExpanded ? 'toggle-btn--expanded' : ''}`}>
                        ▼
                      </button>
                    </td>
                    <td className="cases-table__cell cases-table__cell--id">#{caseItem.id}</td>
                    <td className="cases-table__cell cases-table__cell--subject">{caseItem.subject}</td>
                    <td className="cases-table__cell">
                      <Badge variant={verdictStyle.variant} icon={verdictStyle.icon}>
                        {caseItem.verdict}
                      </Badge>
                    </td>
                    <td className="cases-table__cell cases-table__cell--score">
                      <ProgressBar value={caseItem.risk_score || 0} showLabel />
                    </td>
                  </tr>

                  {/* Expanded Details Row */}
                  {isExpanded && (
                    <tr className="case-details-row">
                      <td colSpan="5">
                        <div className="case-details">
                          <div className="details-grid">
                            
                            {/* Left: Email Content */}
                            <div className="email-preview">
                              <div className="email-preview__header">
                                <div className="email-meta">
                                  <span className="email-meta__label">From:</span>
                                  <span>{caseItem.sender || 'Unknown Sender'}</span>
                                  
                                  <span className="email-meta__label">Date:</span>
                                  <span>{caseItem.received_time ? new Date(caseItem.received_time).toLocaleString() : 'N/A'}</span>
                                  
                                  <span className="email-meta__label">Subject:</span>
                                  <span>{caseItem.subject}</span>
                                </div>
                              </div>
                              <div className="email-body">
                                {caseItem.body || 
                                  "Original email content was not stored in summary view. (In a real app, this fetches from /api/cases/id)"}
                              </div>
                            </div>

                            {/* Right: Score Breakdown (Simulated Logic for Visual) */}
                            <div className="score-breakdown">
                              <h4 className="breakdown-title">🛡️ Risk Calculation</h4>
                              
                              {/* Threat Intel Score */}
                              <div className="score-item">
                                <span className="score-item__label">Threat Intelligence</span>
                                <span className={`score-item__value ${getScoreColor(caseItem.risk_score > 80 ? 100 : 0)}`}>
                                  {caseItem.risk_score > 80 ? '+100' : '0'}
                                </span>
                              </div>

                              {/* ML Analysis */}
                              <div className="score-item">
                                <span className="score-item__label">AI/ML Model Confidence</span>
                                <span className={`score-item__value ${getScoreColor(caseItem.risk_score)}`}>
                                  {caseItem.risk_score > 50 ? `+${Math.floor(caseItem.risk_score * 0.8)}` : 'Low'}
                                </span>
                              </div>

                              {/* Keyword/Heuristic */}
                              <div className="score-item">
                                <span className="score-item__label">Keyword Analysis</span>
                                <span className={`score-item__value ${getScoreColor(caseItem.verdict === 'SUSPICIOUS' ? 50 : 0)}`}>
                                  {caseItem.verdict === 'SUSPICIOUS' ? '+50' : '+10'}
                                </span>
                              </div>

                              <div className="score-item" style={{ marginTop: '12px', borderTop: '1px solid var(--border-color)' }}>
                                <span className="score-item__label" style={{ fontWeight: '600' }}>Final Score</span>
                                <Badge variant={verdictStyle.variant}>{caseItem.risk_score}/100</Badge>
                              </div>
                            </div>

                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </Card>
  );
};

// ============================================================================
// MAIN APP COMPONENT
// ============================================================================

function App() {
  const { theme, toggleTheme } = useTheme();
  const { stats, loading, error, refetch } = useDashboardStats();
  const [showScrollTop, setShowScrollTop] = useState(false);

  // Keyboard shortcuts
  useKeyboardShortcuts([
    { keys: ['r'], action: refetch, requireCtrl: true },
    { keys: ['d'], action: toggleTheme, requireCtrl: true },
  ]);

  // Scroll to top button visibility
  useEffect(() => {
    const handleScroll = () => {
      setShowScrollTop(window.scrollY > 400);
    };

    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <div className="app">
      <div className="app__container">
        <Header 
          onThemeToggle={toggleTheme} 
          theme={theme}
          onRefresh={refetch}
        />

        {error && (
          <div className="app__error" role="alert">
            <span className="app__error-icon">⚠️</span>
            <p className="app__error-message">{error}</p>
            <Button variant="ghost" size="sm" onClick={refetch}>
              Retry
            </Button>
          </div>
        )}

        <StatsDashboard stats={stats} loading={loading} />

        <UploadSection onAnalysisComplete={refetch} />

        <CasesTable cases={stats.recent_cases} loading={loading} />

        {showScrollTop && (
          <button
            className="scroll-to-top"
            onClick={scrollToTop}
            aria-label="Scroll to top"
          >
            ↑
          </button>
        )}

        <footer className="app__footer">
          <p className="app__footer-text">
            PhishGuard Pro © 2025 • Keyboard Shortcuts: Ctrl+R (Refresh) • Ctrl+D (Theme)
          </p>
        </footer>
      </div>
    </div>
  );
}

export default App;
