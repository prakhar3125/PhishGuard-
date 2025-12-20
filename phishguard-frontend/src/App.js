import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import axios from 'axios';
import './App.css';
import {
  Shield,
  FileText,
  AlertTriangle,
  AlertOctagon,
  CheckCircle,
  Upload,
  File,
  ChevronDown,
  Activity,
  X,
  Check,
  RefreshCw,
  Moon,
  Sun,
  XCircle,
  ArrowUp,
  Search,
  Filter,
  Download,
  Trash2,
  Eye,
  EyeOff,
  Clock,
  Mail,
  Link as LinkIcon,
  Hash,
  TrendingUp,
  TrendingDown,
  Minus,
  Calendar,
  Globe,
  Server,
  Database,
  Zap,
  Bell,
  Settings,
  HelpCircle,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Copy,
  ExternalLink,
  Info,
  BarChart3,
  PieChart,
  LineChart
} from "lucide-react";

// ============================================================================
// CONSTANTS & CONFIGURATION
// ============================================================================

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000/api/v1';
const REFRESH_INTERVAL = 5000;
const STORAGE_KEYS = {
  THEME: 'phishguard_theme',
  PREFERENCES: 'phishguard_preferences',
  CASES_PER_PAGE: 'phishguard_cases_per_page',
  COLUMN_VISIBILITY: 'phishguard_column_visibility',
  NOTIFICATION_SETTINGS: 'phishguard_notifications',
};

const VERDICT_TYPES = {
  MALICIOUS: 'MALICIOUS',
  SUSPICIOUS: 'SUSPICIOUS',
  SAFE: 'SAFE',
  CLEAN: 'CLEAN',
  UNKNOWN: 'UNKNOWN'
};

const SORT_FIELDS = {
  ID: 'id',
  SUBJECT: 'subject',
  VERDICT: 'verdict',
  RISK_SCORE: 'risk_score',
  PROCESSED_AT: 'processed_at',
  SENDER: 'sender'
};

const PAGE_SIZES = [10, 25, 50, 100];

const NOTIFICATION_TYPES = {
  SUCCESS: 'success',
  ERROR: 'error',
  WARNING: 'warning',
  INFO: 'info'
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Local storage utilities with error handling and validation
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
      return true;
    } catch (error) {
      console.error(`Error saving to localStorage key "${key}":`, error);
      return false;
    }
  },
  
  remove: (key) => {
    try {
      localStorage.removeItem(key);
      return true;
    } catch (error) {
      console.error(`Error removing localStorage key "${key}":`, error);
      return false;
    }
  },
  
  clear: () => {
    try {
      localStorage.clear();
      return true;
    } catch (error) {
      console.error('Error clearing localStorage:', error);
      return false;
    }
  }
};

/**
 * Enhanced API client with interceptors and retry logic
 */
const api = {
  client: axios.create({
    baseURL: API_BASE_URL,
    timeout: 60000,
    headers: { 'Content-Type': 'application/json' },
  }),

  // Request interceptor for adding auth tokens or logging
  setupInterceptors(onError) {
    this.client.interceptors.response.use(
      response => response,
      error => {
        const errorMessage = error.response?.data?.message || error.message || 'An error occurred';
        onError?.(errorMessage);
        return Promise.reject(error);
      }
    );
  },

  async fetchCases(params = {}) {
    try {
      const response = await this.client.get('/cases', { params });
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
      return { 
        data: null, 
        error: error.response?.data?.message || 'Analysis failed' 
      };
    }
  },

  async fetchEmailContent(caseId) {
    try {
      const response = await this.client.get(`/cases/${caseId}/content`);
      return { data: response.data.content, error: null };
    } catch (error) {
      return { data: null, error: 'Failed to fetch email content' };
    }
  },

  async deleteCase(caseId) {
    try {
      const response = await this.client.delete(`/cases/${caseId}`);
      return { success: true, error: null };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.message || 'Failed to delete case' 
      };
    }
  },

  async deleteCases(caseIds) {
    try {
      // Delete multiple cases
      const promises = caseIds.map(id => this.client.delete(`/cases/${id}`));
      await Promise.all(promises);
      return { success: true, error: null };
    } catch (error) {
      return { 
        success: false, 
        error: 'Failed to delete some cases' 
      };
    }
  },

  async exportCases(format = 'csv', filters = {}) {
    try {
      const response = await this.client.get('/cases/export', {
        params: { format, ...filters },
        responseType: 'blob'
      });
      return { data: response.data, error: null };
    } catch (error) {
      return { data: null, error: 'Failed to export cases' };
    }
  },

  async fetchStatistics(dateRange = 'all') {
    try {
      const response = await this.client.get('/statistics', {
        params: { range: dateRange }
      });
      return { data: response.data, error: null };
    } catch (error) {
      return { data: null, error: 'Failed to fetch statistics' };
    }
  }
};

/**
 * Format file size to human-readable string
 */
const formatFileSize = (bytes) => {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
};

/**
 * Format date to readable string
 */
const formatDate = (dateString, includeTime = true) => {
  if (!dateString) return 'N/A';
  const date = new Date(dateString);
  const options = {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    ...(includeTime && {
      hour: '2-digit',
      minute: '2-digit'
    })
  };
  return date.toLocaleDateString('en-US', options);
};

/**
 * Get relative time string (e.g., "2 hours ago")
 */
const getRelativeTime = (dateString) => {
  if (!dateString) return 'Unknown';
  
  const date = new Date(dateString);
  const now = new Date();
  const diffInSeconds = Math.floor((now - date) / 1000);
  
  if (diffInSeconds < 60) return 'Just now';
  if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)} minutes ago`;
  if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)} hours ago`;
  if (diffInSeconds < 604800) return `${Math.floor(diffInSeconds / 86400)} days ago`;
  
  return formatDate(dateString, false);
};

/**
 * Get verdict badge color and variant
 */
const getVerdictStyle = (verdict) => {
  const styles = {
    MALICIOUS: { 
      variant: 'danger', 
      icon: <AlertOctagon size={16} />,
      color: 'var(--danger-600)'
    },
    SUSPICIOUS: { 
      variant: 'warning', 
      icon: <AlertTriangle size={16} />,
      color: 'var(--warning-600)'
    },
    SAFE: { 
      variant: 'success', 
      icon: <CheckCircle size={16} />,
      color: 'var(--success-600)'
    },
    CLEAN: { 
      variant: 'success', 
      icon: <CheckCircle size={16} />,
      color: 'var(--success-600)'
    },
    UNKNOWN: {
      variant: 'neutral',
      icon: <HelpCircle size={16} />,
      color: 'var(--neutral-600)'
    }
  };
  return styles[verdict] || styles.UNKNOWN;
};

/**
 * Debounce function for search inputs
 */
const debounce = (func, wait) => {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
};

/**
 * Copy text to clipboard
 */
const copyToClipboard = async (text) => {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (error) {
    console.error('Failed to copy:', error);
    return false;
  }
};

/**
 * Download file from blob
 */
const downloadBlob = (blob, filename) => {
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  window.URL.revokeObjectURL(url);
};

/**
 * Validate email format
 */
const isValidEmail = (email) => {
  const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return regex.test(email);
};

/**
 * Extract domain from email
 */
const extractDomain = (email) => {
  if (!email || !isValidEmail(email)) return 'Unknown';
  return email.split('@')[1];
};

/**
 * Generate unique ID
 */
const generateId = () => {
  return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
};

// ============================================================================
// CUSTOM HOOKS
// ============================================================================

/**
 * Theme management hook with system preference detection
 */
const useTheme = () => {
  const [theme, setTheme] = useState(() => {
    const saved = storage.get(STORAGE_KEYS.THEME);
    if (saved) return saved;
    
    // Check system preference
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      return 'dark';
    }
    return 'light';
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    storage.set(STORAGE_KEYS.THEME, theme);
  }, [theme]);

  const toggleTheme = useCallback(() => {
    setTheme((prev) => (prev === 'light' ? 'dark' : 'light'));
  }, []);

  const setLightTheme = useCallback(() => setTheme('light'), []);
  const setDarkTheme = useCallback(() => setTheme('dark'), []);

  return { theme, toggleTheme, setLightTheme, setDarkTheme };
};

/**
 * Dashboard statistics hook with auto-refresh and caching
 */
/**
 * Dashboard statistics hook with auto-refresh and caching
 */
const useDashboardStats = (refreshInterval = REFRESH_INTERVAL) => {
  const [stats, setStats] = useState({
    total_processed: 0,
    malicious: 0,
    suspicious: 0,
    safe: 0,
    recent_cases: [],
    trends: {
      total: undefined,
      malicious: undefined,
      suspicious: undefined,
      safe: undefined
    }
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastFetch, setLastFetch] = useState(null);
  const prevStatsRef = useRef(null);

  const fetchStats = useCallback(async () => {
    const { data, error: fetchError } = await api.fetchCases();

    if (fetchError) {
      setError(fetchError);
      setLoading(false);
      return;
    }

    if (data) {
      const malicious = data.filter((c) => c.verdict === VERDICT_TYPES.MALICIOUS).length;
      const suspicious = data.filter((c) => c.verdict === VERDICT_TYPES.SUSPICIOUS).length;
      const safe = data.length - malicious - suspicious;

      const currentStats = {
        total_processed: data.length,
        malicious,
        suspicious,
        safe
      };

      // Calculate trends if we have previous stats
      let trends = {
        total: undefined,
        malicious: undefined,
        suspicious: undefined,
        safe: undefined
      };

      if (prevStatsRef.current) {
        const prev = prevStatsRef.current;
        
        // Calculate percentage change, handle division by zero
        const calcTrend = (current, previous) => {
          if (previous === 0) return current > 0 ? 100 : 0;
          return Math.round(((current - previous) / previous) * 100);
        };

        trends = {
          total: calcTrend(currentStats.total_processed, prev.total_processed),
          malicious: calcTrend(currentStats.malicious, prev.malicious),
          suspicious: calcTrend(currentStats.suspicious, prev.suspicious),
          safe: calcTrend(currentStats.safe, prev.safe)
        };
      }

      // Store current stats for next comparison
      prevStatsRef.current = currentStats;

      setStats({
        ...currentStats,
        recent_cases: data.slice(0, 100),
        trends
      });
      setError(null);
      setLastFetch(new Date());
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

  return { stats, loading, error, refetch: fetchStats, lastFetch };
};
/**
 * Keyboard shortcuts hook with customization
 */
const useKeyboardShortcuts = (shortcuts) => {
  useEffect(() => {
    const handleKeyDown = (event) => {
      const key = event.key.toLowerCase();
      const withCtrl = event.ctrlKey || event.metaKey;
      const withShift = event.shiftKey;
      const withAlt = event.altKey;

      shortcuts.forEach(({ keys, action, requireCtrl, requireShift, requireAlt }) => {
        const keyMatch = keys.includes(key);
        const ctrlMatch = requireCtrl ? withCtrl : true;
        const shiftMatch = requireShift ? withShift : true;
        const altMatch = requireAlt ? withAlt : true;

        if (keyMatch && ctrlMatch && shiftMatch && altMatch) {
          event.preventDefault();
          action();
        }
      });
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [shortcuts]);
};

/**
 * Notification system hook
 */
const useNotifications = () => {
  const [notifications, setNotifications] = useState([]);

  const addNotification = useCallback((message, type = NOTIFICATION_TYPES.INFO, duration = 5000) => {
    const id = generateId();
    const notification = { id, message, type, timestamp: new Date() };
    
    setNotifications(prev => [...prev, notification]);

    if (duration > 0) {
      setTimeout(() => {
        removeNotification(id);
      }, duration);
    }

    return id;
  }, []);

  const removeNotification = useCallback((id) => {
    setNotifications(prev => prev.filter(n => n.id !== id));
  }, []);

  const clearAll = useCallback(() => {
    setNotifications([]);
  }, []);

  return {
    notifications,
    addNotification,
    removeNotification,
    clearAll,
    success: (msg, duration) => addNotification(msg, NOTIFICATION_TYPES.SUCCESS, duration),
    error: (msg, duration) => addNotification(msg, NOTIFICATION_TYPES.ERROR, duration),
    warning: (msg, duration) => addNotification(msg, NOTIFICATION_TYPES.WARNING, duration),
    info: (msg, duration) => addNotification(msg, NOTIFICATION_TYPES.INFO, duration),
  };
};

/**
 * Pagination hook
 */
const usePagination = (items, initialPageSize = 25) => {
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(() => {
    return storage.get(STORAGE_KEYS.CASES_PER_PAGE, initialPageSize);
  });

  useEffect(() => {
    storage.set(STORAGE_KEYS.CASES_PER_PAGE, pageSize);
  }, [pageSize]);

  const totalPages = Math.ceil(items.length / pageSize);
  const startIndex = (currentPage - 1) * pageSize;
  const endIndex = startIndex + pageSize;
  const currentItems = items.slice(startIndex, endIndex);

  const goToPage = useCallback((page) => {
    const validPage = Math.max(1, Math.min(page, totalPages));
    setCurrentPage(validPage);
  }, [totalPages]);

  const nextPage = useCallback(() => {
    goToPage(currentPage + 1);
  }, [currentPage, goToPage]);

  const prevPage = useCallback(() => {
    goToPage(currentPage - 1);
  }, [currentPage, goToPage]);

  const firstPage = useCallback(() => goToPage(1), [goToPage]);
  const lastPage = useCallback(() => goToPage(totalPages), [goToPage, totalPages]);

  useEffect(() => {
    if (currentPage > totalPages && totalPages > 0) {
      setCurrentPage(totalPages);
    }
  }, [currentPage, totalPages]);

  return {
    currentPage,
    pageSize,
    totalPages,
    currentItems,
    startIndex,
    endIndex,
    setPageSize,
    goToPage,
    nextPage,
    prevPage,
    firstPage,
    lastPage,
    hasNextPage: currentPage < totalPages,
    hasPrevPage: currentPage > 1
  };
};

/**
 * Window size hook for responsive design
 */
const useWindowSize = () => {
  const [windowSize, setWindowSize] = useState({
    width: window.innerWidth,
    height: window.innerHeight,
  });

  useEffect(() => {
    const handleResize = debounce(() => {
      setWindowSize({
        width: window.innerWidth,
        height: window.innerHeight,
      });
    }, 150);

    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  return {
    ...windowSize,
    isMobile: windowSize.width < 768,
    isTablet: windowSize.width >= 768 && windowSize.width < 1024,
    isDesktop: windowSize.width >= 1024
  };
};

// ============================================================================
// UI COMPONENTS
// ============================================================================

/**
 * Enhanced Button Component
 */
const Button = ({ 
  variant = 'primary', 
  size = 'md', 
  loading = false, 
  disabled = false,
  children,
  className = '',
  icon,
  iconPosition = 'left',
  fullWidth = false,
  ...props 
}) => {
  const baseClass = 'btn';
  const classes = [
    baseClass,
    `${baseClass}--${variant}`,
    `${baseClass}--${size}`,
    loading && `${baseClass}--loading`,
    fullWidth && 'u-w-full',
    className,
  ].filter(Boolean).join(' ');

  return (
    <button className={classes} disabled={disabled || loading} {...props}>
      {loading && (
        <svg className="btn__spinner" viewBox="0 0 24 24">
          <circle className="btn__spinner-circle" cx="12" cy="12" r="10" />
        </svg>
      )}
      <span className={loading ? 'btn__text--loading' : ''} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        {icon && iconPosition === 'left' && icon}
        {children}
        {icon && iconPosition === 'right' && icon}
      </span>
    </button>
  );
};

/**
 * Badge Component with animations
 */
const Badge = ({ variant = 'success', icon, children, className = '', pulse = false }) => {
  return (
    <span className={`badge badge--${variant} ${pulse ? 'u-animate-pulse' : ''} ${className}`}>
      {icon && <span className="badge__icon">{icon}</span>}
      {children}
    </span>
  );
};

/**
 * Card Component with variants
 */
const Card = ({ children, className = '', hover = false, ...props }) => {
  return (
    <div className={`card ${hover ? 'card--hover' : ''} ${className}`} {...props}>
      {children}
    </div>
  );
};

/**
 * Enhanced Progress Bar with gradient
 */
const ProgressBar = ({ value = 0, showLabel = true, size = 'md', animated = true }) => {
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
      {showLabel && <span className="progress-bar__label">{Math.round(value)}%</span>}
    </div>
  );
};

/**
 * Empty State Component
 */
const EmptyState = ({ icon, title, description, action }) => {
  return (
    <div className="empty-state">
      {icon && <div className="empty-state__icon">{icon}</div>}
      <h3 className="empty-state__title">{title}</h3>
      {description && <p className="empty-state__description">{description}</p>}
      {action && <div className="empty-state__action">{action}</div>}
    </div>
  );
};

/**
 * Loading Skeleton Component
 */
const Skeleton = ({ width = '100%', height = '20px', className = '', variant = 'text' }) => {
  return (
    <div 
      className={`skeleton skeleton--${variant} ${className}`} 
      style={{ width, height }}
      aria-label="Loading..."
      role="status"
    />
  );
};

/**
 * Stat Card Component with trend indicator
 */
const StatCard = ({ icon, label, value, loading = false, trend, trendValue }) => {
  const getTrendIcon = () => {
    if (!trend) return null;
    if (trend > 0) return <TrendingUp size={16} />;
    if (trend < 0) return <TrendingDown size={16} />;
    return <Minus size={16} />;
  };

  const getTrendColor = () => {
    if (trend > 0) return 'var(--success-600)';
    if (trend < 0) return 'var(--danger-600)';
    return 'var(--neutral-600)';
  };

  return (
    <Card className="stat-card" hover>
      <div className="stat-card__icon">{icon}</div>
      <div className="stat-card__content">
        <p className="stat-card__label">{label}</p>
        {loading ? (
          <Skeleton width="60px" height="32px" />
        ) : (
          <>
            <p className="stat-card__value">{value}</p>
            {trend !== undefined && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '4px', marginTop: '4px', fontSize: '0.75rem', color: getTrendColor() }}>
                {getTrendIcon()}
                <span>{trendValue || `${Math.abs(trend)}%`}</span>
              </div>
            )}
          </>
        )}
      </div>
    </Card>
  );
};

/**
 * Search Input Component
 */
const SearchInput = ({ value, onChange, placeholder = "Search...", className = "" }) => {
  return (
    <div className={`form-group ${className}`} style={{ position: 'relative', marginBottom: 0 }}>
      <Search 
        size={18} 
        style={{ 
          position: 'absolute', 
          left: '12px', 
          top: '50%', 
          transform: 'translateY(-50%)',
          color: 'var(--text-tertiary)',
          pointerEvents: 'none'
        }} 
      />
      <input
        type="text"
        className="form-input"
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        style={{ paddingLeft: '40px' }}
      />
    </div>
  );
};

/**
 * Tooltip Component
 */
const Tooltip = ({ children, content, position = 'top' }) => {
  const [visible, setVisible] = useState(false);

  return (
    <div 
      className="tooltip"
      onMouseEnter={() => setVisible(true)}
      onMouseLeave={() => setVisible(false)}
    >
      {children}
      {visible && content && (
        <div className={`tooltip__content tooltip__content--${position}`}>
          {content}
        </div>
      )}
    </div>
  );
};

/**
 * Modal Component
 */
const Modal = ({ isOpen, onClose, title, children, footer, size = 'md' }) => {
  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = 'unset';
    }

    return () => {
      document.body.style.overflow = 'unset';
    };
  }, [isOpen]);

  if (!isOpen) return null;

  return (
    <div className="modal">
      <div className="modal__backdrop" onClick={onClose} />
      <div className={`modal__content modal__content--${size}`}>
        <div className="modal__header">
          <h3 className="modal__title">{title}</h3>
          <button className="modal__close" onClick={onClose} aria-label="Close modal">
            <X size={20} />
          </button>
        </div>
        <div className="modal__body">
          {children}
        </div>
        {footer && (
          <div className="modal__footer">
            {footer}
          </div>
        )}
      </div>
    </div>
  );
};

/**
 * Toast Notification Component
 */
const Toast = ({ notification, onClose }) => {
  const [isLeaving, setIsLeaving] = useState(false);

  const handleClose = () => {
    setIsLeaving(true);
    setTimeout(() => onClose(notification.id), 300);
  };

  const getIcon = () => {
    switch (notification.type) {
      case NOTIFICATION_TYPES.SUCCESS:
        return <CheckCircle size={20} />;
      case NOTIFICATION_TYPES.ERROR:
        return <XCircle size={20} />;
      case NOTIFICATION_TYPES.WARNING:
        return <AlertTriangle size={20} />;
      default:
        return <Info size={20} />;
    }
  };

  return (
    <div className={`alert alert--${notification.type} ${isLeaving ? 'toast--leaving' : ''}`}>
      <span className="alert__icon">{getIcon()}</span>
      <div className="alert__content">
        <p className="alert__message">{notification.message}</p>
      </div>
      <button className="alert__close" onClick={handleClose}>
        <X size={16} />
      </button>
    </div>
  );
};

/**
 * Toast Container
 */
const ToastContainer = ({ notifications, onClose }) => {
  if (notifications.length === 0) return null;

  return (
    <div className="toast-container">
      {notifications.map(notification => (
        <Toast key={notification.id} notification={notification} onClose={onClose} />
      ))}
    </div>
  );
};

// ============================================================================
// MAIN COMPONENTS
// ============================================================================

/**
 * Application Header with enhanced actions
 */
const Header = ({ onThemeToggle, theme, onRefresh, lastFetch }) => {
  return (
    <header className="header">
      <div className="header__content">
        <div className="header__brand">
          <div className="header__icon">
            <Shield size={40} />
          </div>
          <div>
            <h1 className="header__title">PhishGuard Pro</h1>
            {lastFetch && (
              <p style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', marginTop: '2px' }}>
                Last updated: {getRelativeTime(lastFetch)}
              </p>
            )}
          </div>
        </div>

        <div className="header__actions">
          <div className="header__status">
            <span className="status-indicator status-indicator--online" />
            <span className="header__status-text">Active</span>
          </div>

          <Tooltip content="Refresh data (Ctrl+R)">
            <Button 
              variant="ghost" 
              size="sm" 
              onClick={onRefresh}
              icon={<RefreshCw size={16} />}
              aria-label="Refresh data"
            />
          </Tooltip>

          <Tooltip content={`Switch to ${theme === 'light' ? 'dark' : 'light'} mode (Ctrl+D)`}>
            <Button 
              variant="ghost" 
              size="sm" 
              onClick={onThemeToggle}
              icon={theme === 'light' ? <Moon size={16} /> : <Sun size={16} />}
              aria-label="Toggle theme"
            />
          </Tooltip>
        </div>
      </div>
    </header>
  );
};

/**
 * Enhanced Statistics Dashboard with trends
 */
const StatsDashboard = ({ stats, loading }) => {
  return (
    <div className="stats-dashboard">
      <StatCard
        icon={<FileText size={32} />}
        label="Total Analyzed"
        value={stats.total_processed}
        loading={loading}
        trend={stats.trends?.total}
      />
      <StatCard
        icon={<AlertOctagon size={32} />}
        label="Malicious Detected"
        value={stats.malicious}
        loading={loading}
        trend={stats.trends?.malicious}
      />
      <StatCard
        icon={<AlertTriangle size={32} />}
        label="Suspicious Flagged"
        value={stats.suspicious}
        loading={loading}
        trend={stats.trends?.suspicious}
      />
      <StatCard
        icon={<CheckCircle size={32} />}
        label="Safe Emails"
        value={stats.safe}
        loading={loading}
        trend={stats.trends?.safe}
      />
    </div>
  );
};

/**
 * Enhanced Upload Section with drag-drop and validation
 */
const UploadSection = ({ onAnalysisComplete, onNotify }) => {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  const fileInputRef = useRef(null);

  const validateFile = (file) => {
    const validTypes = ['.eml', '.msg', '.txt'];
    const maxSize = 10 * 1024 * 1024; // 10MB
    
    const extension = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();
    
    if (!validTypes.includes(extension)) {
      return { valid: false, error: 'Invalid file type. Please upload .eml, .msg, or .txt files.' };
    }
    
    if (file.size > maxSize) {
      return { valid: false, error: 'File size exceeds 10MB limit.' };
    }
    
    return { valid: true };
  };

  const handleFileChange = (selectedFile) => {
    if (selectedFile) {
      const validation = validateFile(selectedFile);
      
      if (!validation.valid) {
        setError(validation.error);
        onNotify?.(validation.error, NOTIFICATION_TYPES.ERROR);
        return;
      }
      
      setFile(selectedFile);
      setResult(null);
      setError(null);
      setProgress(0);
    }
  };

  const handleInputChange = (e) => handleFileChange(e.target.files?.[0]);

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else {
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
      const errorMsg = 'Please select a file to analyze';
      setError(errorMsg);
      onNotify?.(errorMsg, NOTIFICATION_TYPES.WARNING);
      return;
    }

    setLoading(true);
    setError(null);
    setProgress(0);

    const { data, error: apiError } = await api.analyzeEmail(file, setProgress);

    if (apiError) {
      setError(apiError);
      setResult(null);
      onNotify?.(apiError, NOTIFICATION_TYPES.ERROR);
    } else {
      setResult(data);
      setError(null);
      onAnalysisComplete?.();
      onNotify?.('Email analyzed successfully!', NOTIFICATION_TYPES.SUCCESS);
    }

    setLoading(false);
    setProgress(0);
  };

  const handleClear = () => {
    setFile(null);
    setResult(null);
    setError(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const handleBrowse = () => fileInputRef.current?.click();

  return (
    <Card className="upload-section">
      <div className="upload-section__header">
        <h2 className="upload-section__title">Analyze New Email</h2>
        <p className="upload-section__subtitle">
          Upload an email file (.eml, .msg, .txt) for AI-powered phishing analysis.
        </p>
      </div>

      <form onSubmit={handleSubmit} className="upload-form">
        {!result && (
          <div
            className={`upload-dropzone ${dragActive ? 'upload-dropzone--active' : ''} ${file ? 'upload-dropzone--has-file' : ''}`}
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
            onClick={handleBrowse}
            role="button"
            tabIndex={0}
          >
            <input
              ref={fileInputRef}
              type="file"
              onChange={handleInputChange}
              className="upload-input"
              accept=".eml,.msg,.txt"
              aria-label="File upload input"
            />
            {file ? (
              <div className="upload-file-info">
                <span className="upload-file-icon">
                  <File size={32} />
                </span>
                <div className="upload-file-details">
                  <p className="upload-file-name">{file.name}</p>
                  <p className="upload-file-size">{formatFileSize(file.size)}</p>
                </div>
              </div>
            ) : (
              <div className="upload-placeholder">
                <span className="upload-placeholder__icon">
                  <Upload size={48} />
                </span>
                <p className="upload-placeholder__text">
                  <strong>Click to browse</strong> or drag and drop
                </p>
                <p className="upload-placeholder__hint">
                  Supports .eml, .msg, .txt files (max 10MB)
                </p>
              </div>
            )}
          </div>
        )}

        {loading && (
          <div className="upload-progress">
            <ProgressBar value={progress} showLabel size="lg" animated />
            <p className="upload-progress__text">
              Analyzing email with AI models... This may take a few moments.
            </p>
          </div>
        )}

        {error && (
          <div className="upload-alert upload-alert--error" role="alert">
            <span className="upload-alert__icon">
              <XCircle size={20} />
            </span>
            <div className="upload-alert__content">
              <p className="upload-alert__message">{error}</p>
            </div>
          </div>
        )}

        {result && (
          <div className="upload-alert upload-alert--success" role="status">
            <span className="upload-alert__icon">
              {getVerdictStyle(result.verdict).icon}
            </span>
            <div className="upload-alert__content">
              <p className="upload-alert__message">
                <strong>Analysis Complete</strong>
              </p>
              <div className="upload-alert__detail">
                <span>Verdict:</span>
                <Badge variant={getVerdictStyle(result.verdict).variant}>
                  {result.verdict}
                </Badge>
                <span>•</span>
                <span>Risk Score: <strong>{result.risk_score}/100</strong></span>
              </div>
            </div>
          </div>
        )}

        <div className="upload-actions">
          {!result && (
            <Button
              type="submit"
              variant="primary"
              size="lg"
              loading={loading}
              disabled={!file || loading}
              icon={<Zap size={18} />}
            >
              {loading ? 'Analyzing...' : 'Analyze Email'}
            </Button>
          )}

          {(file || result) && !loading && (
            <Button
              type="button"
              variant={result ? 'primary' : 'ghost'}
              size="lg"
              onClick={handleClear}
              icon={result ? <Upload size={18} /> : <X size={18} />}
            >
              {result ? 'Analyze Another Email' : 'Clear'}
            </Button>
          )}
        </div>
      </form>
    </Card>
  );
};

/**
 * Advanced Cases Table with sorting, filtering, pagination, export, and delete
 */
const CasesTable = ({ cases, loading, onNotify, onCasesUpdate }) => {
  const [sortField, setSortField] = useState(SORT_FIELDS.ID);
  const [sortDirection, setSortDirection] = useState('desc');
  const [filter, setFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedRowId, setExpandedRowId] = useState(null);
  const [emailContent, setEmailContent] = useState({});
  const [loadingContent, setLoadingContent] = useState(false);
  const [selectedCases, setSelectedCases] = useState(new Set());
  const [showFilters, setShowFilters] = useState(false);
  const [dateFilter, setDateFilter] = useState('all');
  const [deletingCases, setDeletingCases] = useState(new Set());

  const toggleRow = async (id) => {
    if (expandedRowId === id) {
      setExpandedRowId(null);
      return;
    }

    setExpandedRowId(id);

    if (!emailContent[id]) {
      setLoadingContent(true);
      const { data } = await api.fetchEmailContent(id);
      setEmailContent(prev => ({
        ...prev,
        [id]: data || "Unable to load email content."
      }));
      setLoadingContent(false);
    }
  };

  const handleSort = (field) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('desc');
    }
  };

  const handleSelectCase = (id) => {
    const newSelected = new Set(selectedCases);
    if (newSelected.has(id)) {
      newSelected.delete(id);
    } else {
      newSelected.add(id);
    }
    setSelectedCases(newSelected);
  };

  const handleSelectAll = () => {
    if (selectedCases.size === filteredCases.length) {
      setSelectedCases(new Set());
    } else {
      setSelectedCases(new Set(filteredCases.map(c => c.id)));
    }
  };

  const handleExport = async () => {
    if (selectedCases.size === 0) {
      onNotify?.('Please select cases to export', NOTIFICATION_TYPES.WARNING);
      return;
    }

    onNotify?.('Exporting cases...', NOTIFICATION_TYPES.INFO, 2000);
    
    // Create CSV manually since API endpoint may not exist
    try {
      const casesToExport = sortedCases.filter(c => selectedCases.has(c.id));
      const csvContent = [
        ['ID', 'Subject', 'Sender', 'Verdict', 'Risk Score', 'Date'],
        ...casesToExport.map(c => [
          c.id,
          c.subject || 'No Subject',
          c.sender || 'Unknown',
          c.verdict,
          c.risk_score || 0,
          formatDate(c.processed_at)
        ])
      ].map(row => row.map(cell => `"${cell}"`).join(',')).join('\n');

      const blob = new Blob([csvContent], { type: 'text/csv' });
      downloadBlob(blob, `phishguard-export-${Date.now()}.csv`);
      onNotify?.('Cases exported successfully!', NOTIFICATION_TYPES.SUCCESS);
    } catch (error) {
      onNotify?.('Export failed. Please try again.', NOTIFICATION_TYPES.ERROR);
    }
  };

  const handleDeleteSelected = async () => {
    if (selectedCases.size === 0) {
      onNotify?.('Please select cases to delete', NOTIFICATION_TYPES.WARNING);
      return;
    }
    
    const confirmed = window.confirm(
      `Are you sure you want to permanently delete ${selectedCases.size} case(s)?\n\nThis action cannot be undone.`
    );
    if (!confirmed) return;

    const caseIdsToDelete = Array.from(selectedCases);
    setDeletingCases(new Set(caseIdsToDelete));
    onNotify?.(`Deleting ${selectedCases.size} case(s)...`, NOTIFICATION_TYPES.INFO, 2000);

    try {
      const { success, error } = await api.deleteCases(caseIdsToDelete);
      
      if (success) {
        setSelectedCases(new Set());
        setDeletingCases(new Set());
        onNotify?.(`Successfully deleted ${caseIdsToDelete.length} case(s)!`, NOTIFICATION_TYPES.SUCCESS);
        
        // Trigger refresh to update the UI
        onCasesUpdate?.();
      } else {
        setDeletingCases(new Set());
        onNotify?.(error || 'Failed to delete cases', NOTIFICATION_TYPES.ERROR);
      }
    } catch (error) {
      setDeletingCases(new Set());
      onNotify?.('An error occurred while deleting cases', NOTIFICATION_TYPES.ERROR);
    }
  };

  const handleDeleteSingle = async (caseId) => {
    const confirmed = window.confirm(
      'Are you sure you want to permanently delete this case?\n\nThis action cannot be undone.'
    );
    if (!confirmed) return;

    setDeletingCases(new Set([caseId]));
    onNotify?.('Deleting case...', NOTIFICATION_TYPES.INFO, 1000);

    try {
      const { success, error } = await api.deleteCase(caseId);
      
      if (success) {
        setDeletingCases(new Set());
        // Remove from selected if it was selected
        if (selectedCases.has(caseId)) {
          const newSelected = new Set(selectedCases);
          newSelected.delete(caseId);
          setSelectedCases(newSelected);
        }
        onNotify?.('Case deleted successfully!', NOTIFICATION_TYPES.SUCCESS);
        
        // Trigger refresh to update the UI
        onCasesUpdate?.();
      } else {
        setDeletingCases(new Set());
        onNotify?.(error || 'Failed to delete case', NOTIFICATION_TYPES.ERROR);
      }
    } catch (error) {
      setDeletingCases(new Set());
      onNotify?.('An error occurred while deleting the case', NOTIFICATION_TYPES.ERROR);
    }
  };

  const filteredCases = useMemo(() => {
    return cases.filter((caseItem) => {
      const matchesFilter = filter === 'all' || caseItem.verdict.toLowerCase() === filter.toLowerCase();
      
      const matchesSearch = searchQuery === '' ||
        caseItem.subject?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        caseItem.sender?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        caseItem.id.toString().includes(searchQuery);
      
      const matchesDate = dateFilter === 'all' || (() => {
        if (!caseItem.processed_at) return false;
        const date = new Date(caseItem.processed_at);
        const now = new Date();
        const daysDiff = (now - date) / (1000 * 60 * 60 * 24);
        
        switch (dateFilter) {
          case 'today':
            return daysDiff < 1;
          case 'week':
            return daysDiff < 7;
          case 'month':
            return daysDiff < 30;
          default:
            return true;
        }
      })();
      
      return matchesFilter && matchesSearch && matchesDate;
    });
  }, [cases, filter, searchQuery, dateFilter]);

  const sortedCases = useMemo(() => {
    const sorted = [...filteredCases].sort((a, b) => {
      let aVal = a[sortField];
      let bVal = b[sortField];

      if (sortField === SORT_FIELDS.RISK_SCORE) {
        aVal = parseFloat(aVal) || 0;
        bVal = parseFloat(bVal) || 0;
      }

      if (sortDirection === 'asc') {
        return aVal > bVal ? 1 : -1;
      }
      return aVal < bVal ? 1 : -1;
    });

    // Renumber IDs sequentially starting from 1
    return sorted.map((caseItem, index) => ({
      ...caseItem,
      displayId: index + 1, // Add sequential display ID
      originalId: caseItem.id // Keep original ID for API calls
    }));
  }, [filteredCases, sortField, sortDirection]);

  const {
    currentItems,
    currentPage,
    totalPages,
    pageSize,
    setPageSize,
    nextPage,
    prevPage,
    firstPage,
    lastPage,
    hasNextPage,
    hasPrevPage
  } = usePagination(sortedCases, 25);

  const getScoreColor = (score) => {
    if (score >= 70) return 'score-item__value--high';
    if (score >= 40) return 'score-item__value--med';
    return 'score-item__value--low';
  };

  const handleCopyContent = async (content) => {
    const success = await copyToClipboard(content);
    if (success) {
      onNotify?.('Content copied to clipboard!', NOTIFICATION_TYPES.SUCCESS, 2000);
    } else {
      onNotify?.('Failed to copy content', NOTIFICATION_TYPES.ERROR);
    }
  };

  if (loading) {
    return (
      <Card className="cases-table-card">
        <div className="cases-table-header">
          <h2 className="cases-table-title">Analysis History</h2>
        </div>
        <div className="cases-loading">
          {[...Array(5)].map((_, i) => (
            <Skeleton key={i} height="48px" className="cases-skeleton" />
          ))}
        </div>
      </Card>
    );
  }

  if (cases.length === 0) {
    return (
      <Card className="cases-table-card">
        <EmptyState
          icon={<FileText size={64} />}
          title="No Cases Yet"
          description="Upload your first email to start analyzing potential phishing threats."
        />
      </Card>
    );
  }

  return (
    <Card className="cases-table-card">
      <div className="cases-table-header">
        <h2 className="cases-table-title">
          Analysis History ({filteredCases.length})
        </h2>

        <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', alignItems: 'center' }}>
          <SearchInput
            value={searchQuery}
            onChange={setSearchQuery}
            placeholder="Search cases..."
          />

          <Button
            variant="ghost"
            size="sm"
            onClick={() => setShowFilters(!showFilters)}
            icon={<Filter size={16} />}
          >
            Filters
          </Button>

          {selectedCases.size > 0 && (
            <>
              <Button
                variant="secondary"
                size="sm"
                onClick={handleExport}
                icon={<Download size={16} />}
              >
                Export ({selectedCases.size})
              </Button>
              <Button
                variant="danger"
                size="sm"
                onClick={handleDeleteSelected}
                icon={<Trash2 size={16} />}
              >
                Delete ({selectedCases.size})
              </Button>
            </>
          )}
        </div>
      </div>

      {showFilters && (
        <div style={{ padding: '1rem 1.5rem', borderBottom: '1px solid var(--border-primary)', display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
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

          <div className="cases-filters">
            {['all', 'today', 'week', 'month'].map((dateOption) => (
              <button
                key={dateOption}
                className={`filter-btn ${dateFilter === dateOption ? 'filter-btn--active' : ''}`}
                onClick={() => setDateFilter(dateOption)}
              >
                {dateOption === 'all' ? 'All Time' : dateOption.charAt(0).toUpperCase() + dateOption.slice(1)}
              </button>
            ))}
          </div>
        </div>
      )}

      <div className="cases-table-wrapper custom-scrollbar">
        <table className="cases-table">
          <thead>
            <tr>
              <th style={{ width: '40px' }}>
                <input
                  type="checkbox"
                  checked={selectedCases.size === currentItems.length && currentItems.length > 0}
                  onChange={handleSelectAll}
                  aria-label="Select all cases"
                />
              </th>
              <th style={{ width: '50px' }}></th>
              <th onClick={() => handleSort(SORT_FIELDS.ID)} className="cases-table__th--sortable">
                <div className="cases-table__header-content">
                  ID
                  {sortField === SORT_FIELDS.ID && (
                    <span className="sort-indicator">{sortDirection === 'asc' ? '↑' : '↓'}</span>
                  )}
                </div>
              </th>
              <th onClick={() => handleSort(SORT_FIELDS.SUBJECT)} className="cases-table__th--sortable">
                <div className="cases-table__header-content">
                  Subject
                  {sortField === SORT_FIELDS.SUBJECT && (
                    <span className="sort-indicator">{sortDirection === 'asc' ? '↑' : '↓'}</span>
                  )}
                </div>
              </th>
              <th onClick={() => handleSort(SORT_FIELDS.SENDER)} className="cases-table__th--sortable">
                <div className="cases-table__header-content">
                  Sender
                  {sortField === SORT_FIELDS.SENDER && (
                    <span className="sort-indicator">{sortDirection === 'asc' ? '↑' : '↓'}</span>
                  )}
                </div>
              </th>
              <th onClick={() => handleSort(SORT_FIELDS.VERDICT)} className="cases-table__th--sortable">
                <div className="cases-table__header-content">
                  Verdict
                  {sortField === SORT_FIELDS.VERDICT && (
                    <span className="sort-indicator">{sortDirection === 'asc' ? '↑' : '↓'}</span>
                  )}
                </div>
              </th>
              <th onClick={() => handleSort(SORT_FIELDS.RISK_SCORE)} className="cases-table__th--sortable">
                <div className="cases-table__header-content">
                  Risk Score
                  {sortField === SORT_FIELDS.RISK_SCORE && (
                    <span className="sort-indicator">{sortDirection === 'asc' ? '↑' : '↓'}</span>
                  )}
                </div>
              </th>
              <th onClick={() => handleSort(SORT_FIELDS.PROCESSED_AT)} className="cases-table__th--sortable">
                <div className="cases-table__header-content">
                  Date
                  {sortField === SORT_FIELDS.PROCESSED_AT && (
                    <span className="sort-indicator">{sortDirection === 'asc' ? '↑' : '↓'}</span>
                  )}
                </div>
              </th>
              <th style={{ width: '80px', textAlign: 'center' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {currentItems.map((caseItem) => {
              const verdictStyle = getVerdictStyle(caseItem.verdict);
              const isExpanded = expandedRowId === caseItem.originalId; // Use originalId for expansion
              const isSelected = selectedCases.has(caseItem.originalId); // Use originalId for selection
              const isDeleting = deletingCases.has(caseItem.originalId); // Use originalId for deletion
              const scores = caseItem.breakdown || {};

              return (
                <React.Fragment key={caseItem.originalId}>
                  <tr
                    className={`cases-table__row ${isExpanded ? 'case-row-expanded' : ''} ${isSelected ? 'case-row-selected' : ''} ${isDeleting ? 'u-opacity-50' : ''}`}
                    style={{ opacity: isDeleting ? 0.5 : 1, pointerEvents: isDeleting ? 'none' : 'auto' }}
                  >
                    <td className="cases-table__cell">
                      <input
                        type="checkbox"
                        checked={isSelected}
                        onChange={() => handleSelectCase(caseItem.originalId)} // Use originalId
                        onClick={(e) => e.stopPropagation()}
                        aria-label={`Select case ${caseItem.displayId}`}
                      />
                    </td>
                    <td className="cases-table__cell">
                      <button
                        className={`toggle-btn ${isExpanded ? 'toggle-btn--expanded' : ''}`}
                        onClick={() => toggleRow(caseItem.originalId)} // Use originalId
                        aria-label="Toggle details"
                      >
                        <ChevronDown size={16} />
                      </button>
                    </td>
                    <td className="cases-table__cell cases-table__cell--id">
                      #{caseItem.displayId}
                    </td>
                    <td className="cases-table__cell cases-table__cell--subject">
                      {caseItem.subject || 'No Subject'}
                    </td>
                    <td className="cases-table__cell">
                      {caseItem.sender || 'Unknown'}
                    </td>
                    <td className="cases-table__cell">
                      <Badge variant={verdictStyle.variant} icon={verdictStyle.icon}>
                        {caseItem.verdict}
                      </Badge>
                    </td>
                    <td className="cases-table__cell cases-table__cell--score">
                      <ProgressBar value={caseItem.risk_score || 0} showLabel size="md" />
                    </td>
                    <td className="cases-table__cell">
                      {getRelativeTime(caseItem.processed_at)}
                    </td>
                    <td className="cases-table__cell" style={{ textAlign: 'center' }}>
                      <Tooltip content="Delete case permanently">
                        <Button
                          variant="ghost"
                          size="xs"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleDeleteSingle(caseItem.originalId); // Use originalId for deletion
                          }}
                          disabled={isDeleting}
                          icon={<Trash2 size={14} />}
                          style={{ 
                            color: 'var(--danger-600)',
                            opacity: isDeleting ? 0.5 : 0.6,
                          }}
                          aria-label="Delete case"
                        />
                      </Tooltip>
                    </td>
                  </tr>

                  {isExpanded && (
                    <tr className="case-details-row">
                      <td colSpan="9">
                        <div className="case-details">
                          <div className="details-grid">
                            <div className="email-preview">
                              <div className="email-preview__header">
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                                  <h4 style={{ fontSize: '0.875rem', fontWeight: '600', margin: 0 }}>
                                    Email Content
                                  </h4>
                                  <Button
                                    variant="ghost"
                                    size="xs"
                                    onClick={() => handleCopyContent(emailContent[caseItem.originalId])} // Use originalId
                                    icon={<Copy size={14} />}
                                  >
                                    Copy
                                  </Button>
                                </div>
                                <div className="email-meta">
                                  <span className="email-meta__label">From:</span>
                                  <span>{caseItem.sender || 'Unknown Sender'}</span>

                                  <span className="email-meta__label">Domain:</span>
                                  <span>{extractDomain(caseItem.sender)}</span>

                                  <span className="email-meta__label">Date:</span>
                                  <span>{formatDate(caseItem.processed_at)}</span>

                                  <span className="email-meta__label">Subject:</span>
                                  <span>{caseItem.subject || 'No Subject'}</span>
                                </div>
                              </div>
                              <div className="email-body">
                                {loadingContent && !emailContent[caseItem.originalId] ? ( // Use originalId
                                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                                    <Skeleton width="100%" height="16px" />
                                    <Skeleton width="90%" height="16px" />
                                    <Skeleton width="95%" height="16px" />
                                    <Skeleton width="85%" height="16px" />
                                  </div>
                                ) : (
                                  emailContent[caseItem.originalId] || "No content available." // Use originalId
                                )}
                              </div>
                            </div>

                            <div className="score-breakdown">
                              <h4 className="breakdown-title">
                                <Shield size={16} />
                                Risk Analysis
                              </h4>

                              {(scores.threat_intel || 0) > 0 && (
                                <div className="score-item">
                                  <span className="score-item__label">Threat Intelligence</span>
                                  <span className={`score-item__value ${getScoreColor(scores.threat_intel)}`}>
                                    +{scores.threat_intel}
                                  </span>
                                </div>
                              )}

                              {(scores.ml_analysis || 0) > 0 && (
                                <div className="score-item">
                                  <span className="score-item__label">AI/ML Model</span>
                                  <span className={`score-item__value ${getScoreColor(scores.ml_analysis)}`}>
                                    +{scores.ml_analysis}
                                  </span>
                                </div>
                              )}

                              {(scores.attachment_risk || 0) > 0 && (
                                <div className="score-item">
                                  <span className="score-item__label">Attachments</span>
                                  <span className={`score-item__value ${getScoreColor(scores.attachment_risk)}`}>
                                    +{scores.attachment_risk}
                                  </span>
                                </div>
                              )}

                              {(scores.heuristic_risk || 0) > 0 && (
                                <div className="score-item">
                                  <span className="score-item__label">Keywords (Heuristics)</span>
                                  <span className={`score-item__value ${getScoreColor(scores.heuristic_risk)}`}>
                                    +{scores.heuristic_risk}
                                  </span>
                                </div>
                              )}

                              <div className="score-item" style={{ marginTop: '12px', paddingTop: '12px', borderTop: '2px solid var(--border-primary)' }}>
                                <span className="score-item__label" style={{ fontWeight: '600', fontSize: '0.875rem' }}>
                                  Final Risk Score
                                </span>
                                <Badge variant={verdictStyle.variant} style={{ fontSize: '0.875rem', padding: '4px 12px' }}>
                                  {caseItem.risk_score}/100
                                </Badge>
                              </div>

                              <div style={{ marginTop: '1rem', paddingTop: '1rem', borderTop: '1px solid var(--border-secondary)' }}>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  fullWidth
                                  icon={<ExternalLink size={14} />}
                                >
                                  View Full Report
                                </Button>
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

      {totalPages > 1 && (
        <div className="pagination">
          <Button
            variant="secondary"
            size="sm"
            onClick={firstPage}
            disabled={!hasPrevPage}
            icon={<ChevronsLeft size={16} />}
            aria-label="First page"
          />
          <Button
            variant="secondary"
            size="sm"
            onClick={prevPage}
            disabled={!hasPrevPage}
            icon={<ChevronLeft size={16} />}
            aria-label="Previous page"
          />

          <span style={{ padding: '0 1rem', fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
            Page {currentPage} of {totalPages}
          </span>

          <Button
            variant="secondary"
            size="sm"
            onClick={nextPage}
            disabled={!hasNextPage}
            icon={<ChevronRight size={16} />}
            aria-label="Next page"
          />
          <Button
            variant="secondary"
            size="sm"
            onClick={lastPage}
            disabled={!hasNextPage}
            icon={<ChevronsRight size={16} />}
            aria-label="Last page"
          />

          <select
            value={pageSize}
            onChange={(e) => setPageSize(Number(e.target.value))}
            className="form-select"
            style={{ width: 'auto', marginLeft: '1rem', padding: '0.5rem' }}
            aria-label="Cases per page"
          >
            {PAGE_SIZES.map(size => (
              <option key={size} value={size}>
                {size} per page
              </option>
            ))}
          </select>
        </div>
      )}

      {filteredCases.length === 0 && searchQuery && (
        <div className="cases-empty-filter">
          <EmptyState
            icon={<Search size={48} />}
            title="No Results Found"
            description={`No cases match your search for "${searchQuery}"`}
            action={
              <Button variant="secondary" size="sm" onClick={() => setSearchQuery('')}>
                Clear Search
              </Button>
            }
          />
        </div>
      )}
    </Card>
  );
};

// ============================================================================
// MAIN APP COMPONENT
// ============================================================================

function App() {
  const { theme, toggleTheme } = useTheme();
  const { stats, loading, error, refetch, lastFetch } = useDashboardStats();
  const { notifications, addNotification, removeNotification, success, error: notifyError, warning, info } = useNotifications();
  const [showScrollTop, setShowScrollTop] = useState(false);
  const windowSize = useWindowSize();

  // Setup API interceptors
  useEffect(() => {
    api.setupInterceptors((error) => {
      notifyError(error);
    });
  }, [notifyError]);

  // Keyboard shortcuts
  useKeyboardShortcuts([
    {
      keys: ['r'],
      action: () => {
        refetch();
        // Notification will be shown by the useEffect above
      },
      requireCtrl: true
    },
    {
      keys: ['d'],
      action: toggleTheme,
      requireCtrl: true
    },
    {
      keys: ['k'],
      action: () => {
        const searchInput = document.querySelector('input[type="text"]');
        searchInput?.focus();
      },
      requireCtrl: true
    },
    {
      keys: ['escape'],
      action: () => {
        const searchInput = document.querySelector('input[type="text"]');
        if (document.activeElement === searchInput) {
          searchInput.blur();
        }
      },
      requireCtrl: false
    }
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

  // Auto-refresh notification (disabled to prevent spam)
  const lastFetchRef = useRef(null);
  useEffect(() => {
    // Notification disabled - was showing too frequently
    lastFetchRef.current = lastFetch ? new Date(lastFetch) : null;
  }, [lastFetch, loading]);

  return (
    <div className="app">
      <div className="app__container">
        <Header
          onThemeToggle={toggleTheme}
          theme={theme}
          onRefresh={refetch}
          lastFetch={lastFetch}
        />

        {error && (
          <div className="app__error" role="alert">
            <span className="app__error-icon">
              <AlertTriangle size={20} />
            </span>
            <div style={{ flex: 1 }}>
              <p className="app__error-message">
                <strong>Connection Error:</strong> {error}
              </p>
              <p style={{ fontSize: '0.75rem', marginTop: '4px', color: 'var(--text-secondary)' }}>
                Please check your network connection or backend service.
              </p>
            </div>
            <Button variant="ghost" size="sm" onClick={refetch} icon={<RefreshCw size={16} />}>
              Retry
            </Button>
          </div>
        )}

        <StatsDashboard stats={stats} loading={loading} />

        <UploadSection
          onAnalysisComplete={refetch}
          onNotify={addNotification}
        />

        <CasesTable
          cases={stats.recent_cases}
          loading={loading}
          onNotify={addNotification}
          onCasesUpdate={refetch}
        />

        {showScrollTop && (
          <button
            className="scroll-to-top"
            onClick={scrollToTop}
            aria-label="Scroll to top"
          >
            <ArrowUp size={24} />
          </button>
        )}

        <footer className="app__footer">
          <p className="app__footer-text">
            <strong>PhishGuard Pro</strong> © 2025 • Advanced Email Security Analysis
            {!windowSize.isMobile && (
              <>
                {' • '}
                <kbd style={{ fontSize: '0.7rem', padding: '2px 6px', background: 'var(--bg-surface)', borderRadius: '4px', border: '1px solid var(--border-primary)' }}>
                  Ctrl+R
                </kbd> Refresh
                {' • '}
                <kbd style={{ fontSize: '0.7rem', padding: '2px 6px', background: 'var(--bg-surface)', borderRadius: '4px', border: '1px solid var(--border-primary)' }}>
                  Ctrl+D
                </kbd> Theme
                {' • '}
                <kbd style={{ fontSize: '0.7rem', padding: '2px 6px', background: 'var(--bg-surface)', borderRadius: '4px', border: '1px solid var(--border-primary)' }}>
                  Ctrl+K
                </kbd> Search
              </>
            )}
          </p>
          <p style={{ fontSize: '0.7rem', color: 'var(--text-tertiary)', marginTop: '0.5rem', textAlign: 'center' }}>
            Powered by AI/ML • {windowSize.isMobile ? 'Mobile' : windowSize.isTablet ? 'Tablet' : 'Desktop'} View
            {stats.total_processed > 0 && ` • ${stats.total_processed} emails analyzed`}
          </p>
        </footer>
      </div>

      <ToastContainer
        notifications={notifications}
        onClose={removeNotification}
      />
    </div>
  );
}

export default App;