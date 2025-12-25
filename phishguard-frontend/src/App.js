// Add 'Navigate' to the import list
import { BrowserRouter as Router, Routes, Route, useNavigate, useParams, Navigate } from 'react-router-dom';
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
// SOC TOOLKIT - THREAT INTELLIGENCE SOURCES
// ============================================================================

const IOC_SOURCES = {
  ip: [
    {name:"VirusTotal", url:"https://www.virustotal.com/gui/ip-address/{data}", logo: "virustotal.com"},
    {name:"AbuseIPDB", url:"https://www.abuseipdb.com/check/{data}", logo: "abuseipdb.com"},
    {name:"Talos", url:"https://talosintelligence.com/reputation_center/lookup?search={data}", logo: "talosintelligence.com"},
    {name:"IBM X-Force", url:"https://exchange.xforce.ibmcloud.com/ip/{data}", logo: "exchange.xforce.ibmcloud.com"},
    {name:"AlienVault OTX", url:"https://otx.alienvault.com/indicator/ip/{data}", logo: "otx.alienvault.com"},
    {name:"Shodan", url:"https://www.shodan.io/search?query={data}", logo: "shodan.io"},
    {name:"Censys", url:"https://search.censys.io/hosts/{data}", logo: "search.censys.io"},
    {name:"GreyNoise", url:"https://www.greynoise.io/viz/ip/{data}", logo: "greynoise.io"},
  ],
  domain: [
    {name:"VirusTotal", url:"https://www.virustotal.com/gui/domain/{data}", logo: "virustotal.com"},
    {name:"Talos", url:"https://talosintelligence.com/reputation_center/lookup?search={data}", logo: "talosintelligence.com"},
    {name:"URLScan", url:"https://urlscan.io/search/#{data}", logo: "urlscan.io"},
    {name:"URLVoid", url:"https://urlvoid.com/scan/{data}/", logo: "urlvoid.com"},
    {name:"WHOIS", url:"https://www.whois.com/whois/{data}", logo: "whois.com"},
    {name:"SecurityTrails", url:"https://securitytrails.com/domain/{data}", logo: "securitytrails.com"},
  ],
  url: [
    {name:"VirusTotal", url:"https://www.virustotal.com/gui/url/{data}", logo: "virustotal.com", needsHash: true},
    {name:"URLScan", url:"https://urlscan.io/search/#{data}", logo: "urlscan.io"},
    {name:"URLVoid", url:"https://urlvoid.com/scan/{data}/", logo: "urlvoid.com", usesDomain: true},
    {name:"URLHaus", url:"https://urlhaus.abuse.ch/browse.php?search={data}", logo: "urlhaus.abuse.ch"},
  ],
  email: [
    {name:"Have I Been Pwned", url:"https://haveibeenpwned.com/unifiedsearch/{data}", logo: "haveibeenpwned.com"},
  ],
  hash: [
    {name:"VirusTotal", url:"https://www.virustotal.com/gui/file/{data}", logo: "virustotal.com"},
    {name:"Hybrid-Analysis", url:"https://www.hybrid-analysis.com/sample/{data}", logo: "hybrid-analysis.com"},
    {name:"MalShare", url:"https://malshare.com/sample.php?action=detail&hash={data}", logo: "malshare.com"},
  ]
};

// Helper function to detect IOC type
const detectIOCType = (value) => {
  if (/^[a-fA-F0-9]{32,128}$/.test(value)) return 'hash';
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return 'email';
  if (/^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$/.test(value)) return 'ip';
  if (/^https?:\/\//.test(value)) return 'url';
  if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(value)) return 'domain';
  return 'unknown';
};

// Helper to extract domain from URL
const extractDomainFromURL = (url) => {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
};

// Helper to generate SHA256 hash (for URL lookups that need it)
const sha256Hash = async (str) => {
  const buffer = new TextEncoder().encode(str);
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
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
 * Handles both ISO Strings (API) and Date Objects (State)
 */
const formatDate = (dateInput, includeTime = true) => {
  if (!dateInput) return 'N/A';
  
  let date;
  
  // 1. If it's a string, fix the timezone Z issue
  if (typeof dateInput === 'string') {
      const normalizedDate = dateInput.endsWith('Z') ? dateInput : dateInput + 'Z';
      date = new Date(normalizedDate);
  } 
  // 2. If it's already a Date object, use it directly
  else {
      date = new Date(dateInput);
  }
  
  // Check if date is valid
  if (isNaN(date.getTime())) return 'Invalid Date';

  const options = {
    year: 'numeric', 
    month: 'short', 
    day: 'numeric',
    ...(includeTime && { hour: '2-digit', minute: '2-digit' })
  };
  
  return date.toLocaleDateString('en-US', options);
};
/**
 * Get relative time string (e.g., "2 hours ago")
 */
/**
 * Get relative time string (e.g., "2 hours ago")
 */
const getRelativeTime = (dateInput) => {
    if (!dateInput) return 'Unknown';
    
    let date;
    
    // 1. Handle String input (API response)
    if (typeof dateInput === 'string') {
        const normalizedDate = dateInput.endsWith('Z') ? dateInput : dateInput + 'Z';
        date = new Date(normalizedDate);
    } 
    // 2. Handle Date object input (App state / lastFetch)
    else {
        date = new Date(dateInput);
    }

    if (isNaN(date.getTime())) return 'Unknown';

    const now = new Date();
    const diffInSeconds = Math.floor((now - date) / 1000);
    
    if (diffInSeconds < 0) return 'Just now';
    if (diffInSeconds < 60) return 'Just now';
    if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)} minutes ago`;
    if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)} hours ago`;
    if (diffInSeconds < 604800) return `${Math.floor(diffInSeconds / 86400)} days ago`;
    
    return formatDate(date, false);
};
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
              Analyzing email for security threats and indicators of compromise...
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
 * Advanced Cases Table - FIXED (Instant Expansion, No Buffering)
 */
const CasesTable = ({ cases, loading, onNotify, onCasesUpdate }) => {
  const navigate = useNavigate();
  const [sortField, setSortField] = useState(SORT_FIELDS.ID);
  const [sortDirection, setSortDirection] = useState('desc');
  const [filter, setFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedRowId, setExpandedRowId] = useState(null);
  
  // REMOVED: Unnecessary loading states that caused the buffer
  
  const [selectedCases, setSelectedCases] = useState(new Set());
  const [showFilters, setShowFilters] = useState(false);
  const [dateFilter, setDateFilter] = useState('all');
  const [deletingCases, setDeletingCases] = useState(new Set());

  // ✅ FIX 1: Instant toggle. No "await" or API calls here.
  const toggleRow = (id) => {
    if (expandedRowId === id) {
      setExpandedRowId(null);
    } else {
      setExpandedRowId(id);
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
        if (selectedCases.has(caseId)) {
          const newSelected = new Set(selectedCases);
          newSelected.delete(caseId);
          setSelectedCases(newSelected);
        }
        onNotify?.('Case deleted successfully!', NOTIFICATION_TYPES.SUCCESS);
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

    return sorted.map((caseItem, index) => ({
      ...caseItem,
      displayId: index + 1, 
      originalId: caseItem.id 
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
      onNotify?.('Copied snippet to clipboard!', NOTIFICATION_TYPES.SUCCESS, 1000);
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
        {/* ✅ FIX: Added tableLayout: 'fixed' to prevent columns from jumping */}
        <table className="cases-table" style={{ width: '100%', tableLayout: 'fixed', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              {/* ✅ FIX: Defined explicit widths for every column */}
              <th style={{ width: '40px' }}>
                <input
                  type="checkbox"
                  checked={selectedCases.size === currentItems.length && currentItems.length > 0}
                  onChange={handleSelectAll}
                  aria-label="Select all cases"
                />
              </th>
              <th style={{ width: '50px' }}></th>
              
              <th style={{ width: '80px' }} onClick={() => handleSort(SORT_FIELDS.ID)} className="cases-table__th--sortable">
                <div className="cases-table__header-content">
                  ID
                  {sortField === SORT_FIELDS.ID && (
                    <span className="sort-indicator">{sortDirection === 'asc' ? '↑' : '↓'}</span>
                  )}
                </div>
              </th>
              
              <th style={{ width: '30%' }} onClick={() => handleSort(SORT_FIELDS.SUBJECT)} className="cases-table__th--sortable">
                <div className="cases-table__header-content">
                  Subject
                  {sortField === SORT_FIELDS.SUBJECT && (
                    <span className="sort-indicator">{sortDirection === 'asc' ? '↑' : '↓'}</span>
                  )}
                </div>
              </th>
              
              <th style={{ width: '20%' }} onClick={() => handleSort(SORT_FIELDS.SENDER)} className="cases-table__th--sortable">
                <div className="cases-table__header-content">
                  Sender
                  {sortField === SORT_FIELDS.SENDER && (
                    <span className="sort-indicator">{sortDirection === 'asc' ? '↑' : '↓'}</span>
                  )}
                </div>
              </th>
              
              <th style={{ width: '120px' }} onClick={() => handleSort(SORT_FIELDS.VERDICT)} className="cases-table__th--sortable">
                <div className="cases-table__header-content">
                  Verdict
                  {sortField === SORT_FIELDS.VERDICT && (
                    <span className="sort-indicator">{sortDirection === 'asc' ? '↑' : '↓'}</span>
                  )}
                </div>
              </th>
              
              <th style={{ width: '150px' }} onClick={() => handleSort(SORT_FIELDS.PROCESSED_AT)} className="cases-table__th--sortable">
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
              const isExpanded = expandedRowId === caseItem.originalId;
              const isSelected = selectedCases.has(caseItem.originalId);
              const isDeleting = deletingCases.has(caseItem.originalId);
              const scores = caseItem.breakdown || {};
              
              const snippet = caseItem.body_analysis?.snippet || "No text content available.";

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
                        onChange={() => handleSelectCase(caseItem.originalId)}
                        onClick={(e) => e.stopPropagation()}
                        aria-label={`Select case ${caseItem.displayId}`}
                      />
                    </td>
                    <td className="cases-table__cell">
                      <button
                        className={`toggle-btn ${isExpanded ? 'toggle-btn--expanded' : ''}`}
                        onClick={() => toggleRow(caseItem.originalId)}
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
                            handleDeleteSingle(caseItem.originalId);
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
                      <td colSpan="8">
                        <div className="case-details">
                          <div className="details-grid">
                            <div className="email-preview">
                              <div className="email-preview__header">
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                                  <h4 style={{ fontSize: '0.875rem', fontWeight: '600', margin: 0 }}>
                                    Email Snippet
                                  </h4>
                                  <Button
                                    variant="ghost"
                                    size="xs"
                                    onClick={() => handleCopyContent(snippet)}
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
                                <div style={{ 
                                    fontFamily: 'monospace', 
                                    whiteSpace: 'pre-wrap', 
                                    fontSize: '0.9rem',
                                    color: 'var(--text-secondary)'
                                }}>
                                    {snippet}
                                </div>
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

                              <div style={{ marginTop: '1rem', paddingTop: '1rem' }}>
  <Button
    variant="ghost"
    size="sm"
    fullWidth
    icon={<ExternalLink size={14} />}
    onClick={() => navigate(`/report/${caseItem.originalId}`)}
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

/**
 * IOC Lookup Dropdown Component
 */
const IOCLookupDropdown = ({ ioc, type, onNotify }) => {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef(null);

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setIsOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleLookup = async (source) => {
    let data = ioc;
    
    // Handle special cases
    if (source.usesDomain && type === 'url') {
      data = extractDomainFromURL(ioc);
    }
    
    if (source.needsHash && type === 'url') {
      data = await sha256Hash(ioc);
    }
    
    const url = source.url.replace('{data}', encodeURIComponent(data));
    window.open(url, '_blank', 'noopener,noreferrer');
    
    onNotify?.(`Opening ${source.name} for lookup`, NOTIFICATION_TYPES.INFO, 2000);
    setIsOpen(false);
  };

  const sources = IOC_SOURCES[type] || [];

  if (sources.length === 0) return null;

  return (
    <div className="ioc-lookup-dropdown" ref={dropdownRef} style={{ position: 'relative', display: 'inline-block' }}>
      <button
        className="btn btn--xs btn--secondary"
        onClick={() => setIsOpen(!isOpen)}
        style={{ 
          display: 'flex', 
          alignItems: 'center', 
          gap: '4px',
          padding: 'var(--space-1) var(--space-3)'
        }}
      >
        <Globe size={14} />
        Lookup
        <ChevronDown size={12} style={{ transform: isOpen ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s' }} />
      </button>

      {isOpen && (
        <div
          className="ioc-lookup-menu"
          style={{
            position: 'absolute',
            top: '100%',
            right: 0,
            marginTop: 'var(--space-1)',
            minWidth: '220px',
            maxHeight: '320px',
            overflowY: 'auto',
            backgroundColor: 'var(--bg-elevated)',
            border: '1px solid var(--border-primary)',
            borderRadius: 'var(--radius-lg)',
            boxShadow: 'var(--shadow-xl)',
            padding: 'var(--space-2)',
            zIndex: 1000,
            animation: 'slideDown 0.2s ease-out'
          }}
        >
          {sources.map((source, idx) => (
            <button
              key={idx}
              onClick={() => handleLookup(source)}
              className="ioc-lookup-item"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 'var(--space-3)',
                width: '100%',
                padding: 'var(--space-2) var(--space-3)',
                border: 'none',
                background: 'transparent',
                borderRadius: 'var(--radius-md)',
                cursor: 'pointer',
                transition: 'background-color var(--transition-fast)',
                textAlign: 'left',
                fontSize: 'var(--font-size-sm)',
                color: 'var(--text-primary)'
              }}
              onMouseEnter={(e) => e.currentTarget.style.backgroundColor = 'var(--bg-overlay)'}
              onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'transparent'}
            >
              <img
                src={`https://www.google.com/s2/favicons?domain=${source.logo}&sz=32`}
                alt={source.name}
                style={{ width: '16px', height: '16px', flexShrink: 0 }}
                onError={(e) => e.target.style.display = 'none'}
              />
              <span style={{ flex: 1 }}>{source.name}</span>
              <ExternalLink size={12} style={{ color: 'var(--text-tertiary)' }} />
            </button>
          ))}
        </div>
      )}
    </div>
  );
};

/**
 * FIXED REPORT PAGE - Matches User's Custom CSS Theme
 */
/**
 * FIXED REPORT PAGE - With Integrated AI Analysis Tab
 */
const ReportPage = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const { notifications, addNotification, removeNotification } = useNotifications();
  
  // 1. State Definitions
  const [caseData, setCaseData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [aiSummary, setAiSummary] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);

  // 2. Fetch Data Effect
  useEffect(() => {
    const fetchCaseDetails = async () => {
      try {
        const response = await api.client.get(`/cases/${id}`);
        setCaseData(response.data);
      } catch (err) {
        setError(err.message || "Failed to load report");
      } finally {
        setLoading(false);
      }
    };
    fetchCaseDetails();
  }, [id]);

  // 3. AI Summary Function
  const handleGenerateSummary = useCallback(async () => {
    if (aiSummary || aiLoading) return; // Prevent duplicate calls
    
    setAiLoading(true);
    try {
      const response = await api.client.post('/ai-summary', {
        subject: caseData.subject,
        sender: caseData.sender,
        risk_score: caseData.risk_score,
        verdict: caseData.verdict,
        body: caseData.body_analysis?.snippet || ""
      });
      setAiSummary(response.data);
    } catch (error) {
      console.error("Failed to generate AI summary:", error);
      addNotification("Failed to generate AI analysis", NOTIFICATION_TYPES.ERROR);
    } finally {
      setAiLoading(false);
    }
  }, [aiSummary, aiLoading, caseData, addNotification]);

  // 4. Auto-trigger AI Analysis when tab is active
  useEffect(() => {
    if (activeTab === 'ai_analysis' && !aiSummary && caseData) {
      handleGenerateSummary();
    }
  }, [activeTab, aiSummary, caseData, handleGenerateSummary]);

  // 5. Loading/Error States
  if (loading) return (
    <div className="app__container" style={{ padding: 'var(--space-8)', textAlign: 'center' }}>
      <div className="loading-spinner" style={{ margin: '0 auto' }}></div>
      <p style={{ marginTop: 'var(--space-4)', color: 'var(--text-secondary)' }}>Loading analysis...</p>
    </div>
  );

  if (error) return (
    <div className="app__container">
        <div className="alert alert--danger">
            <div className="alert__content">{error}</div>
        </div>
        {/* UPDATE THE PATH HERE */}
        <Button onClick={() => navigate('/home')}>Back to Dashboard</Button>
    </div>
  );
  if (!caseData) return null;

  const verdictStyle = getVerdictStyle(caseData.verdict);

  // Helper for tab styling
  const getTabStyle = (tabName) => ({
    padding: 'var(--space-3) var(--space-4)',
    background: 'none',
    border: 'none',
    borderBottom: activeTab === tabName ? '2px solid var(--primary-500)' : '2px solid transparent',
    color: activeTab === tabName ? 'var(--text-primary)' : 'var(--text-secondary)',
    fontWeight: activeTab === tabName ? 'var(--font-weight-bold)' : 'normal',
    cursor: 'pointer',
    fontSize: 'var(--font-size-sm)',
    transition: 'all var(--transition-base)'
  });

  return (
    <>
    <div className="app__container" style={{ maxWidth: '1200px' }}>
      
      {/* 1. HEADER & NAV */}
      <div style={{ marginBottom: 'var(--space-6)' }}>
        {/* UPDATE THE PATH HERE */}
        <Button variant="ghost" onClick={() => navigate('/home')} icon={<ChevronLeft size={16} />}>
          Back to Dashboard
        </Button>
      </div>

      <div style={{ 
          display: 'flex', 
          justifyContent: 'space-between', 
          alignItems: 'flex-start', 
          marginBottom: 'var(--space-8)', 
          flexWrap: 'wrap', 
          gap: 'var(--space-4)' 
      }}>
        <div>
          <h1 style={{ 
              fontSize: 'var(--font-size-3xl)', 
              fontWeight: 'var(--font-weight-bold)', 
              color: 'var(--text-primary)', 
              marginBottom: 'var(--space-2)' 
          }}>
            Analysis Report #{caseData.id}
          </h1>
          <div style={{ display: 'flex', gap: 'var(--space-4)', color: 'var(--text-tertiary)', fontSize: 'var(--font-size-sm)' }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Clock size={14} /> {formatDate(caseData.processed_at)}
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Hash size={14} /> ID: {caseData.email_id || 'N/A'}
            </span>
          </div>
        </div>

        <div style={{ textAlign: 'right' }}>
           <Badge variant={verdictStyle.variant} style={{ fontSize: 'var(--font-size-base)', padding: 'var(--space-2) var(--space-4)' }}>
             {verdictStyle.icon}
             <span style={{ marginLeft: '8px' }}>{caseData.verdict}</span>
           </Badge>
           <div style={{ marginTop: 'var(--space-2)', fontSize: 'var(--font-size-sm)', color: 'var(--text-secondary)' }}>
             Risk Score: <strong style={{ color: caseData.risk_score > 70 ? 'var(--danger-500)' : 'var(--text-primary)' }}>
               {caseData.risk_score}/100
             </strong>
           </div>
        </div>
      </div>

      {/* 2. TABS (Modified) */}
      <div style={{ 
          display: 'flex', 
          alignItems: 'center',
          marginBottom: 'var(--space-6)', 
          borderBottom: '1px solid var(--border-primary)' 
      }}>
        <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
          {/* Changed 'advanced' to 'ai_analysis' */}
          {['overview', 'iocs', 'ai_analysis'].map(tab => (
              <button key={tab} onClick={() => setActiveTab(tab)} style={getTabStyle(tab)}>
                  {tab === 'iocs' ? 'IOCs' : tab === 'ai_analysis' ? 'AI Analysis' : tab.charAt(0).toUpperCase() + tab.slice(1)}
              </button>
          ))}
        </div>
        {/* Button removed here */}
      </div>

      {/* 3. TAB CONTENT */}
      
      {/* === OVERVIEW TAB === */}
      {activeTab === 'overview' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(500px, 1fr))', gap: 'var(--space-6)' }}>

           {/* Email Details Card */}
           <Card>
               <div className="card__header">
                   <h3 style={{ fontSize: 'var(--font-size-lg)', fontWeight: '600', display: 'flex', alignItems: 'center', gap: '8px' }}>
                       <Mail size={20}/> Email Details
                   </h3>
               </div>
               <div className="card__body" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
                   {[
                       { label: 'Subject', value: caseData.subject },
                       { label: 'Sender', value: caseData.sender },
                       { label: 'Received', value: formatDate(caseData.received_time) }
                   ].map((item, i) => (
                       <div key={i} style={{ 
                           padding: 'var(--space-3)', 
                           backgroundColor: 'var(--bg-subtle)', 
                           borderRadius: 'var(--radius-md)',
                           border: '1px solid var(--border-secondary)'
                       }}>
                           <span style={{ 
                               display: 'block', 
                               fontSize: 'var(--font-size-xs)', 
                               color: 'var(--text-tertiary)', 
                               textTransform: 'uppercase', 
                               marginBottom: '4px' 
                           }}>
                               {item.label}
                           </span>
                           <span style={{ 
                               color: 'var(--text-primary)', 
                               fontWeight: '500', 
                               wordBreak: 'break-word' 
                           }}>
                               {item.value}
                           </span>
                       </div>
                   ))}
               </div>
           </Card>

           {/* Risk Breakdown Card */}
           <Card>
               <div className="card__header">
                   <h3 style={{ fontSize: 'var(--font-size-lg)', fontWeight: '600', display: 'flex', alignItems: 'center', gap: '8px' }}>
                       <Activity size={20}/> Scoring Breakdown
                   </h3>
               </div>
               <div className="card__body">
                   <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
                       {Object.entries(caseData.breakdown || {}).map(([key, score]) => (
                           <div key={key} style={{ 
                               display: 'flex', 
                               justifyContent: 'space-between', 
                               paddingBottom: 'var(--space-2)', 
                               borderBottom: '1px dashed var(--border-secondary)' 
                           }}>
                               <span style={{ textTransform: 'capitalize', color: 'var(--text-secondary)' }}>
                                   {key.replace('_', ' ')}
                               </span>
                               <span style={{ 
                                   fontWeight: 'bold', 
                                   color: score > 0 ? 'var(--danger-500)' : 'var(--success-500)' 
                               }}>
                                   {score > 0 ? `+${score}` : score}
                               </span>
                           </div>
                       ))}
                       <div style={{ 
                           marginTop: 'var(--space-4)', 
                           paddingTop: 'var(--space-3)', 
                           borderTop: '2px solid var(--border-primary)', 
                           display: 'flex', 
                           justifyContent: 'space-between' 
                       }}>
                           <strong style={{ color: 'var(--text-primary)' }}>Total Risk Score</strong>
                           <strong style={{ color: 'var(--text-primary)' }}>{caseData.risk_score}/100</strong>
                       </div>
                   </div>
               </div>
           </Card>
           
           {/* Static AI & Body Analysis Card (ML Model) */}
           <Card style={{ gridColumn: '1 / -1' }}>
               <div className="card__header">
                   <h3 style={{ fontSize: 'var(--font-size-lg)', fontWeight: '600', display: 'flex', alignItems: 'center', gap: '8px' }}>
                       <Zap size={20}/> Body Analysis & ML
                   </h3>
               </div>
               <div className="card__body">
                   <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: 'var(--space-6)', marginBottom: 'var(--space-6)' }}>
                       <div>
                           <h4 style={{ fontSize: 'var(--font-size-sm)', color: 'var(--text-tertiary)', marginBottom: 'var(--space-2)' }}>ML Model Prediction</h4>
                           <div style={{ padding: 'var(--space-3)', backgroundColor: 'var(--bg-subtle)', borderRadius: 'var(--radius-md)' }}>
                               <div style={{ marginBottom: '4px', color: 'var(--text-primary)' }}>
                                   Is Phishing: <strong>{caseData.ml_prediction?.is_phishing ? 'YES' : 'NO'}</strong>
                               </div>
                               <div style={{ color: 'var(--text-secondary)' }}>
                                   Confidence: <strong>{Math.round((caseData.ml_prediction?.confidence || 0) * 100)}%</strong>
                               </div>
                           </div>
                       </div>
                       <div>
                           <h4 style={{ fontSize: 'var(--font-size-sm)', color: 'var(--text-tertiary)', marginBottom: 'var(--space-2)' }}>Urgency & Tone</h4>
                           <div style={{ padding: 'var(--space-3)', backgroundColor: 'var(--bg-subtle)', borderRadius: 'var(--radius-md)' }}>
                               <div style={{ color: 'var(--text-primary)' }}>
                                   Urgency Detected: <strong>{caseData.body_analysis?.urgency_detected ? 'Yes' : 'No'}</strong>
                               </div>
                           </div>
                       </div>
                   </div>
                   <div>
                       <h4 style={{ fontSize: 'var(--font-size-sm)', color: 'var(--text-tertiary)', marginBottom: 'var(--space-2)' }}>Content Snippet</h4>
                       <div style={{ 
                           fontFamily: 'monospace', 
                           backgroundColor: 'var(--bg-base)', 
                           padding: 'var(--space-4)', 
                           borderRadius: 'var(--radius-md)', 
                           fontSize: 'var(--font-size-sm)',
                           color: 'var(--text-secondary)',
                           border: '1px solid var(--border-secondary)'
                       }}>
                           {caseData.body_analysis?.snippet || "No snippet available"}
                       </div>
                   </div>
               </div>
           </Card>
        </div>
      )}

      {/* === IOCS TAB === */}
      {activeTab === 'iocs' && (
        <div style={{ display: 'grid', gap: 'var(--space-6)' }}>
          
          {/* 1. URLs & Domains Table */}
          <Card className="card--overflow-visible">
            <div className="card__header">
              <h3 style={{ fontSize: 'var(--font-size-lg)', fontWeight: '600', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <LinkIcon size={20}/> URLs & Domains
              </h3>
            </div>
            <div className="card__body" style={{ padding: 0 }}>
              {(caseData.iocs?.urls?.length > 0 || caseData.iocs?.domains?.length > 0) ? (
                <div style={{ maxHeight: '500px', overflowY: 'auto' }}>
                  <table className="cases-table" style={{ tableLayout: 'fixed', width: '100%' }}>
                    <thead style={{ position: 'sticky', top: 0, backgroundColor: 'var(--bg-surface)', zIndex: 10 }}>
                      <tr>
                        <th style={{ width: '100px' }}>Type</th>
                        <th>Value</th>
                        <th style={{ width: '120px', textAlign: 'right', paddingRight: 'var(--space-6)' }}>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {/* URLs */}
                      {caseData.iocs?.urls?.map((url, i) => {
                        const iocType = detectIOCType(url);
                        return (
                          <tr key={`url-${i}`} className="cases-table__row">
                            <td className="cases-table__cell">
                              <Badge variant="info" icon={<LinkIcon size={12} />}>
                                {iocType.toUpperCase()}
                              </Badge>
                            </td>
                            <td className="cases-table__cell" style={{ 
                              wordBreak: 'break-all', 
                              fontFamily: 'monospace',
                              fontSize: 'var(--font-size-xs)'
                            }}>
                              {url}
                            </td>
                            <td className="cases-table__cell" style={{ textAlign: 'right', overflow: 'visible' }}>
                              <div style={{ display: 'flex', gap: 'var(--space-2)', justifyContent: 'flex-end' }}>
                                <Tooltip content="Copy">
                                  <Button
                                    variant="ghost"
                                    size="xs"
                                    icon={<Copy size={14} />}
                                    onClick={() => {
                                      copyToClipboard(url);
                                      addNotification?.('Copied!', NOTIFICATION_TYPES.SUCCESS, 1000);
                                    }}
                                  />
                                </Tooltip>
                                <IOCLookupDropdown 
                                  ioc={url} 
                                  type={iocType}
                                  onNotify={addNotification}
                                />
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                      {/* Domains */}
                      {caseData.iocs?.domains?.map((domain, i) => (
                        <tr key={`dom-${i}`} className="cases-table__row">
                          <td className="cases-table__cell">
                            <Badge variant="neutral" icon={<Globe size={12} />}>
                              DOMAIN
                            </Badge>
                          </td>
                          <td className="cases-table__cell" style={{ 
                            fontFamily: 'monospace',
                            fontSize: 'var(--font-size-xs)'
                          }}>
                            {domain}
                          </td>
                          <td className="cases-table__cell" style={{ textAlign: 'right', overflow: 'visible' }}>
                            <div style={{ display: 'flex', gap: 'var(--space-2)', justifyContent: 'flex-end' }}>
                              <Tooltip content="Copy">
                                <Button
                                  variant="ghost"
                                  size="xs"
                                  icon={<Copy size={14} />}
                                  onClick={() => {
                                    copyToClipboard(domain);
                                    addNotification?.('Copied!', NOTIFICATION_TYPES.SUCCESS, 1000);
                                  }}
                                />
                              </Tooltip>
                              <IOCLookupDropdown 
                                ioc={domain} 
                                type="domain"
                                onNotify={addNotification}
                              />
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div style={{ padding: 'var(--space-12)', textAlign: 'center' }}>
                  <EmptyState
                    icon={<LinkIcon size={48} />}
                    title="No URLs Found"
                    description="No URLs or domains were extracted."
                  />
                </div>
              )}
            </div>
          </Card>

          {/* 2. IP Addresses Table */}
          <Card className="card--overflow-visible">
            <div className="card__header">
              <h3 style={{ fontSize: 'var(--font-size-lg)', fontWeight: '600', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Server size={20}/> IP Addresses
              </h3>
            </div>
            <div className="card__body" style={{ padding: 0 }}>
              {caseData.iocs?.ips?.length > 0 ? (
                <div style={{ maxHeight: '500px', overflowY: 'auto' }}>
                  <table className="cases-table" style={{ tableLayout: 'fixed', width: '100%' }}>
                    <thead style={{ position: 'sticky', top: 0, backgroundColor: 'var(--bg-surface)', zIndex: 10 }}>
                      <tr>
                        <th style={{ width: '100px' }}>Type</th>
                        <th>Value</th>
                        <th style={{ width: '120px', textAlign: 'right', paddingRight: 'var(--space-6)' }}>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {caseData.iocs.ips.map((ip, i) => (
                        <tr key={`ip-${i}`} className="cases-table__row">
                          <td className="cases-table__cell">
                            <Badge variant="warning" icon={<Server size={12} />}>
                              IPV4
                            </Badge>
                          </td>
                          <td className="cases-table__cell" style={{ 
                            fontFamily: 'monospace',
                            fontSize: 'var(--font-size-xs)'
                          }}>
                            {ip}
                          </td>
                          <td className="cases-table__cell" style={{ textAlign: 'right', overflow: 'visible' }}>
                            <div style={{ display: 'flex', gap: 'var(--space-2)', justifyContent: 'flex-end' }}>
                              <Tooltip content="Copy">
                                <Button
                                  variant="ghost"
                                  size="xs"
                                  icon={<Copy size={14} />}
                                  onClick={() => {
                                    copyToClipboard(ip);
                                    addNotification?.('Copied!', NOTIFICATION_TYPES.SUCCESS, 1000);
                                  }}
                                />
                              </Tooltip>
                              <IOCLookupDropdown 
                                ioc={ip} 
                                type="ip"
                                onNotify={addNotification}
                              />
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div style={{ padding: 'var(--space-12)', textAlign: 'center' }}>
                  <EmptyState
                    icon={<Server size={48} />}
                    title="No IPs Found"
                    description="No IP addresses were extracted."
                  />
                </div>
              )}
            </div>
          </Card>

          {/* 3. File Hashes Table */}
          <Card className="card--overflow-visible">
            <div className="card__header">
              <h3 style={{ fontSize: 'var(--font-size-lg)', fontWeight: '600', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Hash size={20}/> File Hashes
              </h3>
            </div>
            <div className="card__body" style={{ padding: 0 }}>
              {caseData.iocs?.hashes?.md5?.length > 0 ? (
                <div style={{ maxHeight: '500px', overflowY: 'auto' }}>
                  <table className="cases-table" style={{ tableLayout: 'fixed', width: '100%' }}>
                    <thead style={{ position: 'sticky', top: 0, backgroundColor: 'var(--bg-surface)', zIndex: 10 }}>
                      <tr>
                        <th style={{ width: '100px' }}>Type</th>
                        <th>Value</th>
                        <th style={{ width: '120px', textAlign: 'right', paddingRight: 'var(--space-6)' }}>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {caseData.iocs.hashes.md5.map((hash, i) => (
                        <tr key={`hash-${i}`} className="cases-table__row">
                          <td className="cases-table__cell">
                            <Badge variant="neutral" icon={<Hash size={12} />}>
                              MD5
                            </Badge>
                          </td>
                          <td className="cases-table__cell" style={{ 
                            wordBreak: 'break-all', 
                            fontFamily: 'monospace',
                            fontSize: 'var(--font-size-xs)'
                          }}>
                            {hash}
                          </td>
                          <td className="cases-table__cell" style={{ textAlign: 'right', overflow: 'visible' }}>
                            <div style={{ display: 'flex', gap: 'var(--space-2)', justifyContent: 'flex-end' }}>
                              <Tooltip content="Copy">
                                <Button
                                  variant="ghost"
                                  size="xs"
                                  icon={<Copy size={14} />}
                                  onClick={() => {
                                    copyToClipboard(hash);
                                    addNotification?.('Copied!', NOTIFICATION_TYPES.SUCCESS, 1000);
                                  }}
                                />
                              </Tooltip>
                              <IOCLookupDropdown 
                                ioc={hash} 
                                type="hash"
                                onNotify={addNotification}
                              />
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div style={{ padding: 'var(--space-12)', textAlign: 'center' }}>
                  <EmptyState
                    icon={<Hash size={48} />}
                    title="No Hashes Found"
                    description="No file hashes were detected."
                  />
                </div>
              )}
            </div>
          </Card>

          {/* 4. Attachment Analysis */}
          <Card>
            <div className="card__header">
                <h3 style={{ fontSize: 'var(--font-size-lg)', fontWeight: '600', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <File size={20}/> Attachment Analysis
                </h3>
            </div>
            <div className="card__body">
                {caseData.attachments && caseData.attachments.length > 0 ? (
                    caseData.attachments.map((att, i) => (
                        <div key={i} style={{ 
                            border: '1px solid var(--border-primary)', 
                            borderRadius: 'var(--radius-lg)', 
                            padding: 'var(--space-4)', 
                            marginBottom: 'var(--space-4)',
                            backgroundColor: 'var(--bg-subtle)'
                        }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 'var(--space-2)' }}>
                                <strong style={{ color: 'var(--text-primary)' }}>{att.filename}</strong>
                                <Badge variant={att.risk_score > 0 ? 'danger' : 'success'}>Score: {att.risk_score}</Badge>
                            </div>
                            <div style={{ fontSize: 'var(--font-size-sm)', color: 'var(--text-secondary)' }}>
                                <p>Type: {att.file_type}</p>
                                <p>MD5: <span style={{ fontFamily: 'monospace' }}>{att.md5}</span></p>
                                {att.findings && att.findings.length > 0 && (
                                    <div style={{ marginTop: 'var(--space-2)' }}>
                                        <strong>Findings:</strong>
                                        <ul style={{ paddingLeft: '20px', margin: '5px 0' }}>
                                            {att.findings.map((f, idx) => (
                                                <li key={idx} style={{ color: 'var(--danger-500)' }}>{f}</li>
                                            ))}
                                        </ul>
                                    </div>
                                )}
                            </div>
                        </div>
                    ))
                ) : (
                    <p style={{ color: 'var(--text-tertiary)', fontStyle: 'italic' }}>No attachments found.</p>
                )}
            </div>
          </Card>

        </div>
      )}

      {/* === NEW AI ANALYSIS TAB (Replaces Advanced) === */}
      {activeTab === 'ai_analysis' && (
        <div style={{ display: 'grid', gap: 'var(--space-6)' }}>
            
            {/* Loading Buffer */}
            {aiLoading && (
                <Card>
                    <div style={{ padding: 'var(--space-12)', textAlign: 'center' }}>
                        <div className="loading-spinner" style={{ margin: '0 auto 1.5rem', width: '40px', height: '40px' }}></div>
                        <h3 style={{ fontSize: '1.1rem', marginBottom: '0.5rem' }}>Analyzing Threat Context...</h3>
                        <p style={{ color: 'var(--text-secondary)' }}>Our AI is generating a comprehensive security summary.</p>
                    </div>
                </Card>
            )}

            {/* AI Summary Result */}
            {!aiLoading && aiSummary && (
                <Card style={{ borderLeft: '4px solid var(--primary-500)' }}>
                    <div className="card__header">
                        <h3 style={{ fontSize: 'var(--font-size-lg)', fontWeight: '600', display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <Zap size={20} className="text-primary-500" /> Executive Threat Summary
                        </h3>
                    </div>
                    <div className="card__body">
                        <p style={{ marginBottom: '1.5rem', fontSize: '1.05rem', lineHeight: '1.7' }}>
                            {aiSummary.summary}
                        </p>
                        
                        <div style={{ backgroundColor: 'var(--bg-subtle)', padding: 'var(--space-4)', borderRadius: 'var(--radius-md)' }}>
                            <h4 style={{ fontSize: '0.9rem', fontWeight: '700', color: 'var(--text-primary)', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '6px' }}>
                                <CheckCircle size={16} /> Recommended Actions:
                            </h4>
                            <ul style={{ paddingLeft: '1.5rem', margin: 0 }}>
                                {aiSummary.actions?.map((action, idx) => (
                                    <li key={idx} style={{ marginBottom: '0.5rem', color: 'var(--text-secondary)' }}>{action}</li>
                                ))}
                            </ul>
                        </div>
                    </div>
                </Card>
            )}

            {/* Fallback / Error State */}
            {!aiLoading && !aiSummary && (
                <EmptyState 
                    icon={<AlertTriangle size={48} />} 
                    title="Analysis Not Available" 
                    description="Unable to generate the AI summary at this time." 
                    action={
                        <Button variant="secondary" onClick={handleGenerateSummary}>Try Again</Button>
                    }
                />
            )}
        </div>
      )}

    </div>
    <ToastContainer notifications={notifications} onClose={removeNotification} />
    </>
  );
};
// FILE: App.js

// ... existing components ...

/**
 * NEW: Threat Intelligence Timeline Component
 */
const ThreatActivityTimeline = ({ cases, initialRange = '24h' }) => {
  const [timeRange, setTimeRange] = useState(initialRange);

  const activityData = useMemo(() => {
    if (!cases || cases.length === 0) return [];
    
    const now = new Date();
    // Calculate cutoff based on range
    const cutoff = new Date(now.getTime() - (
      timeRange === '24h' ? 86400000 : 
      timeRange === '7d' ? 604800000 : 
      2592000000 // 30d
    ));
    
    return cases
      .filter(c => new Date(c.processed_at) > cutoff)
      .map(c => ({
        id: c.id,
        time: new Date(c.processed_at),
        verdict: c.verdict,
        risk_score: c.risk_score,
        sender_domain: extractDomain(c.sender),
        subject: c.subject
      }))
      .sort((a, b) => b.time - a.time);
  }, [cases, timeRange]);

  return (
    <Card className="timeline-card" style={{ marginBottom: 'var(--space-6)' }}>
      <div className="card__header">
        <h3 style={{ fontSize: 'var(--font-size-lg)', fontWeight: '600', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Activity size={20} /> Threat Activity Timeline
        </h3>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          {['24h', '7d', '30d'].map(range => (
            <Button
              key={range}
              variant={timeRange === range ? 'primary' : 'ghost'}
              size="xs"
              onClick={() => setTimeRange(range)}
            >
              {range}
            </Button>
          ))}
        </div>
      </div>
      <div className="card__body">
        {activityData.length > 0 ? (
          <div className="custom-scrollbar" style={{ maxHeight: '300px', overflowY: 'auto', paddingRight: '4px' }}>
            {activityData.map((item) => (
              <div key={item.id} style={{
                display: 'flex',
                gap: '1rem',
                padding: '0.75rem',
                borderLeft: `4px solid ${getVerdictStyle(item.verdict).color}`,
                marginBottom: '0.5rem',
                backgroundColor: 'var(--bg-subtle)',
                borderRadius: 'var(--radius-md)',
                alignItems: 'center'
              }}>
                <div style={{ minWidth: '100px', fontSize: '0.75rem', color: 'var(--text-tertiary)', display: 'flex', flexDirection: 'column' }}>
                  <span style={{ fontWeight: '600', color: 'var(--text-secondary)' }}>{item.time.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</span>
                  <span>{formatDate(item.time, false)}</span>
                </div>
                
                <div style={{ flex: 1, minWidth: 0 }}> {/* minWidth 0 for text truncation */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                    <Badge variant={getVerdictStyle(item.verdict).variant} style={{ fontSize: '0.7rem', padding: '2px 6px' }}>
                      {item.verdict}
                    </Badge>
                    <span style={{ 
                      fontSize: '0.875rem', 
                      fontWeight: '500', 
                      whiteSpace: 'nowrap', 
                      overflow: 'hidden', 
                      textOverflow: 'ellipsis',
                      maxWidth: '400px'
                    }}>
                      {item.subject || 'No Subject'}
                    </span>
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', display: 'flex', gap: '12px' }}>
                    <span>From: <strong style={{ color: 'var(--text-secondary)' }}>{item.sender_domain}</strong></span>
                    <span>Risk: <strong style={{ color: item.risk_score > 70 ? 'var(--danger-500)' : 'var(--text-secondary)' }}>{item.risk_score}/100</strong></span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
           <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-tertiary)' }}>
             <Activity size={32} style={{ opacity: 0.3, marginBottom: '0.5rem' }} />
             <p>No activity detected in the last {timeRange}.</p>
           </div>
        )}
      </div>
    </Card>
  );
};

// ============================================================================
// MAIN APP COMPONENT
// ============================================================================
// ============================================================================
// MAIN APP COMPONENT
// ============================================================================
const Dashboard = () => {
  // Pass theme props if needed, or use the hook inside Header
  const { theme, toggleTheme } = useTheme(); 
  const { stats, loading, error, refetch, lastFetch } = useDashboardStats();
  const { notifications, addNotification, removeNotification, success, error: notifyError } = useNotifications();
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
      action: () => refetch(),
      requireCtrl: true
    },
    {
      keys: ['d'],
      action: toggleTheme,
      requireCtrl: true
    }
  ]);

  // Scroll to top logic
  useEffect(() => {
    const handleScroll = () => setShowScrollTop(window.scrollY > 400);
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const scrollToTop = () => window.scrollTo({ top: 0, behavior: 'smooth' });

  return (
    <>
      <div className="app__container">
        <Header
          onThemeToggle={toggleTheme}
          theme={theme}
          onRefresh={refetch}
          lastFetch={lastFetch}
        />

        {error && (
          <div className="app__error" role="alert">
            <span className="app__error-icon"><AlertTriangle size={20} /></span>
            <div style={{ flex: 1 }}>
              <p className="app__error-message"><strong>Connection Error:</strong> {error}</p>
            </div>
            <Button variant="ghost" size="sm" onClick={refetch} icon={<RefreshCw size={16} />}>Retry</Button>
          </div>
        )}

        <StatsDashboard stats={stats} loading={loading} />
        {/* Only show timeline if we have data to prevent layout jump */}
        {!loading && (
           <ThreatActivityTimeline cases={stats.recent_cases} initialRange="24h" />
        )}

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
          <button className="scroll-to-top" onClick={scrollToTop} aria-label="Scroll to top">
            <ArrowUp size={24} />
          </button>
        )}

        <footer className="app__footer">
          <p className="app__footer-text"><strong>PhishGuard Pro</strong> © 2025</p>
        </footer>
      </div>

      <ToastContainer notifications={notifications} onClose={removeNotification} />
    </>
  );
}


// ============================================================================
// 3. NEW MAIN ENTRY POINT: APP (Handles Routing)
// ============================================================================
function App() {
  const { theme } = useTheme(); // Get theme here to apply to the main div wrapper

  return (
    <Router>
      <div className="app" data-theme={theme}>
        <Routes>
          {/* Redirect root URL ("/") to "/home" */}
          <Route path="/" element={<Navigate to="/home" replace />} />

          {/* The Main Dashboard is now at "/home" */}
          <Route path="/home" element={<Dashboard />} />
          
          {/* Report Page */}
          <Route path="/report/:id" element={<ReportPage />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;