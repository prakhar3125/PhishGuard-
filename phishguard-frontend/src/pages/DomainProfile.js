import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { 
  ChevronLeft, 
  Globe, 
  Mail, 
  AlertOctagon, 
  Activity, 
  ExternalLink, 
  Search 
} from "lucide-react";

// ============================================================================
// IMPORTS
// You must ensure these components are exported from their respective files
// ============================================================================

// 1. Shared UI Components (Move these from App.js to src/components/UI.js)
import { 
  Header, 
  Button, 
  StatCard, 
  Card, 
  Badge 
} from '../components/UI'; 

// 2. Complex Components (Move these to src/components/...)
import { ThreatActivityTimeline } from '../components/ThreatActivityTimeline';
import { CasesTable } from '../components/CasesTable';

// 3. Utilities & Hooks (Move these to src/utils/ and src/hooks/)
import { api } from '../utils/api';
import { useTheme } from '../hooks/useTheme';

const DomainProfile = () => {
  const { domainName } = useParams();
  const navigate = useNavigate();
  // Access theme for the Header
  const { theme, toggleTheme } = useTheme(); 
  const decodedDomain = decodeURIComponent(domainName);
  
  const [cases, setCases] = useState([]);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState({ total: 0, malicious: 0, riskSum: 0 });

  useEffect(() => {
    const loadDomainData = async () => {
      setLoading(true);
      // Fetch up to 100 recent cases for this specific domain/sender
      const { data } = await api.fetchCases({ sender: decodedDomain, limit: 100 });
      
      if (data) {
        setCases(data);
        // Calculate quick stats
        const stats = data.reduce((acc, curr) => ({
          total: acc.total + 1,
          malicious: curr.verdict === 'MALICIOUS' ? acc.malicious + 1 : acc.malicious,
          riskSum: acc.riskSum + (curr.risk_score || 0)
        }), { total: 0, malicious: 0, riskSum: 0 });
        setStats(stats);
      }
      setLoading(false);
    };
    loadDomainData();
  }, [decodedDomain]);

  const avgRisk = stats.total > 0 ? Math.round(stats.riskSum / stats.total) : 0;

  return (
    <div className="app__container">
      {/* 1. Global Header Integration */}
      <Header onThemeToggle={toggleTheme} theme={theme} />

      <div style={{ padding: 'var(--space-6)' }}>
        {/* Navigation & Header */}
        <div style={{ marginBottom: 'var(--space-6)' }}>
            <Button variant="ghost" onClick={() => navigate('/home')} icon={<ChevronLeft size={16} />}>
            Back to Dashboard
            </Button>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem', marginBottom: 'var(--space-8)' }}>
            <div style={{ 
                width: '64px', height: '64px', borderRadius: '16px', 
                backgroundColor: 'var(--bg-elevated)', border: '1px solid var(--border-primary)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                boxShadow: 'var(--shadow-lg)'
            }}>
            <Globe size={32} style={{ color: 'var(--primary-500)' }} />
            </div>
            <div>
            <h1 style={{ fontSize: '2rem', fontWeight: 'bold', margin: '0 0 4px 0', letterSpacing: '-0.5px' }}>{decodedDomain}</h1>
            <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Sender Profile & Threat History</span>
                <Badge variant={avgRisk > 70 ? 'danger' : avgRisk > 40 ? 'warning' : 'success'}>
                    Reputation: {avgRisk > 70 ? 'Poor' : avgRisk > 40 ? 'Suspicious' : 'Good'}
                </Badge>
            </div>
            </div>
        </div>

        {/* Stats Grid */}
        <div className="stats-dashboard" style={{ marginBottom: 'var(--space-8)' }}>
            <StatCard icon={<Mail size={24}/>} label="Total Emails" value={stats.total} />
            <StatCard icon={<AlertOctagon size={24}/>} label="Malicious" value={stats.malicious} />
            <StatCard 
                icon={<Activity size={24}/>} 
                label="Avg Risk Score" 
                value={avgRisk + '/100'} 
                trend={avgRisk > 50 ? 1 : 0} 
                trendValue={avgRisk > 70 ? 'High' : 'Moderate'}
            />
            {/* Domain Actions Card */}
            <Card className="stat-card" hover style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', gap: '8px' }}>
                <Button variant="ghost" size="sm" fullWidth icon={<ExternalLink size={14}/>} onClick={() => window.open(`https://www.virustotal.com/gui/domain/${decodedDomain}`, '_blank')}>
                    VirusTotal Lookup
                </Button>
                <Button variant="ghost" size="sm" fullWidth icon={<Search size={14}/>} onClick={() => window.open(`https://who.is/whois/${decodedDomain}`, '_blank')}>
                    Whois Record
                </Button>
            </Card>
        </div>

        {/* Timeline - Locked to chronological view for clarity */}
        <h3 style={{ fontSize: '1.25rem', fontWeight: '600', marginBottom: '1rem' }}>Activity Timeline</h3>
        {loading ? (
            <div className="loading-spinner"></div>
        ) : (
            <ThreatActivityTimeline 
                cases={cases} 
                initialRange="30d" 
                hideSenderGrouping={true} 
            />
        )}
        
        {/* Full Case List */}
        <div style={{ marginTop: '3rem' }}>
            <h3 style={{ fontSize: '1.25rem', fontWeight: '600', marginBottom: '1rem' }}>Detailed Case Log</h3>
            <CasesTable cases={cases} loading={loading} />
        </div>
      </div>
    </div>
  );
};

export default DomainProfile;