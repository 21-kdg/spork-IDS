import React, { useState, useEffect } from 'react';
import { Sidebar } from './components/Sidebar';
import { Navbar } from './components/Navbar';
import { Overview } from './pages/Overview';
import { Alerts } from './pages/Alerts';
import { Events } from './pages/Events';
import { Detection } from './pages/Detection';
import { Decisions } from './pages/Decisions';
import { Metrics } from './pages/Metrics';
import { Settings } from './pages/Settings';
import { HealthStatus, DashboardSummary, Alert } from './types';
import { api } from './services/api';

export const App: React.FC = () => {
  const [currentPage, setCurrentPage] = useState<string>('overview');
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [selectedAlertForModal, setSelectedAlertForModal] = useState<Alert | null>(null);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const fetchTelemetry = async (silent: boolean = false) => {
    if (!silent) setIsRefreshing(true);
    try {
      const [healthData, summaryData] = await Promise.all([
        api.getHealth(),
        api.getDashboardSummary(),
      ]);
      setHealth(healthData);
      setSummary(summaryData);
    } catch (err) {
      console.error('Failed to fetch telemetry:', err);
    } finally {
      setIsLoading(false);
      if (!silent) setIsRefreshing(false);
    }
  };

  useEffect(() => {
    fetchTelemetry();
    // Auto-refresh telemetry every 6 seconds
    const interval = setInterval(() => {
      fetchTelemetry(true);
    }, 6000);
    return () => clearInterval(interval);
  }, []);

  const handleSimulateAttack = async () => {
    try {
      setToastMessage('Simulating SSH Brute Force intrusion attack against engine...');
      const res = await api.launchSimulation({ scenario: 'spork/ssh-bf' });
      setToastMessage(res.message);
      fetchTelemetry(false);
      setTimeout(() => setToastMessage(null), 6000);
    } catch (err: any) {
      alert(`Simulation failed: ${err.message}`);
    }
  };

  const pageTitles: Record<string, string> = {
    overview: 'Threat Operations Overview',
    alerts: 'Security & Detection Alerts',
    events: 'Events & Audit Logs',
    detection: 'Scenario Engine & Detection Rules',
    decisions: 'Active Remediation Decisions',
    metrics: 'System Metrics & Telemetry',
    settings: 'Configuration & Integrations',
  };

  return (
    <div className="flex h-screen bg-[#0A0F1D] text-slate-100 overflow-hidden font-sans">
      {/* Sidebar */}
      <Sidebar
        currentPage={currentPage}
        onNavigate={(page) => {
          setCurrentPage(page);
          setSelectedAlertForModal(null);
        }}
        health={health}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <Navbar
          currentPageTitle={pageTitles[currentPage] || 'Spork-IDS'}
          health={health}
          onRefresh={() => fetchTelemetry(false)}
          isRefreshing={isRefreshing}
          onSimulateAttack={handleSimulateAttack}
        />

        {/* Global Toast Notification */}
        {toastMessage && (
          <div className="fixed bottom-6 right-6 z-50 px-4 py-3 rounded-xl bg-slate-900 border border-sky-500/40 text-sky-300 text-xs font-mono shadow-2xl flex items-center space-x-3 animate-fade-in">
            <span className="w-2.5 h-2.5 rounded-full bg-sky-400 animate-ping"></span>
            <span>{toastMessage}</span>
          </div>
        )}

        <main className="flex-1 overflow-y-auto">
          {currentPage === 'overview' && (
            <Overview
              summary={summary}
              isLoading={isLoading}
              onNavigate={setCurrentPage}
              onSelectAlert={(alert) => {
                setSelectedAlertForModal(alert);
                setCurrentPage('alerts');
              }}
              onRefresh={() => fetchTelemetry(true)}
            />
          )}

          {currentPage === 'alerts' && (
            <Alerts
              initialSelectedAlert={selectedAlertForModal}
              onClearSelectedAlert={() => setSelectedAlertForModal(null)}
            />
          )}

          {currentPage === 'events' && <Events />}

          {currentPage === 'detection' && <Detection />}

          {currentPage === 'decisions' && <Decisions />}

          {currentPage === 'metrics' && <Metrics />}

          {currentPage === 'settings' && <Settings />}
        </main>
      </div>
    </div>
  );
};
