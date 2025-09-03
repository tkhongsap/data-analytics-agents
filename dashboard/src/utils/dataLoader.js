import Papa from 'papaparse';
import { format, parseISO, subDays, startOfDay, endOfDay } from 'date-fns';

export const loadCyberData = async () => {
  try {
    const response = await fetch('/enhanced_data.csv');
    const csvText = await response.text();
    
    const parsed = Papa.parse(csvText, {
      header: true,
      skipEmptyLines: true,
      dynamicTyping: true
    });

    console.log('Parsed CSV rows:', parsed.data.length);
    console.log('Sample row:', parsed.data[0]);

    const data = parsed.data.map(row => ({
      ...row,
      timestamp: typeof row.timestamp === 'string' ? parseISO(row.timestamp) : new Date(),
      risk_score: parseFloat(row.max_abs_z) || 0,
      risk_category: row.risk_category || 'Normal/Moderate',
      event_id: parseInt(row.event_id) || 0
    }));

    console.log('Processed data sample:', data[0]);
    const result = processData(data);
    console.log('Dashboard data:', result);
    return result;
  } catch (error) {
    console.error('Error loading data:', error);
    return generateMockData();
  }
};

const processData = (rawData) => {
  // Calculate key metrics
  const criticalAlerts = rawData.filter(d => d.risk_category === 'Critical').length;
  const highAlerts = rawData.filter(d => d.risk_category === 'High Risk').length;
  const totalAlerts = rawData.length;
  const anomalyRate = ((criticalAlerts + highAlerts) / totalAlerts * 100).toFixed(1);
  
  // Get unique users and hosts with threats
  const uniqueUsers = new Set(rawData.filter(d => d.risk_category !== 'Normal/Moderate').map(d => d.username)).size;
  const uniqueHosts = new Set(rawData.filter(d => d.risk_category !== 'Normal/Moderate').map(d => d.hostname)).size;

  // Create timeline data (last 7 days)
  const timelineData = createTimelineData(rawData);
  
  // Create risk distribution
  const riskDistribution = [
    { name: 'Critical', value: criticalAlerts, color: '#ef4444' },
    { name: 'High Risk', value: rawData.filter(d => d.risk_category === 'High Risk').length, color: '#fb923c' },
    { name: 'Normal/Moderate', value: rawData.filter(d => d.risk_category === 'Normal/Moderate').length, color: '#22c55e' }
  ].filter(item => item.value > 0);

  // Top threats by event type
  const threatCounts = rawData.reduce((acc, row) => {
    if (row.risk_category !== 'Normal/Moderate') {
      const eventType = getEventType(row.event_id);
      acc[eventType] = (acc[eventType] || 0) + 1;
    }
    return acc;
  }, {});

  const topThreats = Object.entries(threatCounts)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);

  // Critical events for table
  const criticalEvents = rawData
    .filter(d => d.risk_category === 'Critical')
    .sort((a, b) => b.risk_score - a.risk_score)
    .slice(0, 10)
    .map(event => ({
      id: `${event.timestamp.getTime()}-${event.username}`,
      timestamp: event.timestamp,
      user: event.username,
      host: event.hostname,
      event: getEventType(event.event_id),
      risk_score: event.risk_score,
      severity: event.risk_category,
      description: event.event_description?.substring(0, 80) + '...' || 'Security event detected'
    }));

  return {
    metrics: {
      criticalAlerts,
      anomalyRate: parseFloat(anomalyRate),
      activeThreats: uniqueUsers,
      systemsAtRisk: uniqueHosts
    },
    timelineData,
    riskDistribution,
    topThreats,
    criticalEvents,
    totalEvents: totalAlerts
  };
};

const createTimelineData = (data) => {
  const last7Days = Array.from({ length: 7 }, (_, i) => {
    const date = subDays(new Date(), 6 - i);
    return {
      date: format(date, 'MMM dd'),
      timestamp: date,
      critical: 0,
      high: 0,
      medium: 0,
      anomalies: 0
    };
  });

  data.forEach(row => {
    const dayIndex = last7Days.findIndex(day => 
      startOfDay(row.timestamp) <= day.timestamp && 
      day.timestamp <= endOfDay(row.timestamp)
    );
    
    if (dayIndex >= 0) {
      const day = last7Days[dayIndex];
      if (row.risk_category === 'Critical') day.critical++;
      else if (row.risk_category === 'High Risk') day.high++;
      else if (row.risk_category === 'Normal/Moderate') day.medium++;
      
      if (row.risk_category !== 'Normal/Moderate') day.anomalies++;
    }
  });

  return last7Days;
};

const getEventType = (eventId) => {
  const eventTypes = {
    4624: 'Successful Logon',
    4625: 'Failed Logon',
    4634: 'Account Logoff',
    4672: 'Special Privileges',
    4688: 'Process Creation',
    4689: 'Process Termination',
    4648: 'Explicit Logon',
    4768: 'Kerberos Auth',
    4769: 'Service Ticket',
    4776: 'Credential Validation'
  };
  return eventTypes[eventId] || `Event ${eventId}`;
};

const generateMockData = () => {
  console.log('Using mock data for dashboard');
  
  const mockTimelineData = [
    { date: 'Aug 27', critical: 45, high: 23, medium: 12, anomalies: 80 },
    { date: 'Aug 28', critical: 52, high: 31, medium: 18, anomalies: 101 },
    { date: 'Aug 29', critical: 38, high: 19, medium: 25, anomalies: 82 },
    { date: 'Aug 30', critical: 67, high: 45, medium: 33, anomalies: 145 },
    { date: 'Aug 31', critical: 72, high: 51, medium: 28, anomalies: 151 },
    { date: 'Sep 01', critical: 89, high: 62, medium: 35, anomalies: 186 },
    { date: 'Sep 02', critical: 79, high: 48, medium: 31, anomalies: 158 }
  ];

  return {
    metrics: {
      criticalAlerts: 442,
      anomalyRate: 30.9,
      activeThreats: 153,
      systemsAtRisk: 7
    },
    timelineData: mockTimelineData,
    riskDistribution: [
      { name: 'Critical', value: 442, color: '#ef4444' },
      { name: 'High', value: 284, color: '#fb923c' },
      { name: 'Medium', value: 156, color: '#fbbf24' },
      { name: 'Low', value: 89, color: '#22c55e' }
    ],
    topThreats: [
      { name: 'Successful Logon', count: 145 },
      { name: 'Special Privileges', count: 98 },
      { name: 'Process Creation', count: 76 },
      { name: 'Failed Logon', count: 54 },
      { name: 'Account Logoff', count: 43 },
      { name: 'Credential Validation', count: 26 }
    ],
    criticalEvents: [
      {
        id: '1',
        timestamp: new Date('2025-09-02T15:30:17Z'),
        user: 'ANONYMOUS LOGON',
        host: 'STBVADC04',
        event: 'Successful Logon',
        risk_score: 75.86,
        severity: 'Critical',
        description: 'CRITICAL anomaly detected - Suspicious logon pattern from external IP'
      },
      {
        id: '2',
        timestamp: new Date('2025-09-02T14:45:21Z'),
        user: 'STBVADC01$',
        host: 'STBVADC01',
        event: 'Special Privileges',
        risk_score: 50.65,
        severity: 'Critical',
        description: 'Special privileges assigned - Potential privilege escalation detected'
      },
      {
        id: '3',
        timestamp: new Date('2025-09-02T13:19:04Z'),
        user: 'admin_user',
        host: 'STBVADC02',
        event: 'Process Creation',
        risk_score: 48.30,
        severity: 'Critical',
        description: 'Suspicious process execution - Unknown binary launched'
      }
    ],
    totalEvents: 1428
  };
};