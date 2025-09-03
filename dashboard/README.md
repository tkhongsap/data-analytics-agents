# Cybersecurity SOC Dashboard

A stunning, production-ready React dashboard for visualizing Windows security event data with real-time monitoring capabilities.

## Features

- **Dark Glassmorphism Design**: Modern cybersecurity-focused UI with neon glow effects
- **Real-time Metrics**: Live updating counters and status indicators
- **Interactive Charts**: Timeline analysis, risk distribution, and threat visualization
- **Critical Events Table**: Real-time security event monitoring
- **Threat Intelligence**: AI-powered threat analysis and recommendations
- **Responsive Layout**: Optimized for SOC displays and various screen sizes

## Key Metrics Displayed

- Critical Alerts: Real-time count of critical security events
- Anomaly Rate: Percentage of anomalous events detected
- Active Threats: Number of users with active security threats
- Systems at Risk: Number of hosts with detected security issues

## Technology Stack

- **React 18**: Modern React with hooks and functional components
- **Vite**: Fast build tool and development server
- **Recharts**: Beautiful, responsive charts for data visualization
- **Framer Motion**: Smooth animations and transitions
- **Tailwind CSS**: Utility-first CSS framework with custom cybersecurity theme
- **Lucide React**: Modern icon library
- **Papa Parse**: CSV data parsing
- **Date-fns**: Date manipulation utilities

## Installation

1. Navigate to the dashboard directory:
   ```bash
   cd dashboard
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the development server:
   ```bash
   npm run dev
   ```

4. Open your browser and navigate to `http://localhost:3000`

## Build for Production

1. Build the application:
   ```bash
   npm run build
   ```

2. Preview the production build:
   ```bash
   npm run preview
   ```

## Data Source

The dashboard reads from `enhanced_data.csv` which should contain the following columns:
- `timestamp`: Event timestamp in ISO format
- `username`: Username associated with the event
- `hostname`: Host where the event occurred
- `event_id`: Windows event ID
- `event_description`: Description of the security event
- `risk_category`: Risk level (Critical, High, Medium, Low, Normal)
- `max_abs_z`: Risk score for the event

## Color Scheme

- **Critical**: Red (#ef4444) with glow effects
- **High**: Orange (#fb923c) with glow effects  
- **Medium**: Yellow (#fbbf24)
- **Low/Normal**: Green (#22c55e) with glow effects
- **Background**: Dark slate with gradient overlay

## Dashboard Sections

1. **Header**: Real-time clock, connection status, and branding
2. **Metrics Cards**: Key performance indicators with animated counters
3. **Timeline Chart**: Multi-line chart showing security events over time
4. **Risk Distribution**: Pie chart of risk levels
5. **Top Threats**: Horizontal bar chart of most common threat types
6. **Threat Intelligence**: AI-generated threat analysis panel
7. **Critical Events Table**: Real-time table of critical security events

## Customization

The dashboard is highly customizable:

- Modify colors in `tailwind.config.js`
- Update metrics calculations in `src/utils/dataLoader.js`
- Add new chart components in `src/components/`
- Customize animations in individual components

## Performance

- Optimized for 24/7 SOC display usage
- Efficient data loading and processing
- Smooth 60fps animations
- Memory-efficient chart rendering

## Browser Support

- Chrome/Chromium (recommended for SOC displays)
- Firefox
- Safari
- Edge

## License

This dashboard is designed for cybersecurity operations and monitoring purposes.