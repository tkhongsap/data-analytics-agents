#!/bin/bash

echo "🔒 Cybersecurity SOC Dashboard Deployment Script"
echo "================================================"

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js first."
    exit 1
fi

# Check if npm is installed
if ! command -v npm &> /dev/null; then
    echo "❌ npm is not installed. Please install npm first."
    exit 1
fi

echo "✅ Node.js version: $(node --version)"
echo "✅ npm version: $(npm --version)"

# Install dependencies
echo ""
echo "📦 Installing dependencies..."
npm install

if [ $? -ne 0 ]; then
    echo "❌ Failed to install dependencies"
    exit 1
fi

# Build the application
echo ""
echo "🏗️  Building production application..."
npm run build

if [ $? -ne 0 ]; then
    echo "❌ Failed to build application"
    exit 1
fi

echo ""
echo "✅ Dashboard built successfully!"
echo ""
echo "🚀 To run the dashboard:"
echo "   Development: npm run dev"
echo "   Production preview: npm run preview"
echo ""
echo "🌐 Access the dashboard at: http://localhost:3000"
echo ""
echo "🔧 For production deployment:"
echo "   - Copy the 'dist' folder to your web server"
echo "   - Ensure enhanced_data.csv is accessible"
echo "   - Configure proper HTTPS and security headers"