#!/bin/bash

echo "Running tests with coverage..."

# Run tests with coverage
dotnet test \
  /p:CollectCoverage=true \
  /p:CoverletOutputFormat=cobertura \
  /p:CoverletOutput=./TestResults/ \
  /p:Exclude="[*.Tests]*" \
  --settings coverage.runsettings

if [ $? -ne 0 ]; then
    echo "Tests failed!"
    exit 1
fi

echo ""
echo "Generating coverage report..."

# Generate HTML report
reportgenerator \
  -reports:"./TestResults/coverage.cobertura.xml" \
  -targetdir:"./TestResults/html" \
  -reporttypes:"Html;HtmlSummary" \
  -classfilters:"-System.*;-Microsoft.*"

# Open report in browser
xdg-open ./TestResults/html/index.html 2>/dev/null || \
  open ./TestResults/html/index.html 2>/dev/null || \
  start ./TestResults/html/index.html 2>/dev/null || \
  echo "Coverage report generated at: ./TestResults/html/index.html"

echo ""
echo "Coverage Summary:"
