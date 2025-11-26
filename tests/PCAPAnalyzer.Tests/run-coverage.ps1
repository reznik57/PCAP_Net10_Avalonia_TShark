#!/usr/bin/env pwsh

Write-Host "Running tests with coverage..." -ForegroundColor Cyan

# Run tests with coverage
dotnet test `
  /p:CollectCoverage=true `
  /p:CoverletOutputFormat=cobertura `
  /p:CoverletOutput=./TestResults/ `
  /p:Exclude="[*.Tests]*" `
  --settings coverage.runsettings

if ($LASTEXITCODE -ne 0) {
    Write-Host "Tests failed!" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "Generating coverage report..." -ForegroundColor Cyan

# Generate HTML report
reportgenerator `
  -reports:"./TestResults/coverage.cobertura.xml" `
  -targetdir:"./TestResults/html" `
  -reporttypes:"Html;HtmlSummary" `
  -classfilters:"-System.*;-Microsoft.*"

# Open report
Start-Process "./TestResults/html/index.html"

Write-Host ""
Write-Host "Coverage report generated at: ./TestResults/html/index.html" -ForegroundColor Green
