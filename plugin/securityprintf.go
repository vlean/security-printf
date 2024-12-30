package main

import (
	"golang.org/x/tools/go/analysis"

	"github.com/vlean/security-printf/pkg/analyzer"
)

type analyzerPlugin struct{}

func (*analyzerPlugin) GetAnalyzers() []*analysis.Analyzer {
	return []*analysis.Analyzer{
		analyzer.Analyzer,
	}
}

// This must be defined and named 'AnalyzerPlugin'
var AnalyzerPlugin analyzerPlugin //nolint
