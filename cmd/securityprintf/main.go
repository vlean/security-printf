package main

import (
	"golang.org/x/tools/go/analysis/singlechecker"

	"github.com/vlean/security-printf/pkg/analyzer"
)

func main() {
	singlechecker.Main(analyzer.Analyzer)
}
