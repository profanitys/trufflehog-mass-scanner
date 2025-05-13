package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	// "log" // Replaced by slog
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"log/slog" // Using slog

	_ "github.com/mattn/go-sqlite3"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine"
	"github.com/trufflesecurity/trufflehog/v3/pkg/output"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const (
	scannerUserAgent = "TruffleHog-MassScanner/v0.3.0" // Updated User-Agent
	githubAPIBaseURLDefault = "https://api.github.com"
	githubAPIPerPage = 100
	huggingFaceAPIBaseURLDefault = "https://huggingface.co/api"
	huggingFaceAPILimit = 100
)


// Configuration options (via command-line flags)
var (
	maxConcurrency      int
	resultsDir          string
	dbPath              string
	scanTimeoutMinutes  int
	// scanGitHistory bool // Now part of TruffleHog config logic
	// maxDepth int // Now part of TruffleHog config logic
	scanHFSpaces        bool
	scanHFModels        bool
	scanGitHub          bool
	dbRetryAttempts     int
	dbRetryDelay        time.Duration
	rateLimitBuffer     int
	initialSleep        int
	backoffFactor       float64
	maxSleep            int
	slogLevel           string // Renamed from logLevel to avoid conflict with slog package
	githubTokenEnv      string
	huggingFaceTokenEnv string

	// Metrics settings
	metricsInterval time.Duration
	metricsFile     string

	// TruffleHog configuration
	trufflehogConfigPath   string // For loading config from a file
	thScanGitHistory       bool   // Specific flag for history, helps determine MaxDepth if no config file
	thMaxDepth             int    // Specific flag for depth

	// TruffleHog engine configuration flags (used if no config file)
	detectorsToRun      string
	detectorsToSkip     string
	includePathsFile    string
	excludePathsFile    string
	verifySecretsFlag   bool
	onlyVerified        bool
	// skipUnverifiedFlag bool // Deprecated in TruffleHog, OnlyVerified is preferred.
	entropyPrecision    float64
	entropyThreshold    float64
	logDetectors        bool
	jsonDebugFlag       bool
	printAvgEntropyFlag bool
	noUpdateCheck       bool // Renamed from noUpdate to avoid conflict
	concurrentDetectors int
)

// Global TruffleHog config (loaded from file or built from flags)
var effectiveTrufflehogConfig config.Config

// Repository represents a repository to scan
type Repository struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	FullName    string `json:"full_name"`
	URL         string `json:"html_url"`
	Description string `json:"description"`
	Platform    string
}

// ScanResult tracks scan results
type ScanResult struct {
	RepoID      string
	Platform    string
	URL         string
	ScanTime    time.Time
	Status      string
	FindingsNum int
	Error       string
}

// RateLimit for GitHub API
type RateLimit struct {
	Resources struct {
		Core struct {
			Limit     int   `json:"limit"`
			Remaining int   `json:"remaining"`
			Reset     int64 `json:"reset"`
		} `json:"core"`
	} `json:"resources"`
}

// Metrics tracks statistics about the scanning process
type Metrics struct {
	RepositoriesDiscovered int64
	GithubReposDiscovered  int64
	HFModelsDiscovered     int64
	HFSpacesDiscovered     int64
	ScansStarted           int64
	ScansCompleted         int64
	ScansFailed            int64
	ScansTimedOut          int64
	TotalSecretsFound      int64
	RateLimitHits          int64
	TotalRateLimitWaitsSec int64 // Renamed for clarity
	TotalScanTimeNs        int64 // Renamed for clarity
	AvgScanTimeNs          int64
	scanTimes              []time.Duration
	scanTimesMutex         sync.Mutex
}

var globalMetrics = &Metrics{} // Global metrics instance

func (m *Metrics) RecordScanTime(duration time.Duration) {
	atomic.AddInt64(&m.TotalScanTimeNs, duration.Nanoseconds())
	m.scanTimesMutex.Lock()
	m.scanTimes = append(m.scanTimes, duration)
	count := len(m.scanTimes)
	m.scanTimesMutex.Unlock()

	if count > 0 {
		currentTotalNs := atomic.LoadInt64(&m.TotalScanTimeNs)
		atomic.StoreInt64(&m.AvgScanTimeNs, currentTotalNs/int64(count))
	}
}

func (m *Metrics) RecordRepositoryDiscovered(platform string) {
	atomic.AddInt64(&m.RepositoriesDiscovered, 1)
	switch platform {
	case "github":
		atomic.AddInt64(&m.GithubReposDiscovered, 1)
	case "huggingface-model":
		atomic.AddInt64(&m.HFModelsDiscovered, 1)
	case "huggingface-space":
		atomic.AddInt64(&m.HFSpacesDiscovered, 1)
	}
}

func (m *Metrics) RecordScanStarted() {
	atomic.AddInt64(&m.ScansStarted, 1)
}

func (m *Metrics) RecordScanResult(status string, secretsFound int) {
	// Standardize status for metrics; scanRepository should use these
	switch strings.ToLower(status) {
	case "completed":
		atomic.AddInt64(&m.ScansCompleted, 1)
	case "timeout", "cancelled", "timeout_or_cancelled": // Group timeout and cancelled
		atomic.AddInt64(&m.ScansTimedOut, 1)
	default: // "error", "error_creating_output_file", "error_creating_scan_source", "error_starting_scan", etc.
		atomic.AddInt64(&m.ScansFailed, 1)
	}
	atomic.AddInt64(&m.TotalSecretsFound, int64(secretsFound))
}

func (m *Metrics) RecordRateLimit(waitTime time.Duration) {
	atomic.AddInt64(&m.RateLimitHits, 1)
	atomic.AddInt64(&m.TotalRateLimitWaitsSec, int64(waitTime.Seconds()))
}

func (m *Metrics) GenerateReport() string {
	report := struct {
		Timestamp    string `json:"timestamp"`
		Repositories struct {
			Total   int64 `json:"total"`
			GitHub  int64 `json:"github"`
			HFModel int64 `json:"hf_model"`
			HFSpace int64 `json:"hf_space"`
		} `json:"repositories"`
		Scans struct {
			Started        int64 `json:"started"`
			Completed      int64 `json:"completed"`
			Failed         int64 `json:"failed"`
			TimedOut       int64 `json:"timed_out_or_cancelled"`
			InProgress     int64 `json:"in_progress"` // Calculated
		} `json:"scans"`
		Results struct {
			TotalSecrets int64   `json:"total_secrets"`
			AvgPerScan   float64 `json:"avg_secrets_per_completed_scan"`
		} `json:"results"`
		Performance struct {
			AvgScanTimeS     float64 `json:"avg_scan_time_s"`
			TotalRateLimits  int64   `json:"total_rate_limit_hits"`
			RateLimitWaitSec int64   `json:"total_rate_limit_wait_s"`
		} `json:"performance"`
	}{}

	report.Timestamp = time.Now().Format(time.RFC3339)
	report.Repositories.Total = atomic.LoadInt64(&m.RepositoriesDiscovered)
	report.Repositories.GitHub = atomic.LoadInt64(&m.GithubReposDiscovered)
	report.Repositories.HFModel = atomic.LoadInt64(&m.HFModelsDiscovered)
	report.Repositories.HFSpace = atomic.LoadInt64(&m.HFSpacesDiscovered)

	scansStarted := atomic.LoadInt64(&m.ScansStarted)
	scansCompleted := atomic.LoadInt64(&m.ScansCompleted)
	scansFailed := atomic.LoadInt64(&m.ScansFailed)
	scansTimedOut := atomic.LoadInt64(&m.ScansTimedOut)

	report.Scans.Started = scansStarted
	report.Scans.Completed = scansCompleted
	report.Scans.Failed = scansFailed
	report.Scans.TimedOut = scansTimedOut
	report.Scans.InProgress = scansStarted - (scansCompleted + scansFailed + scansTimedOut)


	report.Results.TotalSecrets = atomic.LoadInt64(&m.TotalSecretsFound)
	if scansCompleted > 0 {
		report.Results.AvgPerScan = float64(atomic.LoadInt64(&m.TotalSecretsFound)) / float64(scansCompleted)
	}

	avgTimeNs := atomic.LoadInt64(&m.AvgScanTimeNs)
	report.Performance.AvgScanTimeS = time.Duration(avgTimeNs).Seconds()
	report.Performance.TotalRateLimits = atomic.LoadInt64(&m.RateLimitHits)
	report.Performance.RateLimitWaitSec = atomic.LoadInt64(&m.TotalRateLimitWaitsSec)

	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		slog.Error("Error generating metrics report JSON", "error", err)
		return `{"error": "failed to generate metrics report"}`
	}
	return string(jsonData)
}

func initMetricsReporting(ctx context.Context, reportInterval time.Duration, reportPath string) {
	if reportInterval <= 0 {
		slog.Info("Metrics reporting disabled (interval is zero or negative).")
		return
	}
	slog.Info("Metrics reporting initialized", "interval", reportInterval.String())
	if reportPath != "" {
		slog.Info("Metrics will be written to file", "path", reportPath)
	}

	go func() {
		ticker := time.NewTicker(reportInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				report := globalMetrics.GenerateReport()
				slog.Info("Periodic Metrics Report", "report", json.RawMessage(report)) // Log as JSON for structured output

				if reportPath != "" {
					err := os.WriteFile(reportPath, []byte(report), 0644)
					if err != nil {
						slog.Error("Error writing periodic metrics report to file", "path", reportPath, "error", err)
					}
				}
			case <-ctx.Done():
				report := globalMetrics.GenerateReport()
				slog.Info("Final Metrics Report", "report", json.RawMessage(report))
				if reportPath != "" {
					finalPath := reportPath + ".final" // Use .final suffix
					err := os.WriteFile(finalPath, []byte(report), 0644)
					if err != nil {
						slog.Error("Error writing final metrics report to file", "path", finalPath, "error", err)
					} else {
						slog.Info("Final metrics report written", "path", finalPath)
					}
				}
				return
			}
		}
	}()
}

func createHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second, // General purpose timeout
		Transport: &http.Transport{
			MaxIdleConns:        maxConcurrency + 10, // Should be at least maxConcurrency for discovery + rate checks
			MaxIdleConnsPerHost: maxConcurrency + 10, //
			IdleConnTimeout:     90 * time.Second,
			ForceAttemptHTTP2:   true,
		},
	}
}

func init() {
	flag.IntVar(&maxConcurrency, "concurrency", 5, "Number of concurrent scans")
	flag.StringVar(&resultsDir, "results-dir", "results", "Directory to store scan results")
	flag.StringVar(&dbPath, "db-path", "scans.db", "Path to SQLite database file")
	flag.IntVar(&scanTimeoutMinutes, "timeout", 15, "Timeout in minutes for each repository scan")

	flag.BoolVar(&scanHFSpaces, "scan-spaces", true, "Scan Hugging Face Spaces")
	flag.BoolVar(&scanHFModels, "scan-models", true, "Scan Hugging Face Models")
	flag.BoolVar(&scanGitHub, "scan-github", true, "Scan GitHub repositories")

	flag.IntVar(&dbRetryAttempts, "db-retry", 3, "Number of database operation retry attempts")
	flag.DurationVar(&dbRetryDelay, "db-retry-delay", 1*time.Second, "Delay between database retry attempts")
	flag.IntVar(&rateLimitBuffer, "rate-limit-buffer", 20, "Buffer for API rate limits (for proactive checks)") // Increased buffer
	flag.IntVar(&initialSleep, "initial-sleep", 1000, "Initial sleep time in ms between API requests in discovery") // Increased default
	flag.Float64Var(&backoffFactor, "backoff-factor", 1.5, "Exponential backoff factor for API request retries")
	flag.IntVar(&maxSleep, "max-sleep", 10000, "Maximum sleep time in ms between API requests") // Increased default

	flag.StringVar(&slogLevel, "slog-level", "info", "Log level (debug, info, warn, error)") // Renamed
	flag.StringVar(&githubTokenEnv, "github-token-env", "GITHUB_TOKEN", "Environment variable name for GitHub token")
	flag.StringVar(&huggingFaceTokenEnv, "hf-token-env", "HUGGINGFACE_TOKEN", "Environment variable name for Hugging Face token")

	flag.DurationVar(&metricsInterval, "metrics-interval", 1*time.Minute, "Interval for metrics reporting (0 to disable)") // Shorter default, 0 to disable
	flag.StringVar(&metricsFile, "metrics-file", "", "Path to write metrics JSON reports to (e.g., metrics.json)")

	// TruffleHog configuration: file takes precedence, then these flags.
	flag.StringVar(&trufflehogConfigPath, "trufflehog-config", "", "Path to a JSON TruffleHog configuration file (takes precedence over individual --th-* flags)")
	flag.BoolVar(&thScanGitHistory, "th-scan-history", true, "Scan full git history (used if no config file or config file doesn't set MaxDepth)")
	flag.IntVar(&thMaxDepth, "th-max-depth", 0, "Max depth for git history scanning (0 = unlimited; used if no config file or config file doesn't set MaxDepth)")

	// Individual TruffleHog engine flags (used if --trufflehog-config is NOT provided)
	flag.StringVar(&detectorsToRun, "th-detectors", "", "Comma-separated list of detectors to run (empty = all)")
	flag.StringVar(&detectorsToSkip, "th-skip-detectors", "", "Comma-separated list of detectors to skip")
	flag.StringVar(&includePathsFile, "th-include-paths-file", "", "File with newline-separated regexes for paths to include")
	flag.StringVar(&excludePathsFile, "th-exclude-paths-file", "", "File with newline-separated regexes for paths to exclude")
	flag.BoolVar(&verifySecretsFlag, "th-verify", true, "Verify secrets by making a request with them")
	flag.BoolVar(&onlyVerified, "th-only-verified", false, "Only output verified secrets")
	// SkipUnverified is deprecated by TruffleHog; OnlyVerified is preferred.
	flag.Float64Var(&entropyPrecision, "th-entropy-precision", 0.01, "Entropy precision for detectors") // TruffleHog default is 0.01
	flag.Float64Var(&entropyThreshold, "th-entropy-threshold", 0.0, "Minimum entropy threshold (0.0 means use detector defaults)") // TH Default is often 0.0 allowing detector specific.
	flag.BoolVar(&logDetectors, "th-log-detectors", false, "Log when detector is activated")
	flag.BoolVar(&jsonDebugFlag, "th-json-debug", false, "Log detector JSON errors for debugging")
	flag.BoolVar(&printAvgEntropyFlag, "th-print-avg-entropy", false, "Print average entropy score")
	flag.BoolVar(&noUpdateCheck, "th-no-updates", true, "Skip checking for TruffleHog updates (recommended for automation)")
	flag.IntVar(&concurrentDetectors, "th-concurrent-detectors", 0, "Number of concurrent detectors (0 = TruffleHog auto)")

	flag.Parse()
}

func buildTruffleHogConfigFromFlags() (config.Config, error) {
	cfg := config.DefaultConfig // Start with TruffleHog's own defaults
	
	// Apply flags that have been explicitly set or have different defaults than TruffleHog's
	cfg.Verify = verifySecretsFlag
	cfg.OnlyVerified = onlyVerified
	// cfg.SkipUnverified // Deprecated, not setting directly unless needed
	cfg.EntropyPrecision = entropyPrecision
	cfg.EntropyThreshold = entropyThreshold
	cfg.LogDetectors = logDetectors
	cfg.JsonDebug = jsonDebugFlag
	cfg.PrintAvgEntropy = printAvgEntropyFlag
	cfg.NoUpdates = noUpdateCheck // Use the th-no-updates flag's value
	cfg.ConcurrentDetectors = concurrentDetectors

	if !thScanGitHistory { // If history scanning is off, effectively depth 1
		cfg.MaxDepth = 1
	} else {
		cfg.MaxDepth = thMaxDepth // Use the flag's value (0 for unlimited)
	}


	if detectorsToRun != "" {
		cfg.DetectorsToRun = []string{} // Clear default if any
		for _, d := range strings.Split(detectorsToRun, ",") {
			cfg.DetectorsToRun = append(cfg.DetectorsToRun, strings.TrimSpace(d))
		}
	}
	if detectorsToSkip != "" {
		for _, d := range strings.Split(detectorsToSkip, ",") {
			cfg.DetectorsToSkip = append(cfg.DetectorsToSkip, strings.TrimSpace(d))
		}
	}

	if includePathsFile != "" {
		paths, err := loadPathsFromFile(includePathsFile)
		if err != nil {
			return cfg, fmt.Errorf("error loading include paths from '%s': %w", includePathsFile, err)
		}
		cfg.IncludePaths = paths
	}
	if excludePathsFile != "" {
		paths, err := loadPathsFromFile(excludePathsFile)
		if err != nil {
			return cfg, fmt.Errorf("error loading exclude paths from '%s': %w", excludePathsFile, err)
		}
		cfg.ExcludePaths = paths
	}
	return cfg, nil
}

func loadPathsFromFile(filePath string) ([]string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") { // Skip empty lines and comments
			paths = append(paths, line)
		}
	}
	return paths, nil
}

func main() {
	// Setup structured logging
	var programLevel = new(slog.LevelVar)
	programLevel.Set(slog.LevelInfo) // Default
	logHandlerOpts := slog.HandlerOptions{Level: programLevel}
	if strings.ToLower(slogLevel) == "debug" { // Add source only for debug for cleaner logs otherwise
		logHandlerOpts.AddSource = true
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &logHandlerOpts)))

	switch strings.ToLower(slogLevel) {
	case "debug":
		programLevel.Set(slog.LevelDebug)
	case "info":
		programLevel.Set(slog.LevelInfo)
	case "warn":
		programLevel.Set(slog.LevelWarn)
	case "error":
		programLevel.Set(slog.LevelError)
	default:
		slog.Warn("Invalid slog-level provided, defaulting to info", "provided", slogLevel)
		programLevel.Set(slog.LevelInfo) // Default to Info
	}

	// Determine effective TruffleHog config
	if trufflehogConfigPath != "" {
		slog.Info("Attempting to load TruffleHog configuration from file", "path", trufflehogConfigPath)
		data, err := ioutil.ReadFile(trufflehogConfigPath)
		if err != nil {
			slog.Error("Failed to read TruffleHog config file. Individual --th-* flags will be used if set, or TruffleHog defaults.", "path", trufflehogConfigPath, "error", err)
			// Build from flags as fallback
			cfg, buildErr := buildTruffleHogConfigFromFlags()
			if buildErr != nil {
				slog.Error("Failed to build TruffleHog config from flags after file read error. Using TruffleHog internal defaults.", "error", buildErr)
				effectiveTrufflehogConfig = config.DefaultConfig // Absolute fallback
			} else {
				effectiveTrufflehogConfig = cfg
			}
		} else {
			if err := json.Unmarshal(data, &effectiveTrufflehogConfig); err != nil {
				slog.Error("Failed to parse TruffleHog config file. Individual --th-* flags will be used if set, or TruffleHog defaults.", "path", trufflehogConfigPath, "error", err)
				// Build from flags as fallback
				cfg, buildErr := buildTruffleHogConfigFromFlags()
				if buildErr != nil {
					slog.Error("Failed to build TruffleHog config from flags after file parse error. Using TruffleHog internal defaults.", "error", buildErr)
					effectiveTrufflehogConfig = config.DefaultConfig // Absolute fallback
				} else {
					effectiveTrufflehogConfig = cfg
				}
			} else {
				slog.Info("Successfully loaded TruffleHog configuration from file. This will override individual --th-* flags.")
			}
		}
	} else {
		slog.Info("No TruffleHog configuration file provided. Building config from --th-* flags or TruffleHog defaults.")
		cfg, buildErr := buildTruffleHogConfigFromFlags()
		if buildErr != nil {
			slog.Error("Failed to build TruffleHog config from flags. Using TruffleHog internal defaults.", "error", buildErr)
			effectiveTrufflehogConfig = config.DefaultConfig // Absolute fallback
		} else {
			effectiveTrufflehogConfig = cfg
		}
	}
	// Ensure NoUpdates is true for CLI tool if not explicitly false in config
	if effectiveTrufflehogConfig.NoUpdates == nil || *effectiveTrufflehogConfig.NoUpdates { // TruffleHog uses *bool for NoUpdates
		trueVal := true
		effectiveTrufflehogConfig.NoUpdates = &trueVal
	}

	slog.Info("Effective TruffleHog Configuration",
		"MaxDepth", effectiveTrufflehogConfig.MaxDepth,
		"Verify", effectiveTrufflehogConfig.Verify,
		"OnlyVerified", effectiveTrufflehogConfig.OnlyVerified,
		"NoUpdates", *effectiveTrufflehogConfig.NoUpdates, // Dereference pointer
		"DetectorsToRunCount", len(effectiveTrufflehogConfig.DetectorsToRun),
		"DetectorsToSkipCount", len(effectiveTrufflehogConfig.DetectorsToSkip),
	)


	slog.Info("Starting TruffleHog Mass Scanner", "concurrency", maxConcurrency)

	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		slog.Error("Failed to create results directory", "path", resultsDir, "error", err)
		os.Exit(1)
	}

	db, err := setupDatabase()
	if err != nil {
		slog.Error("Failed to set up database", "path", dbPath, "error", err)
		os.Exit(1)
	}
	defer db.Close()

	httpClient := createHTTPClient() // Create shared HTTP client

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	initMetricsReporting(ctx, metricsInterval, metricsFile)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		slog.Info("Received signal, shutting down gracefully...", "signal", sig.String())
		cancel()
	}()

	var wg sync.WaitGroup
	repoChan := make(chan Repository, maxConcurrency*2)

	for i := 0; i < maxConcurrency; i++ {
		wg.Add(1)
		workerID := i + 1
		go worker(ctx, &wg, repoChan, db, workerID) // Pass effectiveTrufflehogConfig implicitly (it's global)
	}

	var discoveryWg sync.WaitGroup
	if scanGitHub {
		discoveryWg.Add(1)
		go func() {
			defer discoveryWg.Done()
			discoverGithubRepositories(ctx, repoChan, db, httpClient) // Pass client
		}()
	}
	if scanHFModels {
		discoveryWg.Add(1)
		go func() {
			defer discoveryWg.Done()
			discoverHuggingFaceRepositories(ctx, repoChan, db, httpClient) // Pass client
		}()
	}
	if scanHFSpaces {
		discoveryWg.Add(1)
		go func() {
			defer discoveryWg.Done()
			discoverHuggingFaceSpaces(ctx, repoChan, db, httpClient) // Pass client
		}()
	}

	go func() {
		discoveryWg.Wait()
		slog.Info("All discovery processes completed, closing repo channel.")
		close(repoChan)
	}()

	wg.Wait()
	slog.Info("All scanning completed!")
	// Final metrics report will be generated by initMetricsReporting on ctx.Done()
}

func setupDatabase() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	// Disable WAL mode for simplicity, can be enabled for performance with concurrent writers if needed
	// but for this app, writes are likely sequential enough.
	// _, err = db.Exec("PRAGMA journal_mode=WAL;")
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to enable WAL mode: %w", err)
	// }


	createTableSQL := `
	CREATE TABLE IF NOT EXISTS scanned_repos (
		id TEXT,
		platform TEXT NOT NULL,
		url TEXT NOT NULL,
		scan_time TIMESTAMP,
		status TEXT,
		findings_num INTEGER DEFAULT 0,
		error TEXT,
		PRIMARY KEY (platform, id)
	);
	CREATE INDEX IF NOT EXISTS idx_platform_id ON scanned_repos(platform, id);
	`
	var execErr error
	for attempt := 0; attempt < dbRetryAttempts; attempt++ {
		_, execErr = db.Exec(createTableSQL)
		if execErr == nil {
			break
		}
		slog.Warn("Database table creation attempt failed, retrying...",
			"attempt", attempt+1, "max_attempts", dbRetryAttempts, "delay", dbRetryDelay, "error", execErr.Error())
		time.Sleep(dbRetryDelay)
	}
	if execErr != nil {
		return nil, fmt.Errorf("failed to create tables after %d attempts: %w", dbRetryAttempts, execErr)
	}
	slog.Info("Database tables ensured", "path", dbPath)
	return db, nil
}

func isRepoScanned(db *sql.DB, platform string, repoID string) (bool, error) {
	var count int
	var queryErr error
	for attempt := 0; attempt < dbRetryAttempts; attempt++ {
		queryErr = db.QueryRow("SELECT COUNT(*) FROM scanned_repos WHERE platform = ? AND id = ?", platform, repoID).Scan(&count)
		if queryErr == nil {
			break
		}
		slog.Warn("Database query attempt failed, retrying...",
			"attempt", attempt+1, "platform", platform, "repoID", repoID, "error", queryErr.Error())
		time.Sleep(dbRetryDelay)
	}
	if queryErr != nil {
		return false, fmt.Errorf("failed to query repository status for %s/%s after %d attempts: %w", platform, repoID, dbRetryAttempts, queryErr)
	}
	return count > 0, nil
}

func recordScanResult(db *sql.DB, result ScanResult) error {
	var execErr error
	for attempt := 0; attempt < dbRetryAttempts; attempt++ {
		_, execErr = db.Exec(
			"INSERT INTO scanned_repos (id, platform, url, scan_time, status, findings_num, error) VALUES (?, ?, ?, ?, ?, ?, ?)",
			result.RepoID, result.Platform, result.URL, result.ScanTime, result.Status, result.FindingsNum, result.Error,
		)
		if execErr == nil {
			break
		}
		slog.Warn("Database insert attempt failed, retrying...",
			"attempt", attempt+1, "platform", result.Platform, "repoID", result.RepoID, "error", execErr.Error())
		time.Sleep(dbRetryDelay)
	}
	if execErr != nil {
		return fmt.Errorf("failed to record scan result for %s/%s after %d attempts: %w", result.Platform, result.RepoID, dbRetryAttempts, execErr)
	}
	return nil
}

func worker(ctx context.Context, wg *sync.WaitGroup, repoChan <-chan Repository, db *sql.DB, workerID int) {
	defer wg.Done()
	slog.Info("Worker started", "workerID", workerID)

	workerCtx, workerCancel := context.WithCancel(ctx)
	defer workerCancel()

	// Use the globally determined effectiveTrufflehogConfig
	e, err := engine.Start(workerCtx, effectiveTrufflehogConfig)
	if err != nil {
		slog.Error("Worker failed to start TruffleHog engine", "workerID", workerID, "error", err)
		return
	}
	defer func() {
		slog.Info("Worker shutting down engine...", "workerID", workerID)
		e.Shutdown(workerCtx)
		slog.Info("Worker engine shut down.", "workerID", workerID)
	}()
	slog.Debug("Worker engine started successfully", "workerID", workerID)


	activeJobChannels := &sync.Map{}

	go func() {
		engineSecretsChan := e.GetDetectedSecretsChannel()
		for secret := range engineSecretsChan {
			if ch, ok := activeJobChannels.Load(secret.SourceID); ok {
				jobChan := ch.(chan *common.VerifiedSecret)
				select {
				case jobChan <- secret:
				default:
					slog.Warn("Dispatcher failed to send secret to job channel (full or closed)",
						"workerID", workerID, "jobID", secret.SourceID)
				}
			}
		}
		slog.Debug("Worker engine secret dispatcher goroutine finished.", "workerID", workerID)
	}()

	for repo := range repoChan {
		select {
		case <-workerCtx.Done():
			slog.Info("Worker shutting down due to cancellation.", "workerID", workerID)
			return
		default:
			repoLogArgs := []any{"workerID", workerID, "platform", repo.Platform, "repoID", repo.ID, "repoFullName", repo.FullName}
			scanned, err := isRepoScanned(db, repo.Platform, repo.ID)
			if err != nil {
				slog.Error("Error checking if repo is scanned", append(repoLogArgs, "error", err)...)
				continue
			}
			if scanned {
				slog.Debug("Repository already scanned, skipping.", repoLogArgs...)
				continue
			}

			slog.Info("Scanning repository", repoLogArgs...)
			result := scanRepository(workerCtx, e, repo, workerID, activeJobChannels)

			if err := recordScanResult(db, result); err != nil {
				slog.Error("Error recording scan result to DB", append(repoLogArgs, "error", err)...)
			} else {
				slog.Info("Scan result recorded to DB",
					append(repoLogArgs, "findingsNum", result.FindingsNum, "status", result.Status)...)
			}
		}
	}
	slog.Info("Worker completed processing all repositories from channel.", "workerID", workerID)
}

func scanRepository(ctx context.Context, e *engine.Engine, repo Repository, workerID int, activeJobChannels *sync.Map) ScanResult {
	startTime := time.Now()
	globalMetrics.RecordScanStarted() // Record scan started for metrics

	result := ScanResult{
		RepoID:   repo.ID,
		Platform: repo.Platform,
		URL:      repo.URL,
		ScanTime: time.Now(), // This will be close to startTime
		Status:   "initialized",
	}
	repoLogArgs := []any{
		"workerID", workerID, "platform", repo.Platform, "repoID", repo.ID, "repoFullName", repo.FullName,
	}

	scanCtx, cancel := context.WithTimeout(ctx, time.Duration(scanTimeoutMinutes)*time.Minute)
	defer cancel()

	safeID := strings.ReplaceAll(repo.ID, "/", "_")
	safePlatform := strings.ReplaceAll(repo.Platform, "/", "_")
	outputFilename := fmt.Sprintf("%s_%s_findings.json", safePlatform, safeID)
	outputFile := filepath.Join(resultsDir, outputFilename)

	outFile, err := os.Create(outputFile)
	if err != nil {
		result.Status = "error_creating_output_file" // Standardized status
		result.Error = fmt.Sprintf("Failed to create output file %s: %v", outputFile, err)
		slog.Error(result.Error, repoLogArgs...)
		globalMetrics.RecordScanResult(result.Status, 0)
		globalMetrics.RecordScanTime(time.Since(startTime)) // Record time even for early failure
		return result
	}
	defer outFile.Close()

	outputOptions := []output.OutputOption{output.WithFormat("json"), output.WithWriter(outFile)}
	outputter := output.NewOutputter(outputOptions...)
	defer outputter.Close()

	var scanSource sources.Source
	var scanOptions []sources.SourceOption // Corrected type

	// Tokens are now applied via TruffleHog config if possible, or via source options as a fallback.
	// TruffleHog's internal config usually takes precedence.
	// For this version, we'll keep the source options for tokens if needed.
	ghToken := os.Getenv(githubTokenEnv)
	hfToken := os.Getenv(huggingFaceTokenEnv)

	if strings.HasPrefix(repo.Platform, "github") && ghToken != "" {
		scanOptions = append(scanOptions, sources.WithGitHubToken(ghToken))
	} else if strings.HasPrefix(repo.Platform, "huggingface") && hfToken != "" {
		scanOptions = append(scanOptions, sources.WithToken(hfToken))
	}

	// Note: effectiveTrufflehogConfig.MaxDepth is used by the engine.
	// Source options like WithMaxDepth here might be overridden or redundant
	// if MaxDepth is set in the engine's config. For simplicity, not adding it here again.

	var sourceErr error
	metaData := &source_metadatapb.MetaData{ScanType: sourcespb.ScanType_SCAN_TYPE_FULL}
	if repo.Platform == "github" {
		metaData.RepoUrl = repo.URL
		scanSource, sourceErr = sources.NewGitHub(scanCtx, metaData, scanOptions...)
	} else if repo.Platform == "huggingface-model" || repo.Platform == "huggingface-space" {
		metaData.RepoUrl = repo.FullName
		scanSource, sourceErr = sources.NewHuggingFace(scanCtx, metaData, scanOptions...)
	} else {
		sourceErr = fmt.Errorf("unsupported platform: %s", repo.Platform)
	}

	if sourceErr != nil {
		result.Status = "error_creating_scan_source" // Standardized status
		result.Error = fmt.Sprintf("Failed to create scan source: %v", sourceErr)
		slog.Error(result.Error, repoLogArgs...)
		globalMetrics.RecordScanResult(result.Status, 0)
		globalMetrics.RecordScanTime(time.Since(startTime))
		return result
	}

	jobID, err := e.ScanWithSource(scanSource)
	if err != nil {
		result.Status = "error_starting_scan" // Standardized status
		result.Error = fmt.Sprintf("Failed to start scan with engine: %v", err)
		slog.Error(result.Error, repoLogArgs...)
		globalMetrics.RecordScanResult(result.Status, 0)
		globalMetrics.RecordScanTime(time.Since(startTime))
		return result
	}
	jobLogArgs := append(repoLogArgs, "jobID", jobID)
	slog.Info("Scan job started", jobLogArgs...)


	jobCompletedChan := e.JobCompletedChannel(jobID)
	var localFoundSecrets int32

	jobSecretsChan := make(chan *common.VerifiedSecret, 128)
	activeJobChannels.Store(jobID, jobSecretsChan)

	var jobSecretsProcessingWg sync.WaitGroup
	jobSecretsProcessingWg.Add(1)
	go func() {
		defer jobSecretsProcessingWg.Done()
		for secret := range jobSecretsChan {
			if err := outputter.Send(secret); err != nil {
				slog.Error("Error sending secret to outputter", append(jobLogArgs, "error", err)...)
			}
			atomic.AddInt32(&localFoundSecrets, 1)
			count := atomic.LoadInt32(&localFoundSecrets)
			if count > 0 && count%20 == 0 {
				slog.Debug("Processed secrets for job", append(jobLogArgs, "secrets_processed", count)...)
			}
		}
		slog.Debug("Secrets processor goroutine finished", jobLogArgs...)
	}()

	select {
	case <-jobCompletedChan:
		slog.Debug("Job completed successfully by engine", jobLogArgs...)
		result.Status = "completed"
	case <-scanCtx.Done():
		err := scanCtx.Err()
		if err == context.DeadlineExceeded {
			result.Status = "timeout"
			result.Error = "Scan timeout exceeded"
		} else if err == context.Canceled {
			result.Status = "cancelled"
			result.Error = "Scan cancelled"
		} else {
			result.Status = "error_scan_context_done" // More specific error status
			result.Error = fmt.Sprintf("Scan context unexpectedly done: %v", err)
		}
		slog.Warn("Scan job did not complete as expected", append(jobLogArgs, "status", result.Status, "error", result.Error)...)
	}

	activeJobChannels.Delete(jobID)
	close(jobSecretsChan)
	jobSecretsProcessingWg.Wait()

	result.FindingsNum = int(atomic.LoadInt32(&localFoundSecrets))
	finalLogArgs := append(jobLogArgs, "status", result.Status, "findingsNum", result.FindingsNum)
	if result.Error != "" {
		finalLogArgs = append(finalLogArgs, "error", result.Error)
	}
	slog.Info("Scan job finished", finalLogArgs...)

	globalMetrics.RecordScanResult(result.Status, result.FindingsNum)
	globalMetrics.RecordScanTime(time.Since(startTime))

	return result
}

func discoverGithubRepositories(ctx context.Context, repoChan chan<- Repository, db *sql.DB, httpClient *http.Client) {
	slog.Info("Starting GitHub repository discovery...")
	sinceID := 1
	currentSleepDurationMs := float64(initialSleep)
	// discoveredCount := 0 // Using globalMetrics.GithubReposDiscovered
	ghToken := os.Getenv(githubTokenEnv)

	for {
		select {
		case <-ctx.Done():
			slog.Info("GitHub repository discovery cancelled.")
			return
		default:
			shouldProceed, sleepDur := checkGitHubRateLimit(ctx, httpClient, githubAPIBaseURLDefault, ghToken, rateLimitBuffer)
			if !shouldProceed {
				slog.Info("GitHub proactive rate limit: Pausing discovery", "duration", sleepDur.String())
				globalMetrics.RecordRateLimit(sleepDur)
				select {
				case <-time.After(sleepDur):
				case <-ctx.Done():
					slog.Info("GitHub discovery shutting down during proactive rate limit sleep.")
					return
				}
				continue
			}

			url := fmt.Sprintf("%s/repositories?since=%d&per_page=%d", githubAPIBaseURLDefault, sinceID, githubAPIPerPage)
			req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				slog.Error("GitHub discovery: Error creating API request, retrying after backoff.", "url", url, "error", err, "backoff_ms", currentSleepDurationMs)
				select {case <-time.After(time.Duration(currentSleepDurationMs) * time.Millisecond): case <-ctx.Done(): return}
				currentSleepDurationMs = min(currentSleepDurationMs*backoffFactor, float64(maxSleep))
				continue
			}

			if ghToken != "" {
				req.Header.Add("Authorization", "token "+ghToken)
			}
			req.Header.Add("Accept", "application/vnd.github.v3+json")
			req.Header.Add("User-Agent", scannerUserAgent)

			resp, err := httpClient.Do(req) // Use shared client
			if err != nil {
				slog.Error("GitHub discovery: Error fetching repositories, retrying after backoff.", "url", url, "error", err, "backoff_ms", currentSleepDurationMs)
				select {case <-time.After(time.Duration(currentSleepDurationMs) * time.Millisecond): case <-ctx.Done(): return}
				currentSleepDurationMs = min(currentSleepDurationMs*backoffFactor, float64(maxSleep))
				continue
			}

			if resp.StatusCode != http.StatusOK {
				body, _ := ioutil.ReadAll(resp.Body)
				resp.Body.Close()
				logArgs := []any{"url", url, "status_code", resp.StatusCode, "status_text", resp.Status, "response_body_preview", string(body[:minInt(len(body), 200)])}

				var reactiveSleepTime time.Duration = time.Duration(currentSleepDurationMs) * time.Millisecond
				currentSleepDurationMs = min(currentSleepDurationMs*backoffFactor, float64(maxSleep))

				if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
					globalMetrics.RecordRateLimit(0) // Record hit, actual time added below
					resetStr := resp.Header.Get("X-RateLimit-Reset")
					if resetStr != "" {
						resetTimestamp, parseErr := strconv.ParseInt(resetStr, 10, 64)
						if parseErr == nil {
							calculatedSleep := time.Until(time.Unix(resetTimestamp, 0))
							reactiveSleepTime = maxDuration(0, calculatedSleep) + 1*time.Minute
							slog.Warn("GitHub reactive rate limit: Header suggests sleeping.", append(logArgs, "sleep_duration", reactiveSleepTime.String())...)
						}
					} else {
						reactiveSleepTime = 10 * time.Minute
						slog.Warn("GitHub reactive rate limit: No X-RateLimit-Reset header. Defaulting sleep.", append(logArgs, "sleep_duration", reactiveSleepTime.String())...)
					}
					atomic.AddInt64(&globalMetrics.TotalRateLimitWaitsSec, int64(reactiveSleepTime.Seconds())) // Add specific wait time
				} else {
				    slog.Warn("GitHub API returned non-200 status.", logArgs...)
				}
				slog.Info("GitHub discovery: Sleeping due to API error/rate limit.", "duration", reactiveSleepTime.String())
				select {
				case <-time.After(reactiveSleepTime):
				case <-ctx.Done():
					slog.Info("GitHub discovery shutting down during API error/rate limit sleep.")
					return
				}
				continue
			}

			var reposData []map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&reposData); err != nil {
				resp.Body.Close()
				slog.Error("GitHub discovery: Error parsing response, retrying after backoff.", "url", url, "error", err, "backoff_ms", currentSleepDurationMs)
				select {case <-time.After(time.Duration(currentSleepDurationMs) * time.Millisecond): case <-ctx.Done(): return}
				currentSleepDurationMs = min(currentSleepDurationMs*backoffFactor, float64(maxSleep))
				continue
			}
			resp.Body.Close()

			if len(reposData) == 0 {
				slog.Info("GitHub discovery: No more repositories found with current 'since' ID. Discovery pass complete.", "sinceID", sinceID)
				return
			}

			lastGoodIDInBatch := -1
			for i := len(reposData) - 1; i >= 0; i-- {
				if idFloat, ok := reposData[i]["id"].(float64); ok {
					lastGoodIDInBatch = int(idFloat)
					break
				}
			}

			if lastGoodIDInBatch == -1 {
				slog.Error("GitHub discovery: CRITICAL - Could not extract a valid ID from the last batch. Stopping discovery.", "batch_size", len(reposData))
				return
			}
			sinceID = lastGoodIDInBatch

			for _, repoMap := range reposData {
				var repoIDStr string
				if idFloat, ok := repoMap["id"].(float64); ok {
					repoIDStr = strconv.FormatInt(int64(idFloat), 10)
				} else {
					slog.Warn("GitHub discovery: Skipping repository with missing or invalid ID.", "repo_data_preview", safeString(repoMap["full_name"]))
					continue
				}
				repo := Repository{
					ID:          repoIDStr,
					Name:        safeString(repoMap["name"]),
					FullName:    safeString(repoMap["full_name"]),
					URL:         safeString(repoMap["html_url"]),
					Description: safeString(repoMap["description"]),
					Platform:    "github",
				}
				globalMetrics.RecordRepositoryDiscovered("github")
				select {
				case <-ctx.Done():
					return
				case repoChan <- repo:
					// Log less frequently using global metric
					if currentCount := atomic.LoadInt64(&globalMetrics.GithubReposDiscovered); currentCount%1000 == 0 {
						slog.Debug("GitHub discovery: Queued repositories.", "github_discovered_total", currentCount, "next_sinceID", sinceID)
					}
				}
			}
			currentSleepDurationMs = float64(initialSleep)
			select {case <-time.After(time.Duration(initialSleep) * time.Millisecond): case <-ctx.Done(): return }
		}
	}
}

func discoverHuggingFaceRepositories(ctx context.Context, repoChan chan<- Repository, db *sql.DB, httpClient *http.Client) {
	slog.Info("Starting Hugging Face model discovery...")
	offset := 0
	// limit is const huggingFaceAPILimit
	currentSleepDurationMs := float64(initialSleep)
	hfToken := os.Getenv(huggingFaceTokenEnv)

	for {
		select {
		case <-ctx.Done():
			slog.Info("Hugging Face model discovery cancelled.")
			return
		default:
			shouldProceed, sleepDur := checkHuggingFaceRateLimit(ctx, httpClient, hfToken)
			if !shouldProceed {
				slog.Info("HF Model proactive rate limit: Pausing discovery.", "duration", sleepDur.String())
				globalMetrics.RecordRateLimit(sleepDur)
				select {
				case <-time.After(sleepDur):
				case <-ctx.Done():
					slog.Info("HF Model discovery shutting down during proactive rate limit sleep.")
					return
				}
				continue
			}

			url := fmt.Sprintf("%s/models?limit=%d&offset=%d&sort=lastModified&direction=-1", huggingFaceAPIBaseURLDefault, huggingFaceAPILimit, offset)
			req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				slog.Error("HF Model discovery: Error creating API request, retrying after backoff.", "url", url, "error", err, "backoff_ms", currentSleepDurationMs)
				select {case <-time.After(time.Duration(currentSleepDurationMs) * time.Millisecond): case <-ctx.Done(): return}
				currentSleepDurationMs = min(currentSleepDurationMs*backoffFactor, float64(maxSleep))
				continue
			}
			if hfToken != "" {
				req.Header.Add("Authorization", "Bearer "+hfToken)
			}
			req.Header.Add("User-Agent", scannerUserAgent)

			resp, err := httpClient.Do(req) // Use shared client
			if err != nil {
				slog.Error("HF Model discovery: Error fetching models, retrying after backoff.", "url", url, "error", err, "backoff_ms", currentSleepDurationMs)
				select {case <-time.After(time.Duration(currentSleepDurationMs) * time.Millisecond): case <-ctx.Done(): return}
				currentSleepDurationMs = min(currentSleepDurationMs*backoffFactor, float64(maxSleep))
				continue
			}

			if resp.StatusCode != http.StatusOK {
				body, _ := ioutil.ReadAll(resp.Body)
				resp.Body.Close()
				logArgs := []any{"url", url, "status_code", resp.StatusCode, "status_text", resp.Status, "response_body_preview", string(body[:minInt(len(body), 200)])}
				
				var reactiveSleepTime time.Duration = time.Duration(currentSleepDurationMs) * time.Millisecond
				currentSleepDurationMs = min(currentSleepDurationMs*backoffFactor, float64(maxSleep))

				if resp.StatusCode == 429 || resp.StatusCode == 403 {
					globalMetrics.RecordRateLimit(0) // Record hit
					retryAfter := resp.Header.Get("Retry-After")
					if retryAfter != "" {
						seconds, parseErr := strconv.Atoi(retryAfter)
						if parseErr == nil && seconds > 0 {
							reactiveSleepTime = time.Duration(seconds) * time.Second
							slog.Warn("HF Model reactive rate limit: Header suggests sleeping.", append(logArgs, "sleep_duration", reactiveSleepTime.String())...)
						}
					} else {
						reactiveSleepTime = 5 * time.Minute
						slog.Warn("HF Model reactive rate limit: No Retry-After. Defaulting sleep.", append(logArgs, "sleep_duration", reactiveSleepTime.String())...)
					}
					atomic.AddInt64(&globalMetrics.TotalRateLimitWaitsSec, int64(reactiveSleepTime.Seconds()))
				} else {
				    slog.Warn("HF Model API returned non-200 status.", logArgs...)
				}
				slog.Info("HF Model discovery: Sleeping due to API error/rate limit.", "duration", reactiveSleepTime.String())
				select {
				case <-time.After(reactiveSleepTime):
				case <-ctx.Done():
					slog.Info("HF Model discovery shutting down during API error/rate limit sleep.")
					return
				}
				continue
			}

			var modelsData []map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&modelsData); err != nil {
				resp.Body.Close()
				slog.Error("HF Model discovery: Error parsing response, retrying after backoff.", "url", url, "error", err, "backoff_ms", currentSleepDurationMs)
				select {case <-time.After(time.Duration(currentSleepDurationMs) * time.Millisecond): case <-ctx.Done(): return}
				currentSleepDurationMs = min(currentSleepDurationMs*backoffFactor, float64(maxSleep))
				continue
			}
			resp.Body.Close()

			if len(modelsData) == 0 {
				slog.Info("HF Model discovery: No more models found. Discovery pass complete.", "offset", offset)
				return
			}

			for _, modelMap := range modelsData {
				modelID, ok := modelMap["id"].(string)
				if !ok || modelID == "" {
					slog.Warn("HF Model discovery: Skipping model with missing or invalid ID field.", "model_data_map", modelMap) // Log full map on error
					continue
				}
				repo := Repository{
					ID:       modelID, Name: modelID, FullName: modelID,
					URL: "https://huggingface.co/" + modelID, Platform: "huggingface-model",
				}
				globalMetrics.RecordRepositoryDiscovered("huggingface-model")
				select {
				case <-ctx.Done():
					return
				case repoChan <- repo:
					if currentCount := atomic.LoadInt64(&globalMetrics.HFModelsDiscovered); currentCount%200 == 0 {
						slog.Debug("HF Model discovery: Queued models.", "hf_models_discovered_total", currentCount, "current_offset", offset)
					}
				}
			}
			offset += len(modelsData)
			currentSleepDurationMs = float64(initialSleep)
			select {case <-time.After(time.Duration(initialSleep) * time.Millisecond): case <-ctx.Done(): return }
		}
	}
}

func discoverHuggingFaceSpaces(ctx context.Context, repoChan chan<- Repository, db *sql.DB, httpClient *http.Client) {
	slog.Info("Starting Hugging Face Spaces discovery...")
	offset := 0
	// limit is const huggingFaceAPILimit
	currentSleepDurationMs := float64(initialSleep)
	hfToken := os.Getenv(huggingFaceTokenEnv)

	for {
		select {
		case <-ctx.Done():
			slog.Info("Hugging Face Spaces discovery cancelled.")
			return
		default:
			shouldProceed, sleepDur := checkHuggingFaceRateLimit(ctx, httpClient, hfToken)
			if !shouldProceed {
				slog.Info("HF Spaces proactive rate limit: Pausing discovery.", "duration", sleepDur.String())
				globalMetrics.RecordRateLimit(sleepDur)
				select {
				case <-time.After(sleepDur):
				case <-ctx.Done():
					slog.Info("HF Spaces discovery shutting down during proactive rate limit sleep.")
					return
				}
				continue
			}

			url := fmt.Sprintf("%s/spaces?limit=%d&offset=%d&sort=lastModified&direction=-1", huggingFaceAPIBaseURLDefault, huggingFaceAPILimit, offset)
			req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				slog.Error("HF Spaces discovery: Error creating API request, retrying after backoff.", "url", url, "error", err, "backoff_ms", currentSleepDurationMs)
				select {case <-time.After(time.Duration(currentSleepDurationMs) * time.Millisecond): case <-ctx.Done(): return}
				currentSleepDurationMs = min(currentSleepDurationMs*backoffFactor, float64(maxSleep))
				continue
			}
			if hfToken != "" {
				req.Header.Add("Authorization", "Bearer "+hfToken)
			}
			req.Header.Add("User-Agent", scannerUserAgent)

			resp, err := httpClient.Do(req) // Use shared client
			if err != nil {
				slog.Error("HF Spaces discovery: Error fetching spaces, retrying after backoff.", "url", url, "error", err, "backoff_ms", currentSleepDurationMs)
				select {case <-time.After(time.Duration(currentSleepDurationMs) * time.Millisecond): case <-ctx.Done(): return}
				currentSleepDurationMs = min(currentSleepDurationMs*backoffFactor, float64(maxSleep))
				continue
			}

			if resp.StatusCode != http.StatusOK {
				body, _ := ioutil.ReadAll(resp.Body)
				resp.Body.Close()
				logArgs := []any{"url", url, "status_code", resp.StatusCode, "status_text", resp.Status, "response_body_preview", string(body[:minInt(len(body), 200)])}
				
				var reactiveSleepTime time.Duration = time.Duration(currentSleepDurationMs) * time.Millisecond
				currentSleepDurationMs = min(currentSleepDurationMs*backoffFactor, float64(maxSleep))

				if resp.StatusCode == 429 || resp.StatusCode == 403 {
					globalMetrics.RecordRateLimit(0) // Record hit
					retryAfter := resp.Header.Get("Retry-After")
					if retryAfter != "" {
						seconds, parseErr := strconv.Atoi(retryAfter)
						if parseErr == nil && seconds > 0 {
							reactiveSleepTime = time.Duration(seconds) * time.Second
							slog.Warn("HF Spaces reactive rate limit: Header suggests sleeping.", append(logArgs, "sleep_duration", reactiveSleepTime.String())...)
						}
					} else {
						reactiveSleepTime = 5 * time.Minute
						slog.Warn("HF Spaces reactive rate limit: No Retry-After. Defaulting sleep.", append(logArgs, "sleep_duration", reactiveSleepTime.String())...)
					}
					atomic.AddInt64(&globalMetrics.TotalRateLimitWaitsSec, int64(reactiveSleepTime.Seconds()))
				} else {
				    slog.Warn("HF Spaces API returned non-200 status.", logArgs...)
				}
				slog.Info("HF Spaces discovery: Sleeping due to API error/rate limit.", "duration", reactiveSleepTime.String())
				select {
				case <-time.After(reactiveSleepTime):
				case <-ctx.Done():
					slog.Info("HF Spaces discovery shutting down during API error/rate limit sleep.")
					return
				}
				continue
			}

			var spacesData []map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&spacesData); err != nil {
				resp.Body.Close()
				slog.Error("HF Spaces discovery: Error parsing response, retrying after backoff.", "url", url, "error", err, "backoff_ms", currentSleepDurationMs)
				select {case <-time.After(time.Duration(currentSleepDurationMs) * time.Millisecond): case <-ctx.Done(): return}
				currentSleepDurationMs = min(currentSleepDurationMs*backoffFactor, float64(maxSleep))
				continue
			}
			resp.Body.Close()

			if len(spacesData) == 0 {
				slog.Info("HF Spaces discovery: No more spaces found. Discovery pass complete.", "offset", offset)
				return
			}

			for _, spaceMap := range spacesData {
				spaceID, ok := spaceMap["id"].(string)
				if !ok || spaceID == "" {
					slog.Warn("HF Spaces discovery: Skipping space with missing or invalid ID.", "space_data_map", spaceMap) // Log full map
					continue
				}
				repo := Repository{
					ID:       spaceID, Name: spaceID, FullName: spaceID,
					URL: "https://huggingface.co/spaces/" + spaceID, Platform: "huggingface-space",
				}
				globalMetrics.RecordRepositoryDiscovered("huggingface-space")
				select {
				case <-ctx.Done():
					return
				case repoChan <- repo:
					if currentCount := atomic.LoadInt64(&globalMetrics.HFSpacesDiscovered); currentCount%200 == 0 {
						slog.Debug("HF Spaces discovery: Queued spaces.", "hf_spaces_discovered_total", currentCount, "current_offset", offset)
					}
				}
			}
			offset += len(spacesData)
			currentSleepDurationMs = float64(initialSleep)
			select {case <-time.After(time.Duration(initialSleep) * time.Millisecond): case <-ctx.Done(): return }
		}
	}
}

func checkGitHubRateLimit(ctx context.Context, httpClient *http.Client, baseURL, ghToken string, buffer int) (bool, time.Duration) {
	url := baseURL + "/rate_limit"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		slog.Warn("GitHub Rate Check: Error creating request. Proceeding cautiously.", "url", url, "error", err)
		return true, 0
	}
	if ghToken != "" {
		req.Header.Add("Authorization", "token "+ghToken)
	}
	req.Header.Add("Accept", "application/vnd.github.v3+json")
	req.Header.Add("User-Agent", scannerUserAgent+" (RateCheck)")

	resp, err := httpClient.Do(req) // Use provided client
	if err != nil {
		slog.Warn("GitHub Rate Check: Error performing request. Proceeding cautiously.", "url", url, "error", err)
		return true, 0
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		slog.Warn("GitHub Rate Check: Non-200 status.", "url", url, "status_code", resp.StatusCode, "body_preview", string(bodyBytes[:minInt(len(bodyBytes), 100)]))
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
			if resetStr := resp.Header.Get("X-RateLimit-Reset"); resetStr != "" {
				if resetTimestamp, pErr := strconv.ParseInt(resetStr, 10, 64); pErr == nil {
					sleepDur := time.Until(time.Unix(resetTimestamp, 0))
					return false, maxDuration(0, sleepDur) + 30*time.Second
				}
			}
			return false, 5 * time.Minute
		}
		return true, 0
	}

	var rateLimitData RateLimit
	if err := json.NewDecoder(resp.Body).Decode(&rateLimitData); err != nil {
		slog.Warn("GitHub Rate Check: Error parsing response. Proceeding cautiously.", "url", url, "error", err)
		return true, 0
	}

	remaining := rateLimitData.Resources.Core.Remaining
	resetAt := time.Unix(rateLimitData.Resources.Core.Reset, 0)
	slog.Debug("GitHub Rate Check status", "remaining", remaining, "limit", rateLimitData.Resources.Core.Limit, "resets_at", resetAt.Format(time.RFC3339), "buffer", buffer)

	if remaining <= buffer {
		sleepDuration := time.Until(resetAt)
		return false, maxDuration(0, sleepDuration) + 1*time.Minute
	}
	return true, 0
}

func checkHuggingFaceRateLimit(ctx context.Context, httpClient *http.Client, hfToken string) (bool, time.Duration) {
	url := huggingFaceAPIBaseURLDefault + "/whoami-v2"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		slog.Warn("HF Rate Check: Error creating request. Proceeding cautiously.", "url", url, "error", err)
		return true, 0
	}
	if hfToken != "" {
		req.Header.Add("Authorization", "Bearer "+hfToken)
	}
	req.Header.Add("User-Agent", scannerUserAgent+" (RateCheck)")

	resp, err := httpClient.Do(req) // Use provided client
	if err != nil {
		slog.Warn("HF Rate Check: Error performing request. Proceeding cautiously.", "url", url, "error", err)
		return true, 0
	}
	defer resp.Body.Close()
    slog.Debug("HF Rate Check status", "url", url, "status_code", resp.StatusCode)

	if resp.StatusCode == 429 || resp.StatusCode == 403 {
		slog.Warn("HF Rate Check: Received rate-limiting status.", "url", url, "status_code", resp.StatusCode)
		if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
			if seconds, pErr := strconv.Atoi(retryAfter); pErr == nil && seconds > 0 {
				return false, time.Duration(seconds) * time.Second
			}
		}
		return false, 3 * time.Minute
	}
	return true, 0
}


func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func safeString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution. 
Go
IGNORE_WHEN_COPYING_END
