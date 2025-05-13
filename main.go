package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

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
	// Configuration
	maxConcurrency     = 5    // Number of concurrent scans
	resultsDir         = "results"
	dbPath             = "scans.db"
	githubAPIBaseURL   = "https://api.github.com"
	huggingFaceAPIURL  = "https://huggingface.co/api/models"
	scanTimeoutMinutes = 10   // Max time to spend scanning a single repo
	rateLimitBuffer    = 10   // Buffer for rate limit
	initialSleep       = 500  // ms between API requests
	backoffFactor      = 1.5  // Exponential backoff factor
	maxSleep           = 5000 // Max ms between API requests
)

// Repository represents a repository to scan
type Repository struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	FullName    string `json:"full_name"`
	URL         string `json:"html_url"`
	Description string `json:"description"`
	Platform    string // "github" or "huggingface"
}

// ScanResult tracks scan results
type ScanResult struct {
	RepoID      int64
	Platform    string
	URL         string
	ScanTime    time.Time
	Status      string
	FindingsNum int
	Error       string
}

// GithubAPIResponse for handling GitHub pagination
type GithubAPIResponse struct {
	Repositories []Repository
}

// RateLimit for GitHub API
type RateLimit struct {
	Resources struct {
		Core struct {
			Limit     int       `json:"limit"`
			Remaining int       `json:"remaining"`
			Reset     time.Time `json:"reset"`
		} `json:"core"`
	} `json:"resources"`
}

// HuggingFaceModel represents a Hugging Face model
type HuggingFaceModel struct {
	ID   string `json:"id"`
	Name string `json:"modelId"`
}

func main() {
	// Create results directory
	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		log.Fatalf("Failed to create results directory: %v", err)
	}

	// Set up database
	db, err := setupDatabase()
	if err != nil {
		log.Fatalf("Failed to set up database: %v", err)
	}
	defer db.Close()

	// Create a context that can be cancelled
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle termination signals to gracefully shutdown
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("\nReceived signal, shutting down gracefully...")
		cancel()
	}()

	// Create a worker pool
	var wg sync.WaitGroup
	repoChan := make(chan Repository, maxConcurrency)

	// Start workers
	for i := 0; i < maxConcurrency; i++ {
		wg.Add(1)
		go worker(ctx, &wg, repoChan, db)
	}

	// Start discovery goroutines
	wg.Add(2)
	go func() {
		defer wg.Done()
		discoverGithubRepositories(ctx, repoChan, db)
	}()
	go func() {
		defer wg.Done()
		discoverHuggingFaceRepositories(ctx, repoChan, db)
	}()

	// Wait for discovery to complete then close channel
	wg.Wait()
	close(repoChan)

	fmt.Println("All scanning completed!")
}

// setupDatabase initializes the SQLite database
func setupDatabase() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Create tables if they don't exist
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS scanned_repos (
		id INTEGER PRIMARY KEY,
		platform TEXT NOT NULL,
		url TEXT NOT NULL,
		scan_time TIMESTAMP,
		status TEXT,
		findings_num INTEGER DEFAULT 0,
		error TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_platform_id ON scanned_repos(platform, id);
	`
	_, err = db.Exec(createTableSQL)
	if err != nil {
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	return db, nil
}

// isRepoScanned checks if a repository has already been scanned
func isRepoScanned(db *sql.DB, platform string, repoID int64) (bool, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM scanned_repos WHERE platform = ? AND id = ?", platform, repoID).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// recordScanResult records the result of a scan
func recordScanResult(db *sql.DB, result ScanResult) error {
	_, err := db.Exec(
		"INSERT INTO scanned_repos (id, platform, url, scan_time, status, findings_num, error) VALUES (?, ?, ?, ?, ?, ?, ?)",
		result.RepoID, result.Platform, result.URL, result.ScanTime, result.Status, result.FindingsNum, result.Error,
	)
	return err
}

// worker processes repositories from the channel
func worker(ctx context.Context, wg *sync.WaitGroup, repoChan <-chan Repository, db *sql.DB) {
	defer wg.Done()

	for repo := range repoChan {
		select {
		case <-ctx.Done():
			return
		default:
			// Check if repository has already been scanned
			scanned, err := isRepoScanned(db, repo.Platform, repo.ID)
			if err != nil {
				log.Printf("Error checking if repo %s/%d is scanned: %v", repo.Platform, repo.ID, err)
				continue
			}
			if scanned {
				log.Printf("Repository %s already scanned, skipping", repo.FullName)
				continue
			}

			// Scan the repository
			log.Printf("Scanning %s repository: %s", repo.Platform, repo.FullName)
			result := scanRepository(ctx, repo)

			// Record the result
			if err := recordScanResult(db, result); err != nil {
				log.Printf("Error recording scan result for %s: %v", repo.FullName, err)
			}

			// Sleep to avoid hammering APIs
			time.Sleep(1 * time.Second)
		}
	}
}

// scanRepository scans a single repository using TruffleHog
func scanRepository(ctx context.Context, repo Repository) ScanResult {
	result := ScanResult{
		RepoID:   repo.ID,
		Platform: repo.Platform,
		URL:      repo.URL,
		ScanTime: time.Now(),
		Status:   "completed",
	}

	// Create a context with timeout
	scanCtx, cancel := context.WithTimeout(ctx, scanTimeoutMinutes*time.Minute)
	defer cancel()

	// Create an engine to perform the scan
	outputFormat := "json"
	outputFile := fmt.Sprintf("%s/%s_%d.json", resultsDir, repo.Platform, repo.ID)
	outFile, err := os.Create(outputFile)
	if err != nil {
		result.Status = "error"
		result.Error = fmt.Sprintf("Failed to create output file: %v", err)
		return result
	}
	defer outFile.Close()

	// Create output options
	outputOptions := []output.OutputOption{
		output.WithFormat(outputFormat),
		output.WithWriter(outFile),
	}

	// Configure the scan engine
	var scanSource sources.Source
	var scanOptions []sources.Option
	var ghToken, hfToken string

	// Get API tokens from environment
	if repo.Platform == "github" {
		ghToken = os.Getenv("GITHUB_TOKEN")
		if ghToken != "" {
			scanOptions = append(scanOptions, sources.WithGitHubToken(ghToken))
		}
	} else if repo.Platform == "huggingface" {
		hfToken = os.Getenv("HUGGINGFACE_TOKEN")
		if hfToken != "" {
			scanOptions = append(scanOptions, sources.WithToken(hfToken))
		}
	}

	// Configure source based on platform
	var err2 error
	if repo.Platform == "github" {
		scanSource, err2 = sources.NewGitHub(scanCtx, &source_metadatapb.MetaData{
			RepoUrl: repo.URL,
		}, scanOptions...)
	} else if repo.Platform == "huggingface" {
		// For Hugging Face, format the repo name as user/model
		scanSource, err2 = sources.NewHuggingFace(scanCtx, &source_metadatapb.MetaData{
			RepoUrl: repo.FullName, // Assuming FullName is in format "user/model"
		}, scanOptions...)
	}

	if err2 != nil {
		result.Status = "error"
		result.Error = fmt.Sprintf("Failed to create scan source: %v", err2)
		return result
	}

	// Create and run the scan engine
	e, err := engine.Start(scanCtx, config.Config{})
	if err != nil {
		result.Status = "error"
		result.Error = fmt.Sprintf("Failed to start scan engine: %v", err)
		return result
	}

	// Add the source to the engine and wait for completion
	jobID, err := e.ScanWithSource(scanSource)
	if err != nil {
		result.Status = "error"
		result.Error = fmt.Sprintf("Failed to scan repository: %v", err)
		return result
	}

	foundSecrets := 0
	secretsChan := e.GetDetectedSecretsChannel()
	outputter := output.NewOutputter(outputOptions...)

	// Process findings
	for secret := range secretsChan {
		if secret.SourceID == jobID {
			outputter.Send(secret)
			foundSecrets++
		}
	}

	// Wait for completion
	<-e.JobCompletedChannel(jobID)

	// Clean up
	e.Shutdown(scanCtx)
	outputter.Close()

	result.FindingsNum = foundSecrets
	log.Printf("Completed scan of %s, found %d secrets", repo.FullName, foundSecrets)

	return result
}

// discoverGithubRepositories discovers GitHub repositories to scan
func discoverGithubRepositories(ctx context.Context, repoChan chan<- Repository, db *sql.DB) {
	log.Println("Starting GitHub repository discovery")

	// Start from repository id 1
	sinceID := 1
	sleepDuration := initialSleep

	for {
		select {
		case <-ctx.Done():
			return
		default:
			// Check GitHub rate limit
			shouldContinue := checkGitHubRateLimit()
			if !shouldContinue {
				log.Println("GitHub rate limit reached, pausing discovery")
				time.Sleep(10 * time.Minute)
				continue
			}

			// Get repositories
			url := fmt.Sprintf("%s/repositories?since=%d", githubAPIBaseURL, sinceID)
			req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				log.Printf("Error creating GitHub API request: %v", err)
				time.Sleep(time.Duration(sleepDuration) * time.Millisecond)
				sleepDuration = min(float64(sleepDuration)*backoffFactor, maxSleep)
				continue
			}

			// Add authentication if available
			ghToken := os.Getenv("GITHUB_TOKEN")
			if ghToken != "" {
				req.Header.Add("Authorization", "token "+ghToken)
			}
			req.Header.Add("Accept", "application/vnd.github.v3+json")
			req.Header.Add("User-Agent", "TruffleHog-MassScanner")

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				log.Printf("Error fetching GitHub repositories: %v", err)
				time.Sleep(time.Duration(sleepDuration) * time.Millisecond)
				sleepDuration = min(float64(sleepDuration)*backoffFactor, maxSleep)
				continue
			}

			// Handle rate limiting and other errors
			if resp.StatusCode != http.StatusOK {
				body, _ := ioutil.ReadAll(resp.Body)
				resp.Body.Close()
				log.Printf("GitHub API returned non-200 status: %d %s - %s", resp.StatusCode, resp.Status, string(body))

				if resp.StatusCode == http.StatusForbidden {
					// Rate limited, sleep until reset time
					resetStr := resp.Header.Get("X-RateLimit-Reset")
					if resetStr != "" {
						resetTime, err := strconv.ParseInt(resetStr, 10, 64)
						if err == nil {
							sleepTime := time.Until(time.Unix(resetTime, 0)) + time.Minute
							log.Printf("Rate limited, sleeping until %v (about %v)", time.Unix(resetTime, 0), sleepTime)
							time.Sleep(sleepTime)
						} else {
							log.Printf("Failed to parse rate limit reset time: %v", err)
							time.Sleep(10 * time.Minute)
						}
					} else {
						time.Sleep(10 * time.Minute)
					}
				} else {
					// Other error, back off and retry
					time.Sleep(time.Duration(sleepDuration) * time.Millisecond)
					sleepDuration = min(float64(sleepDuration)*backoffFactor, maxSleep)
				}
				continue
			}

			// Parse response
			var repos []Repository
			if err := json.NewDecoder(resp.Body).Decode(&repos); err != nil {
				resp.Body.Close()
				log.Printf("Error parsing GitHub response: %v", err)
				time.Sleep(time.Duration(sleepDuration) * time.Millisecond)
				sleepDuration = min(float64(sleepDuration)*backoffFactor, maxSleep)
				continue
			}
			resp.Body.Close()

			if len(repos) == 0 {
				log.Println("No more GitHub repositories to scan")
				return
			}

			// Update the sinceID for next request
			sinceID = int(repos[len(repos)-1].ID)

			// Mark repositories as GitHub
			for i := range repos {
				repos[i].Platform = "github"
			}

			// Send repositories to the channel
			for _, repo := range repos {
				select {
				case <-ctx.Done():
					return
				case repoChan <- repo:
					// Repository queued for scanning
				}
			}

			// Sleep to respect rate limits
			time.Sleep(time.Duration(initialSleep) * time.Millisecond)
			// Reset backoff on success
			sleepDuration = initialSleep
		}
	}
}

// discoverHuggingFaceRepositories discovers Hugging Face repositories to scan
func discoverHuggingFaceRepositories(ctx context.Context, repoChan chan<- Repository, db *sql.DB) {
	log.Println("Starting Hugging Face repository discovery")

	offset := 0
	limit := 100
	sleepDuration := initialSleep

	for {
		select {
		case <-ctx.Done():
			return
		default:
			// Get repositories
			url := fmt.Sprintf("%s?limit=%d&offset=%d", huggingFaceAPIURL, limit, offset)
			req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				log.Printf("Error creating Hugging Face API request: %v", err)
				time.Sleep(time.Duration(sleepDuration) * time.Millisecond)
				sleepDuration = min(float64(sleepDuration)*backoffFactor, maxSleep)
				continue
			}

			// Add authentication if available
			hfToken := os.Getenv("HUGGINGFACE_TOKEN")
			if hfToken != "" {
				req.Header.Add("Authorization", "Bearer "+hfToken)
			}
			req.Header.Add("User-Agent", "TruffleHog-MassScanner")

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				log.Printf("Error fetching Hugging Face repositories: %v", err)
				time.Sleep(time.Duration(sleepDuration) * time.Millisecond)
				sleepDuration = min(float64(sleepDuration)*backoffFactor, maxSleep)
				continue
			}

			// Handle rate limiting and other errors
			if resp.StatusCode != http.StatusOK {
				body, _ := ioutil.ReadAll(resp.Body)
				resp.Body.Close()
				log.Printf("Hugging Face API returned non-200 status: %d %s - %s", resp.StatusCode, resp.Status, string(body))
				time.Sleep(time.Duration(sleepDuration) * time.Millisecond)
				sleepDuration = min(float64(sleepDuration)*backoffFactor, maxSleep)
				continue
			}

			// Parse response
			var models []HuggingFaceModel
			if err := json.NewDecoder(resp.Body).Decode(&models); err != nil {
				resp.Body.Close()
				log.Printf("Error parsing Hugging Face response: %v", err)
				time.Sleep(time.Duration(sleepDuration) * time.Millisecond)
				sleepDuration = min(float64(sleepDuration)*backoffFactor, maxSleep)
				continue
			}
			resp.Body.Close()

			if len(models) == 0 {
				log.Println("No more Hugging Face repositories to scan")
				return
			}

			// Convert to Repository format and queue for scanning
			for _, model := range models {
				// Extract user/model_name from the ID
				repo := Repository{
					ID:       int64(offset), // Using offset as ID since HF doesn't provide numeric IDs
					Name:     model.Name,
					FullName: model.ID,
					URL:      "https://huggingface.co/" + model.ID,
					Platform: "huggingface",
				}

				select {
				case <-ctx.Done():
					return
				case repoChan <- repo:
					// Repository queued for scanning
					offset++
				}
			}

			// Sleep to respect rate limits
			time.Sleep(time.Duration(initialSleep) * time.Millisecond)
			// Reset backoff on success
			sleepDuration = initialSleep
		}
	}
}

// checkGitHubRateLimit checks the current GitHub API rate limit
func checkGitHubRateLimit() bool {
	url := githubAPIBaseURL + "/rate_limit"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("Error creating rate limit request: %v", err)
		return true // Continue as if no rate limit issue
	}

	// Add authentication if available
	ghToken := os.Getenv("GITHUB_TOKEN")
	if ghToken != "" {
		req.Header.Add("Authorization", "token "+ghToken)
	}
	req.Header.Add("Accept", "application/vnd.github.v3+json")
	req.Header.Add("User-Agent", "TruffleHog-MassScanner")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("Error checking rate limit: %v", err)
		return true // Continue as if no rate limit issue
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Rate limit check returned non-200 status: %d", resp.StatusCode)
		return true // Continue as if no rate limit issue
	}

	var rateLimit RateLimit
	if err := json.NewDecoder(resp.Body).Decode(&rateLimit); err != nil {
		log.Printf("Error parsing rate limit response: %v", err)
		return true // Continue as if no rate limit issue
	}

	remaining := rateLimit.Resources.Core.Remaining
	resetTime := rateLimit.Resources.Core.Reset

	log.Printf("GitHub API rate limit: %d/%d, resets at %v",
		remaining, rateLimit.Resources.Core.Limit, resetTime)

	// If we're close to the limit, wait until reset
	if remaining <= rateLimitBuffer {
		sleepTime := time.Until(resetTime) + time.Minute
		log.Printf("Rate limit almost reached (%d remaining). Will resume at %v (sleeping for %v)",
			remaining, resetTime, sleepTime)
		return false
	}

	return true
}

// min returns the minimum of two float64 values
func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
