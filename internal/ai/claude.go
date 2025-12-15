package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

type ClaudeClient struct {
	apiKey       string
	baseURL      string
	httpClient   *http.Client
	model        string
	lastRequest  time.Time
	minInterval  time.Duration
	TotalInput   int // Total input tokens used
	TotalOutput  int // Total output tokens used
	RequestCount int // Number of API requests made
}

// GetCost returns estimated cost in USD based on Claude Sonnet pricing
// Input: $3/MTok, Output: $15/MTok
func (c *ClaudeClient) GetCost() float64 {
	inputCost := float64(c.TotalInput) / 1000000.0 * 3.0
	outputCost := float64(c.TotalOutput) / 1000000.0 * 15.0
	return inputCost + outputCost
}

// GetUsageStats returns usage statistics
func (c *ClaudeClient) GetUsageStats() (inputTokens, outputTokens, requests int, cost float64) {
	return c.TotalInput, c.TotalOutput, c.RequestCount, c.GetCost()
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ClaudeRequest struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	Messages  []Message `json:"messages"`
	System    string    `json:"system,omitempty"`
}

type ClaudeResponse struct {
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

type PentestDecision struct {
	Action      string   `json:"action"`
	Target      string   `json:"target"`
	Technique   string   `json:"technique"`
	Reasoning   string   `json:"reasoning"`
	RiskLevel   string   `json:"risk_level"`
	NextSteps   []string `json:"next_steps"`
	Exploits    []string `json:"exploits,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
}

func NewClaudeClient() (*ClaudeClient, error) {
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("ANTHROPIC_API_KEY environment variable not set")
	}

	return &ClaudeClient{
		apiKey:  apiKey,
		baseURL: "https://api.anthropic.com/v1/messages",
		httpClient: &http.Client{
			Timeout: 120 * time.Second,
		},
		model:       "claude-sonnet-4-20250514",
		minInterval: 3 * time.Second, // Rate limit: wait between requests
	}, nil
}

func (c *ClaudeClient) systemPrompt() string {
	return `You are an expert penetration testing AI assistant. Your role is to analyze scan results, identify vulnerabilities, and recommend exploitation techniques for AUTHORIZED security testing only.

You must:
1. Analyze reconnaissance data to identify potential attack vectors
2. Prioritize vulnerabilities by severity and exploitability
3. Recommend specific exploitation techniques and tools
4. Provide remediation advice for each vulnerability found
5. Think step-by-step about the attack chain

When given scan results, respond with a JSON object containing:
{
  "action": "the recommended action (scan/enumerate/exploit/report)",
  "target": "specific target host/service/endpoint",
  "technique": "specific technique or tool to use",
  "reasoning": "why this approach is recommended",
  "risk_level": "low/medium/high/critical",
  "next_steps": ["list", "of", "follow-up", "actions"],
  "exploits": ["relevant", "CVEs", "or", "exploit", "names"],
  "remediation": "how to fix this vulnerability"
}

Always prioritize safety and ensure testing stays within authorized scope.`
}

func (c *ClaudeClient) Analyze(ctx context.Context, data string) (*PentestDecision, error) {
	req := ClaudeRequest{
		Model:     c.model,
		MaxTokens: 4096,
		System:    c.systemPrompt(),
		Messages: []Message{
			{
				Role:    "user",
				Content: fmt.Sprintf("Analyze the following pentest data and provide your recommendation:\n\n%s", data),
			},
		},
	}

	return c.sendRequest(ctx, req)
}

func (c *ClaudeClient) PlanAttack(ctx context.Context, target string, reconData string) (*PentestDecision, error) {
	req := ClaudeRequest{
		Model:     c.model,
		MaxTokens: 4096,
		System:    c.systemPrompt(),
		Messages: []Message{
			{
				Role: "user",
				Content: fmt.Sprintf(`Target: %s

Reconnaissance Data:
%s

Based on this information, what is the most promising attack vector? Provide a detailed exploitation plan.`, target, reconData),
			},
		},
	}

	return c.sendRequest(ctx, req)
}

func (c *ClaudeClient) SelectExploit(ctx context.Context, service string, version string, vulns []string) (*PentestDecision, error) {
	vulnList := ""
	for _, v := range vulns {
		vulnList += fmt.Sprintf("- %s\n", v)
	}

	req := ClaudeRequest{
		Model:     c.model,
		MaxTokens: 4096,
		System:    c.systemPrompt(),
		Messages: []Message{
			{
				Role: "user",
				Content: fmt.Sprintf(`Service: %s
Version: %s

Known Vulnerabilities:
%s

Select the most effective exploit for this target and explain how to execute it safely.`, service, version, vulnList),
			},
		},
	}

	return c.sendRequest(ctx, req)
}

func (c *ClaudeClient) AnalyzeWebApp(ctx context.Context, url string, crawlData string, findings string) (*PentestDecision, error) {
	req := ClaudeRequest{
		Model:     c.model,
		MaxTokens: 4096,
		System:    c.systemPrompt(),
		Messages: []Message{
			{
				Role: "user",
				Content: fmt.Sprintf(`Web Application: %s

Crawl Data:
%s

Initial Findings:
%s

Analyze this web application for OWASP Top 10 vulnerabilities and recommend specific tests to run.`, url, crawlData, findings),
			},
		},
	}

	return c.sendRequest(ctx, req)
}

func (c *ClaudeClient) rateLimit() {
	elapsed := time.Since(c.lastRequest)
	if elapsed < c.minInterval {
		time.Sleep(c.minInterval - elapsed)
	}
	c.lastRequest = time.Now()
}

func (c *ClaudeClient) sendRequest(ctx context.Context, req ClaudeRequest) (*PentestDecision, error) {
	c.rateLimit()
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", c.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var claudeResp ClaudeResponse
	if err := json.Unmarshal(respBody, &claudeResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Track token usage
	c.TotalInput += claudeResp.Usage.InputTokens
	c.TotalOutput += claudeResp.Usage.OutputTokens
	c.RequestCount++

	if len(claudeResp.Content) == 0 {
		return nil, fmt.Errorf("empty response from Claude")
	}

	// Parse the JSON decision from Claude's response
	var decision PentestDecision
	responseText := claudeResp.Content[0].Text

	// Try to extract JSON from the response
	if err := json.Unmarshal([]byte(responseText), &decision); err != nil {
		// If direct parsing fails, try to find JSON in the response
		decision = PentestDecision{
			Action:    "analyze",
			Reasoning: responseText,
		}
	}

	return &decision, nil
}

func (c *ClaudeClient) Chat(ctx context.Context, messages []Message) (string, error) {
	c.rateLimit()
	req := ClaudeRequest{
		Model:     c.model,
		MaxTokens: 1024, // Reduced for efficiency
		System:    c.systemPrompt(),
		Messages:  messages,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", c.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var claudeResp ClaudeResponse
	if err := json.Unmarshal(respBody, &claudeResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	// Track token usage
	c.TotalInput += claudeResp.Usage.InputTokens
	c.TotalOutput += claudeResp.Usage.OutputTokens
	c.RequestCount++

	if len(claudeResp.Content) == 0 {
		return "", fmt.Errorf("empty response from Claude")
	}

	return claudeResp.Content[0].Text, nil
}
