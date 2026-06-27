// Package ollama is a client for the Ollama generate API.
package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Result struct {
	Name       string  `json:"name"`
	Confidence float64 `json:"confidence"`
	Summary    string  `json:"summary"`
}

type Client struct {
	baseURL string
	model   string
	numCtx  int
	httpc   *http.Client
}

func New(baseURL, model string, numCtx int) *Client {
	return &Client{
		baseURL: baseURL,
		model:   model,
		numCtx:  numCtx,
		httpc:   &http.Client{Timeout: 300 * time.Second},
	}
}

func (c *Client) Name(ctx context.Context, system, prompt string) (Result, error) {
	reqBody := map[string]any{
		"model":  c.model,
		"system": system,
		"prompt": prompt,
		"stream": false,
		"format": "json",
		"options": map[string]any{
			"temperature": 0.1,
			"num_ctx":     c.numCtx,
		},
	}
	buf, err := json.Marshal(reqBody)
	if err != nil {
		return Result{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/generate", bytes.NewReader(buf))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpc.Do(req)
	if err != nil {
		return Result{}, err
	}
	data, err := io.ReadAll(resp.Body)
	if cerr := resp.Body.Close(); cerr != nil && err == nil {
		err = cerr
	}
	if err != nil {
		return Result{}, err
	}
	var outer struct {
		Response string `json:"response"`
		Error    string `json:"error"`
	}
	if err := json.Unmarshal(data, &outer); err != nil {
		return Result{}, fmt.Errorf("decode ollama response: %w", err)
	}
	if outer.Error != "" {
		return Result{}, fmt.Errorf("ollama: %s", outer.Error)
	}
	var res Result
	if err := json.Unmarshal([]byte(outer.Response), &res); err != nil {
		return Result{}, fmt.Errorf("decode model JSON: %w", err)
	}
	return res, nil
}
