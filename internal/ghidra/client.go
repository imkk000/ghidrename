// Package ghidra is an HTTP client for the GhidraMCP plugin API.
package ghidra

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Function struct {
	Name    string
	Address string
}

type Client struct {
	baseURL string
	httpc   *http.Client
}

func New(baseURL string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpc:   &http.Client{Timeout: 240 * time.Second},
	}
}

func (c *Client) CurrentProgram() (string, error) {
	data, err := c.get("/get_current_program_info")
	if err != nil {
		return "", err
	}
	var info struct {
		Name  string `json:"name"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(data, &info); err != nil {
		return "", fmt.Errorf("decode program info: %w", err)
	}
	if info.Error != "" {
		return "", fmt.Errorf("ghidra: %s", info.Error)
	}
	if info.Name == "" {
		return "", errors.New("no program loaded in Ghidra")
	}
	return info.Name, nil
}

func (c *Client) ListDefaultFunctions() ([]Function, error) {
	data, err := c.get("/list_functions?offset=0&limit=1000000")
	if err != nil {
		return nil, err
	}
	var out []Function
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		name, addr, ok := splitOn(sc.Text(), " at ")
		if !ok || !strings.HasPrefix(name, "FUN_") {
			continue
		}
		out = append(out, Function{Name: name, Address: addr})
	}
	return out, sc.Err()
}

func (c *Client) Callees(addr string) ([]Function, error) {
	data, err := c.get("/get_function_callees?address=" + url.QueryEscape(addr))
	if err != nil {
		return nil, err
	}
	var out []Function
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		name, a, ok := splitOn(sc.Text(), " @ ")
		if ok {
			out = append(out, Function{Name: name, Address: a})
		}
	}
	return out, sc.Err()
}

func (c *Client) Decompile(addr string) (string, error) {
	data, err := c.get("/decompile_function?address=" + url.QueryEscape(addr))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (c *Client) Rename(addr, name string) error {
	data, err := c.postJSON("/rename_function_by_address", map[string]string{
		"function_address": addr,
		"new_name":         name,
	})
	if err != nil {
		return err
	}
	return checkStatus(data)
}

func (c *Client) SetPlateComment(addr, comment string) error {
	data, err := c.postJSON("/set_plate_comment", map[string]string{
		"address": addr,
		"comment": comment,
	})
	if err != nil {
		return err
	}
	return checkStatus(data)
}

func (c *Client) get(path string) ([]byte, error) {
	resp, err := c.httpc.Get(c.baseURL + path)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(resp.Body)
	if cerr := resp.Body.Close(); cerr != nil && err == nil {
		err = cerr
	}
	return body, err
}

func (c *Client) postJSON(path string, body any) ([]byte, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpc.Post(c.baseURL+path, "application/json", bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	out, err := io.ReadAll(resp.Body)
	if cerr := resp.Body.Close(); cerr != nil && err == nil {
		err = cerr
	}
	return out, err
}

func checkStatus(data []byte) error {
	if !json.Valid(data) {
		return nil
	}
	var r struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if r.Error != "" {
		return fmt.Errorf("ghidra: %s", r.Error)
	}
	return nil
}

func splitOn(line, sep string) (left, right string, ok bool) {
	i := strings.LastIndex(line, sep)
	if i < 0 {
		return "", "", false
	}
	left = strings.TrimSpace(line[:i])
	right = strings.TrimSpace(line[i+len(sep):])
	return left, right, left != "" && right != ""
}
