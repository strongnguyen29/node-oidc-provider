// Package config là public re-export của internal/config dành cho external
// consumer. Các type ở đây là type alias (Go 1.9+) nên giữ nguyên type
// identity với bản gốc — *config.Config từ package này có thể truyền thẳng
// vào provider.New mà không cần chuyển đổi.
package config

import internal "github.com/strongnguyen29/go-oidc-provider/internal/config"

// Config holds all provider configuration.
type Config = internal.Config

// ClientConfig represents a registered OAuth2 client.
type ClientConfig = internal.ClientConfig

// Account represents an end-user account.
type Account = internal.Account
