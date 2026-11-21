package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/BioHazard786/warpvault/cli/internal/client"
	"github.com/BioHazard786/warpvault/cli/internal/config"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Show or change saved settings (server, upload token)",
	Long: `Settings are saved in a config file so you don't repeat them on every command. Precedence, highest first:
flag, environment variable, saved config, built-in default.

  warpvault config set server https://vault.example.com   # once, for a self-hosted server
  warpvault config set auth-token                         # asked without echo; only sent to that server
  warpvault config get                                    # what is in effect, and where it comes from
  warpvault config unset server`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error { return runConfigGet(cmd, args) },
}

func init() {
	configCmd.AddCommand(
		&cobra.Command{Use: "get", Short: "Show the settings in effect", Args: cobra.NoArgs, RunE: runConfigGet},
		&cobra.Command{
			Use:       "set <server|auth-token> [value]",
			Short:     "Save a setting",
			Args:      cobra.RangeArgs(1, 2),
			ValidArgs: []string{"server", "auth-token"},
			RunE:      runConfigSet,
		},
		&cobra.Command{
			Use:       "unset <server|auth-token>",
			Short:     "Remove a saved setting",
			Args:      cobra.ExactArgs(1),
			ValidArgs: []string{"server", "auth-token"},
			RunE:      runConfigUnset,
		},
		&cobra.Command{
			Use:   "path",
			Short: "Print the config file location",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				p, err := config.Path()
				if err == nil {
					fmt.Println(p)
				}
				return err
			},
		},
	)
}

func runConfigGet(cmd *cobra.Command, args []string) error {
	server, src, err := config.Resolve(flagServer)
	if err != nil {
		return err
	}
	token, tokenSrc := config.ResolveAuth(flagAuth, server)
	path, _ := config.Path()
	fmt.Printf("server      %s  (%s)\n", server, src)
	if token == "" {
		fmt.Printf("auth token  not set\n")
	} else {
		fmt.Printf("auth token  set  (%s)\n", tokenSrc)
	}
	fmt.Printf("config      %s\n", path)
	return nil
}

func runConfigSet(cmd *cobra.Command, args []string) error {
	f, err := config.Load()
	if err != nil {
		return err
	}
	switch strings.ToLower(args[0]) {
	case "server":
		if len(args) != 2 {
			return errors.New("usage: warpvault config set server <url>")
		}
		server, err := config.NormalizeServer(args[1])
		if err != nil {
			return err
		}
		if old, _ := config.NormalizeServer(orDefault(f.Server)); old != server && f.AuthToken != "" {
			f.AuthToken = "" // the saved token belongs to the previous server
			fmt.Fprintln(os.Stderr, "note: removed the saved auth token, it belonged to the previous server")
		}
		f.Server = server
		if err := f.Save(); err != nil {
			return err
		}
		// Saved either way: being offline right now shouldn't block configuring a server.
		ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
		defer cancel()
		info, err := client.New(server, "").Info(ctx)
		switch {
		case err != nil:
			fmt.Fprintf(os.Stderr, "saved %s, but could not verify it: %v\n", server, err)
			if !strings.Contains(args[1], "://") {
				fmt.Fprintln(os.Stderr, "hint: a bare host means https. For a server without TLS, include http://, e.g. http://localhost:8080")
			}
		case info.AuthRequired:
			fmt.Printf("saved %s (Warpvault %s). It requires an upload token: warpvault config set auth-token\n", server, info.Version)
		default:
			fmt.Printf("saved %s (Warpvault %s)\n", server, info.Version)
		}
	case "auth-token", "auth_token", "token":
		token := ""
		if len(args) == 2 {
			token = args[1]
		} else if token, err = promptSecret("Upload token: "); err != nil {
			return err
		}
		if token == "" {
			return errors.New("the token is empty; use `warpvault config unset auth-token` to remove it")
		}
		f.AuthToken = token
		if err := f.Save(); err != nil {
			return err
		}
		fmt.Printf("saved the auth token for %s\n", orDefault(f.Server))
	default:
		return fmt.Errorf("unknown setting %q (want server or auth-token)", args[0])
	}
	return nil
}

func runConfigUnset(cmd *cobra.Command, args []string) error {
	f, err := config.Load()
	if err != nil {
		return err
	}
	switch strings.ToLower(args[0]) {
	case "server":
		f.Server = ""
		f.AuthToken = "" // it belonged to that server
	case "auth-token", "auth_token", "token":
		f.AuthToken = ""
	default:
		return fmt.Errorf("unknown setting %q (want server or auth-token)", args[0])
	}
	if err := f.Save(); err != nil {
		return err
	}
	fmt.Printf("removed %s\n", args[0])
	return nil
}

func orDefault(server string) string {
	if server == "" {
		return config.DefaultServer
	}
	return server
}
