package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/BioHazard786/warpvault/cli/internal/config"
	"github.com/BioHazard786/warpvault/cli/internal/version"
)

var (
	flagServer string
	flagAuth   string
	flagQuiet  bool
)

var rootCmd = &cobra.Command{
	Use:   "warpvault",
	Short: "Zero-knowledge secret sharing from the terminal",
	Long: `Warpvault encrypts secrets on your machine (AES-256-GCM) before uploading them. The key travels in
the link's #fragment, so the server never sees it. Pipe something in to send it:

  echo "sk_live_999" | warpvault
  warpvault send -f ~/.ssh/id_ed25519 --expiry 12h
  warpvault get "https://vault.warplabs.info/v/a8X2mP9z#KEY"

Self-hosting? Point the CLI at your server once: warpvault config set server https://vault.example.com`,
	Version: version.Version,
	// Piped input and no subcommand means "send".
	RunE: func(cmd *cobra.Command, args []string) error {
		if !isTerminal(os.Stdin) {
			return runSend(cmd, args)
		}
		return cmd.Help()
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&flagServer, "server", "s", "", "server URL, overriding $WARPVAULT_SERVER and the saved one (default "+config.DefaultServer+")")
	rootCmd.PersistentFlags().StringVarP(&flagAuth, "auth", "a", "", "upload token, overriding $WARPVAULT_AUTH_TOKEN and the saved one")
	rootCmd.PersistentFlags().BoolVarP(&flagQuiet, "quiet", "q", false, "print only the link or the secret")
	rootCmd.AddCommand(sendCmd, getCmd, configCmd)
}

var errInterrupted = errors.New("interrupted")

// Execute runs the CLI. Ctrl-C cancels the context so in-flight requests stop cleanly.
func Execute() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	rootCmd.SilenceErrors = true
	rootCmd.SilenceUsage = true
	err := rootCmd.ExecuteContext(ctx)
	stop()
	switch {
	case err == nil:
	case errors.Is(err, errInterrupted), errors.Is(err, context.Canceled):
		os.Exit(130)
	default:
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func isTerminal(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }

// promptSecret reads a line from the terminal without echo. When stdin is piped (the secret itself
// is coming through it) it falls back to the controlling terminal.
func promptSecret(prompt string) (string, error) {
	f := os.Stdin
	if !isTerminal(f) {
		name := "/dev/tty"
		if runtime.GOOS == "windows" {
			name = "CONIN$"
		}
		t, err := os.Open(name)
		if err != nil {
			return "", errors.New("no terminal to ask for the passphrase; set WARPVAULT_PASSPHRASE")
		}
		defer t.Close()
		f = t
	}
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(int(f.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}
