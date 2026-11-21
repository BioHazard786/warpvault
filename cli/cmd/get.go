package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/BioHazard786/warpvault/cli/internal/client"
	"github.com/BioHazard786/warpvault/cli/internal/config"
	"github.com/BioHazard786/warpvault/cli/internal/vault"
)

var getOutput string

var getCmd = &cobra.Command{
	Use:     "get <link>",
	Aliases: []string{"read", "fetch"},
	Short:   "Download and decrypt a secret",
	Long: `Downloads the ciphertext and decrypts it locally. Text is printed to stdout. A file is saved under
its original name in the current directory (never overwriting), or to -o <path>; use -o - for stdout.
A burn-after-reading secret is destroyed on the server the moment it is downloaded.`,
	Args: cobra.ExactArgs(1),
	RunE: runGet,
}

func init() {
	getCmd.Flags().StringVarP(&getOutput, "output", "o", "", "write the secret to this path (- for stdout)")
}

func runGet(cmd *cobra.Command, args []string) error {
	linkServer, id, key, err := client.ParseLink(args[0])
	if err != nil {
		return err
	}
	if key == "" {
		return errors.New("the link has no #key part; copy the complete link")
	}
	// The link names its server, so no setup is needed. -s overrides it (e.g. a link behind another hostname).
	server := linkServer
	if flagServer != "" {
		if server, _, err = config.Resolve(flagServer); err != nil {
			return err
		}
	}

	// Reading needs no token, so none is sent: a link must not be able to make us hand a token to its server.
	blob, err := client.New(server, "").Open(cmd.Context(), id)
	if err != nil {
		return err
	}

	// The blob is already in memory, so a wrong passphrase can be retried without touching the server
	// (which may have just burned the secret).
	passphrase := os.Getenv("WARPVAULT_PASSPHRASE")
	var secret vault.Secret
	for attempt := 0; ; attempt++ {
		secret, err = vault.Open(blob, key, passphrase)
		if err == nil {
			break
		}
		needsPrompt := errors.Is(err, vault.ErrPassphraseRequired) || (vault.NeedsPassphrase(blob) && errors.Is(err, vault.ErrDecrypt))
		if !needsPrompt || attempt >= 3 {
			return err
		}
		if attempt > 0 {
			fmt.Fprintln(os.Stderr, "wrong passphrase, try again")
		}
		if passphrase, err = promptSecret("Passphrase: "); err != nil {
			return err
		}
	}

	return writeSecret(secret)
}

func writeSecret(s vault.Secret) error {
	toStdout := getOutput == "-" || (getOutput == "" && s.Kind == vault.Text)
	if toStdout {
		_, err := os.Stdout.Write(s.Data)
		if err == nil && isTerminal(os.Stdout) && !strings.HasSuffix(string(s.Data), "\n") {
			fmt.Println()
		}
		return err
	}

	path, flags := getOutput, os.O_WRONLY|os.O_CREATE|os.O_TRUNC
	if path == "" { // default name comes from the sender: strip any directories, never overwrite
		name := filepath.Base(strings.ReplaceAll(s.Name, "\\", "/"))
		if name == "" || name == "." || name == ".." || name == "/" {
			name = "secret.bin"
		}
		path, flags = name, os.O_WRONLY|os.O_CREATE|os.O_EXCL
	}
	f, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists; choose another path with -o", path)
		}
		return err
	}
	if _, err := f.Write(s.Data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if !flagQuiet {
		fmt.Fprintf(os.Stderr, "saved %s (%d bytes)\n", path, len(s.Data))
	}
	return nil
}
