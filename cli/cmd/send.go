package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/BioHazard786/warpvault/cli/internal/client"
	"github.com/BioHazard786/warpvault/cli/internal/config"
	"github.com/BioHazard786/warpvault/cli/internal/vault"
)

var (
	sendFile       string
	sendExpiry     string
	sendPassphrase bool
	sendJSON       bool
)

var sendCmd = &cobra.Command{
	Use:     "send [text]",
	Aliases: []string{"put", "create"},
	Short:   "Encrypt and upload text, a file, or stdin",
	Long: `Encrypts locally, uploads the ciphertext and prints a link containing the key.
By default the secret burns after the first read; use --expiry to keep it for a while instead.
Add --passphrase to also require a passphrase (asked without echo; or set WARPVAULT_PASSPHRASE).`,
	RunE: runSend,
}

func init() {
	f := sendCmd.Flags()
	f.StringVarP(&sendFile, "file", "f", "", "file to encrypt and upload")
	f.StringVarP(&sendExpiry, "expiry", "e", "burn", "burn (single read) or a duration the server allows, e.g. 1h, 24h")
	f.BoolVarP(&sendPassphrase, "passphrase", "p", false, "also require a passphrase to open it")
	f.BoolVar(&sendJSON, "json", false, "print the result as JSON")
	// root runs `send` for piped input, so the flags must exist there too
	rootCmd.Flags().AddFlagSet(f)
}

func runSend(cmd *cobra.Command, args []string) error {
	var secret vault.Secret
	switch {
	case sendFile != "":
		data, err := os.ReadFile(sendFile)
		if err != nil {
			return err
		}
		secret = vault.Secret{Kind: vault.File, Name: filepath.Base(sendFile), Data: data}
	case len(args) > 0:
		secret = vault.Secret{Kind: vault.Text, Data: []byte(strings.Join(args, " "))}
	case !isTerminal(os.Stdin):
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("reading stdin: %w", err)
		}
		secret = vault.Secret{Kind: vault.Text, Data: data}
	default:
		return errors.New("nothing to send: pass text, use -f <file>, or pipe data in")
	}
	if len(secret.Data) == 0 {
		return errors.New("secret is empty")
	}

	passphrase := os.Getenv("WARPVAULT_PASSPHRASE")
	if sendPassphrase && passphrase == "" {
		p, err := promptSecret("Passphrase: ")
		if err != nil {
			return err
		}
		again, err := promptSecret("Repeat passphrase: ")
		if err != nil {
			return err
		}
		if p == "" || p != again {
			return errors.New("passphrases are empty or do not match")
		}
		passphrase = p
	}

	server, _, err := config.Resolve(flagServer)
	if err != nil {
		return err
	}
	token, _ := config.ResolveAuth(flagAuth, server)
	key, err := vault.NewKey()
	if err != nil {
		return err
	}
	blob, err := vault.Seal(secret, key, passphrase)
	if err != nil {
		return err
	}
	res, err := client.New(server, token).Create(cmd.Context(), blob, sendExpiry)
	if err != nil {
		return err
	}

	link := res.URL + "#" + key
	switch {
	case sendJSON:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{
			"id": res.ID, "link": link, "delete_url": res.DeleteURL, "delete_token": res.DeleteToken,
			"size_bytes": res.SizeBytes, "expires_at": res.ExpiresAt, "burn": res.Burn, "passphrase": passphrase != "",
		})
	case flagQuiet:
		fmt.Println(link)
	default:
		fmt.Printf("\n  Link     %s\n", link)
		if res.Burn {
			fmt.Printf("  Expires  after the first read (or %s)\n", res.ExpiresAt.Local().Format("2006-01-02 15:04"))
		} else {
			fmt.Printf("  Expires  %s\n", res.ExpiresAt.Local().Format("2006-01-02 15:04 MST"))
		}
		if passphrase != "" {
			fmt.Printf("  Needs    the passphrase you set\n")
		}
		fmt.Printf("  Destroy  %s\n\n", res.DeleteURL)
		fmt.Printf("  Keep the whole link, including #…; without it nobody can decrypt this.\n\n")
	}
	return nil
}
