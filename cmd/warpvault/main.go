package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
	"warpvault/pkg/client"
)

var (
	version = "1.0.0"

	// Global / Persistent Flags
	serverURL string
	authToken string
	quietMode bool

	// Send Flags
	filePath     string
	burnFlag     bool
	expiryFlag   string
	passwordFlag string
	jsonOutput   bool

	// Get Flags
	keyFlag    string
	outputPath string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "warpvault",
		Short: "Zero-knowledge, client-side encrypted secret sharing CLI",
		Long: `Warpvault CLI provides end-to-end encrypted secret sharing directly from your terminal.
Plaintext is encrypted locally using AES-256-CBC (OpenSSL PBKDF2 compatible)
and the decryption key is kept in the URL hash fragment (#<key>) so the server never sees it.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// If input is piped via stdin and no subcommand was given, default to "send"
			if !isatty.IsTerminal(os.Stdin.Fd()) && !isatty.IsCygwinTerminal(os.Stdin.Fd()) {
				return runSend(cmd, args)
			}
			return cmd.Help()
		},
	}

	defaultServer := os.Getenv("WARPVAULT_SERVER")
	if defaultServer == "" {
		defaultServer = os.Getenv("WARPVAULT_BASE_URL")
	}
	if defaultServer == "" {
		defaultServer = "http://localhost:8080"
	}

	defaultAuth := os.Getenv("WARPVAULT_AUTH_TOKEN")

	rootCmd.PersistentFlags().StringVarP(&serverURL, "server", "s", defaultServer, "Warpvault server URL")
	rootCmd.PersistentFlags().StringVarP(&authToken, "auth", "a", defaultAuth, "Optional server authentication token")
	rootCmd.PersistentFlags().BoolVarP(&quietMode, "quiet", "q", false, "Quiet mode: print only the URL or decrypted secret")

	// --- Send Command ---
	sendCmd := &cobra.Command{
		Use:          "send [secret]",
		Aliases:      []string{"put", "create"},
		Short:        "Encrypt and upload a secret or file",
		SilenceUsage: true,
		Long: `Encrypts text, files, or stdin streams locally before uploading to Warpvault.
Outputs a shareable link containing the decryption key in the hash fragment.`,
		RunE: runSend,
	}

	sendCmd.Flags().StringVarP(&filePath, "file", "f", "", "Path to a file to encrypt and upload")
	sendCmd.Flags().BoolVarP(&burnFlag, "burn", "b", true, "Self-destruct after 1 download (Burn After Reading)")
	sendCmd.Flags().StringVarP(&expiryFlag, "expiry", "e", "", "Expiration duration (1h, 12h, 24h, 72h). Overrides default burn.")
	sendCmd.Flags().StringVarP(&passwordFlag, "password", "p", "", "Optional custom passphrase instead of auto-generated key")
	sendCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output response in JSON format")

	// --- Get Command ---
	getCmd := &cobra.Command{
		Use:          "get <url-or-id>",
		Aliases:      []string{"fetch", "read", "download"},
		Short:        "Download and decrypt a secret",
		SilenceUsage: true,
		Long: `Downloads encrypted ciphertext from Warpvault and decrypts it locally in memory.
If given a full URL with #<key>, the key is automatically extracted and decrypted.`,
		Args: cobra.ExactArgs(1),
		RunE: runGet,
	}

	getCmd.Flags().StringVarP(&keyFlag, "key", "k", "", "Decryption key (if omitted in URL fragment)")
	getCmd.Flags().StringVarP(&outputPath, "output", "o", "", "Save decrypted payload to file instead of stdout")

	// --- Version Command ---
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print Warpvault CLI version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("warpvault CLI version %s\n", version)
		},
	}

	rootCmd.AddCommand(sendCmd, getCmd, versionCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runSend(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	var plaintext []byte
	var err error

	if filePath != "" {
		plaintext, err = os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read file %s: %w", filePath, err)
		}
	} else if len(args) > 0 {
		plaintext = []byte(strings.Join(args, " "))
	} else if !isatty.IsTerminal(os.Stdin.Fd()) && !isatty.IsCygwinTerminal(os.Stdin.Fd()) {
		plaintext, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read from stdin: %w", err)
		}
	} else {
		return fmt.Errorf("no secret provided. Pass text as argument, use -f/--file, or pipe via stdin")
	}

	if len(plaintext) == 0 {
		return fmt.Errorf("secret cannot be empty")
	}

	effectiveBurn := burnFlag
	effectiveExpiry := expiryFlag
	if cmd.Flags().Changed("expiry") && !cmd.Flags().Changed("burn") {
		effectiveBurn = false
	}
	if effectiveBurn {
		effectiveExpiry = "burn"
	}

	c := client.NewClient(serverURL, authToken)
	res, err := c.SendSecret(ctx, plaintext, client.SendOptions{
		Burn:     effectiveBurn,
		Expiry:   effectiveExpiry,
		Password: passwordFlag,
	})
	if err != nil {
		return fmt.Errorf("upload failed: %w", err)
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}

	if quietMode {
		fmt.Println(res.ShareURL)
		return nil
	}

	fmt.Printf("\n🔐 Warpvault Secret Created!\n\n")
	fmt.Printf("  Share Link:   %s\n", res.ShareURL)
	if res.IsBurn {
		fmt.Printf("  Expiry:       Burn after reading (single-use)\n")
	} else {
		fmt.Printf("  Expiry:       %s\n", res.ExpiresAt.Local().Format("2006-01-02 15:04:05 MST"))
	}
	fmt.Printf("  Size:         %d bytes\n", res.SizeBytes)
	fmt.Printf("  Delete Link:  %s\n\n", res.DeleteURL)
	fmt.Printf("  Tip: Keep the full link with '#%s' to decrypt.\n\n", res.Key)

	return nil
}

func runGet(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	rawInput := args[0]

	serverBase, id, key, err := client.ParseVaultURL(rawInput)
	if err != nil {
		return err
	}

	targetServer := serverURL
	if serverBase != "" {
		targetServer = serverBase
	}

	effectiveKey := key
	if keyFlag != "" {
		effectiveKey = keyFlag
	}

	if effectiveKey == "" {
		return fmt.Errorf("decryption key missing. Provide a URL with #<key> or use -k/--key flag")
	}

	c := client.NewClient(targetServer, authToken)
	decrypted, err := c.GetSecret(ctx, id, effectiveKey)
	if err != nil {
		return err
	}

	if outputPath != "" {
		if err := os.WriteFile(outputPath, decrypted, 0600); err != nil {
			return fmt.Errorf("failed to write decrypted secret to %s: %w", outputPath, err)
		}
		if !quietMode {
			fmt.Printf("Decrypted secret successfully saved to %s (%d bytes)\n", outputPath, len(decrypted))
		}
		return nil
	}

	if isatty.IsTerminal(os.Stdout.Fd()) && !strings.HasSuffix(string(decrypted), "\n") {
		_, _ = fmt.Fprintln(os.Stdout, string(decrypted))
	} else {
		_, _ = os.Stdout.Write(decrypted)
	}

	return nil
}
