package version

// Version of the Warpvault CLI. Overridden at build time (GoReleaser sets it):
//
//	go build -ldflags="-X github.com/BioHazard786/warpvault/cli/internal/version.Version=1.0.0"
var Version = "dev"
