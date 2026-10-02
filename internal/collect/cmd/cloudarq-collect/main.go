// Command cloudarq-collect reads one cloud account and writes the bundle
// the engine reads: `cloudarq-collect aws --profile prod > estate.json`.
//
// It runs with the customer's own credentials, from AWS's standard chain -
// a profile, SSO, the environment - and only reads. The bundle goes to
// standard output and nothing else does; what it did and what AWS refused
// go to standard error.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	collect "github.com/CloudArq-net/cloudarq/internal/collect/aws"
)

// version is set at release, by the linker.
var version = "dev"

const (
	exitWhole   = 0
	exitFailed  = 1 // no bundle: the account could not be learned
	exitUsage   = 2
	exitPartial = 3 // a bundle, with something refused or capped
)

// defaultRegion is where STS is asked when nothing names a region. IAM is
// global, and STS answers GetCallerIdentity in every region of a partition.
const defaultRegion = "us-east-1"

// timeout bounds a whole collection: five pages of roles take seconds, and a
// run still going after this is waiting on something that will not answer.
const timeout = 10 * time.Minute

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage: cloudarq-collect aws [--profile NAME] [--region REGION] [--explain] > estate.json

Reads the AWS account your credentials belong to - who it is, its roles and
their trust policies, and its alias - and writes them as one bundle on
standard output. It only reads, with your own credentials from AWS's
standard chain.

  --profile NAME    the profile to use, as the AWS CLI's --profile
  --region REGION   the region to ask STS in; IAM is global
  --explain         name every call on standard error before it is made
  --version         print the version and exit
`)
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "--version" || args[0] == "-version") {
		fmt.Fprintln(stdout, "cloudarq-collect", version)
		return exitWhole
	}
	if len(args) == 0 || args[0] != "aws" {
		usage(stderr)
		return exitUsage
	}
	flags := flag.NewFlagSet("cloudarq-collect aws", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { usage(stderr) }
	profile := flags.String("profile", "", "the profile to use")
	region := flags.String("region", "", "the region to ask STS in")
	explain := flags.Bool("explain", false, "name every call before it is made")
	if err := flags.Parse(args[1:]); err != nil {
		return exitUsage
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(stderr, "cloudarq-collect: aws takes no arguments, only flags; %+q was given\n", flags.Arg(0))
		usage(stderr)
		return exitUsage
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	options := []func(*config.LoadOptions) error{config.WithAppID("cloudarq-collect")}
	if *profile != "" {
		options = append(options, config.WithSharedConfigProfile(*profile))
	}
	if *region != "" {
		options = append(options, config.WithRegion(*region))
	}
	settings, err := config.LoadDefaultConfig(ctx, options...)
	if err != nil {
		fmt.Fprintln(stderr, "cloudarq-collect: the AWS settings could not be read:", err)
		return exitFailed
	}
	if settings.Region == "" {
		settings.Region = defaultRegion
	}

	reader := collect.Reader{
		STS:       sts.NewFromConfig(settings),
		IAM:       iam.NewFromConfig(settings),
		Clock:     time.Now,
		Collector: "cloudarq-collect " + version,
	}
	if *explain {
		reader.Explain = stderr
	}
	bundle, err := reader.Collect(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "cloudarq-collect:", err)
		if errors.Is(err, context.DeadlineExceeded) {
			fmt.Fprintf(stderr, "cloudarq-collect: the collection was stopped after %s\n", timeout)
		}
		return exitFailed
	}
	if err := bundle.Encode(stdout); err != nil {
		fmt.Fprintln(stderr, "cloudarq-collect: the bundle could not be written:", err)
		return exitFailed
	}
	return report(stderr, bundle)
}

// report says on standard error what the bundle holds, and what it lacks.
func report(stderr io.Writer, bundle collect.Bundle) int {
	name := bundle.Account
	if bundle.Alias != nil {
		name = fmt.Sprintf("%s (%s)", bundle.Account, sdk.ToString(bundle.Alias))
	}
	fmt.Fprintf(stderr, "cloudarq-collect: account %s: %s in %s\n", name, counted(bundle.Roles(), "role"), counted(len(bundle.Pages), "page"))
	for _, refused := range bundle.Refused {
		fmt.Fprintf(stderr, "cloudarq-collect: AWS refused %s: %s: %s\n", refused.Call, refused.Code, refused.Message)
	}
	for _, limit := range bundle.Limits {
		fmt.Fprintln(stderr, "cloudarq-collect:", limit)
	}
	if !bundle.Partial() {
		return exitWhole
	}
	fmt.Fprintln(stderr, "cloudarq-collect: the bundle is partial, and says what it lacks; a whole read needs iam:ListRoles and iam:ListAccountAliases")
	return exitPartial
}

func counted(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
