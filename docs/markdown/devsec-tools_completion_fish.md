## devsec-tools completion fish

Generate the autocompletion script for fish

### Synopsis

Generate the autocompletion script for the fish shell.

To load completions in your current shell session:

	devsec-tools completion fish | source

To load completions for every new session, execute once:

	devsec-tools completion fish > ~/.config/fish/completions/devsec-tools.fish

You will need to start a new shell for this setup to take effect.

```
devsec-tools completion fish [flags]
```

### Options

```
  -h, --help              help for fish
      --no-descriptions   disable completion descriptions
```

### Options inherited from parent commands

```
  -q, --quiet     Disable all logging output.
  -v, --verbose   Enable verbose output.
```

### SEE ALSO

* [devsec-tools completion](devsec-tools_completion.md)  - Generate the autocompletion script for the specified shell
