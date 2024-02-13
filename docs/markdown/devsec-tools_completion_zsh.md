## devsec-tools completion zsh

Generate the autocompletion script for zsh

### Synopsis

Generate the autocompletion script for the zsh shell.

If shell completion is not already enabled in your environment you will need
to enable it.  You can execute the following once:

	echo "autoload -U compinit; compinit" >> ~/.zshrc

To load completions in your current shell session:

	source <(devsec-tools completion zsh)

To load completions for every new session, execute once:

#### Linux

	devsec-tools completion zsh > "${fpath[1]}/_devsec-tools"

#### macOS

	devsec-tools completion zsh > $(brew --prefix)/share/zsh/site-functions/_devsec-tools

You will need to start a new shell for this setup to take effect.

```
devsec-tools completion zsh [flags]
```

### Options

```
  -h, --help              help for zsh
      --no-descriptions   disable completion descriptions
```

### Options inherited from parent commands

```
  -q, --quiet     Disable all logging output.
  -v, --verbose   Enable verbose output.
```

### SEE ALSO

* [devsec-tools completion](devsec-tools_completion.md)  - Generate the autocompletion script for the specified shell
