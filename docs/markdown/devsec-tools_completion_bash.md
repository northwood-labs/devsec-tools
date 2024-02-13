## devsec-tools completion bash

Generate the autocompletion script for bash

### Synopsis

Generate the autocompletion script for the bash shell.

This script depends on the 'bash-completion' package.
If it is not installed already, you can install it via your OS's package manager.

To load completions in your current shell session:

	source <(devsec-tools completion bash)

To load completions for every new session, execute once:

#### Linux

	devsec-tools completion bash > /etc/bash_completion.d/devsec-tools

#### macOS

	devsec-tools completion bash > $(brew --prefix)/etc/bash_completion.d/devsec-tools

You will need to start a new shell for this setup to take effect.

```
devsec-tools completion bash
```

### Options

```
  -h, --help              help for bash
      --no-descriptions   disable completion descriptions
```

### Options inherited from parent commands

```
  -q, --quiet     Disable all logging output.
  -v, --verbose   Enable verbose output.
```

### SEE ALSO

* [devsec-tools completion](devsec-tools_completion.md)  - Generate the autocompletion script for the specified shell
