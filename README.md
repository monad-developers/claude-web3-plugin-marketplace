# Claude Web3 Plugin Marketplace

Directory of Claude Code web3 plugins including utility plugins and chain-specific plugins.

## Installation

### Step 1: Add the marketplace

```bash
/plugin marketplace add github.com/monad-developers/claude-web3-plugin-marketplace
```

### Step 2: Install a plugin

```bash
/plugin install monad-development@web3-plugins
```

Or install globally (available in all projects):

```bash
/plugin install monad-development@web3-plugins --global
```

## Available Plugins

| Plugin | Description | Version |
|--------|-------------|---------|
| `monad-development` | Build dapps on Monad blockchain without friction | 0.1.0 |

## For Teams

Add automatic marketplace installation to your project's `.claude/settings.json`:

```json
{
  "extraKnownMarketplaces": [
    "github.com/monad-developers/claude-web3-plugin-marketplace"
  ]
}
```

When team members trust the repository folder, Claude Code automatically adds this marketplace.

## Contributing

To add a new plugin:

1. Create a folder in `plugins/your-plugin-name/`
2. Add `.claude-plugin/plugin.json` with plugin metadata
3. Add your skills, commands, or agents
4. Update `.claude-plugin/marketplace.json` with your plugin entry
5. Submit a PR

## Links

- [Monad Docs](https://docs.monad.xyz)
- [Claude Code Plugin Docs](https://docs.anthropic.com/en/docs/claude-code/plugins)
