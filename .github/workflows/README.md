# Lotus CI Workflow System

This directory contains the GitHub Actions workflows for the Lotus project. The CI system has been designed to be modular, maintainable, and efficient.

## Workflow Structure

The CI system is organized into the following workflows:

### Main Orchestrator

- **[lotus-main-ci.yml](./lotus-main-ci.yml)**: The main entry point that orchestrates all other workflows. This workflow triggers when code is pushed to main branches or when pull requests are created.

### Version Management

- **[lotus-version-management.yml](./lotus-version-management.yml)**: Handles version checking and automatic version bumping based on the number of commits since the last tag.
- **[lotus-version-revert.yml](./lotus-version-revert.yml)**: Reverts version bumps if any of the build jobs fail.

### Build Workflows

These workflows handle building different components of the Lotus project:

- **[lotus-core-build.yml](./lotus-core-build.yml)**: Builds the core components (lotusd, lotus-cli, lotus-tx).
- **[lotus-tools-build.yml](./lotus-tools-build.yml)**: Builds utility tools (lotus-seeder, lotus-wallet).
- **[lotus-gui-build.yml](./lotus-gui-build.yml)**: Builds the GUI wallet (lotus-qt).
- **[lotus-miner-build.yml](./lotus-miner-build.yml)**: Builds the GPU miner component.

### Release Management

- **[lotus-release.yml](./lotus-release.yml)**: Packages all artifacts, creates GitHub releases, and generates release notes.

## Workflow Dependencies

```
lotus-main-ci.yml
  ├── lotus-version-management.yml
  ├── lotus-core-build.yml
  ├── lotus-tools-build.yml
  ├── lotus-gui-build.yml
  ├── lotus-miner-build.yml
  ├── lotus-version-revert.yml (conditional)
  └── lotus-release.yml
```

## How It Works

1. When code is pushed to master, the main workflow first checks the current version and may bump it.
2. Build workflows run in parallel to build all components.
3. If any builds fail after a version bump, the version is automatically reverted.
4. If all builds succeed, artifacts are packaged and a GitHub release is created.

## Benefits of This Structure

- **Modularity**: Each workflow focuses on a specific task, making them easier to understand and maintain.
- **Parallelism**: The build workflows run in parallel, reducing the overall build time.
- **Error Handling**: The system has robust error handling, including automatic version reversion if builds fail.
- **Clean Outputs**: Each workflow produces clean, well-defined artifacts.

## Contributing

When making changes to the CI system:

1. Test your changes on a branch before merging to master.
2. Keep workflows focused on specific tasks.
3. Document any new workflows or significant changes in this README. 