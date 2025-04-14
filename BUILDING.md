# Building GDBG

This document explains how to build GDBG from source code to create standalone executable binaries for various platforms.

## Prerequisites

- Node.js 14.x or later
- npm 6.x or later
- git

## Building Process

GDBG uses [pkg](https://github.com/vercel/pkg) to create standalone executables that include Node.js runtime, so no external dependencies are required to run the built binaries.

### 1. Clone the Repository

```bash
git clone https://github.com/MswTester/gdbg.git
cd gdbg
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Build the Binaries

#### Build for All Platforms

To build for Windows, macOS, and Linux:

```bash
npm run build-all
```

#### Build for Specific Platforms

To build for a specific platform:

```bash
# Windows
npm run build-win

# macOS
npm run build-macos

# Linux
npm run build-linux
```

The binaries will be generated in the `dist` directory:

- Windows: `dist/gdbg-win.exe`
- macOS: `dist/gdbg-macos`
- Linux: `dist/gdbg-linux`

### 4. Testing the Build

You can test the binary directly:

```bash
# Windows
dist\gdbg-win.exe -h

# macOS/Linux
chmod +x dist/gdbg-macos  # Make executable
./dist/gdbg-macos -h
```

## Customizing the Build

You can modify the build configuration in `package.json`:

```json
"pkg": {
  "scripts": "index.js",
  "assets": [
    "gdbg.js"
  ],
  "targets": [
    "node16-win-x64",
    "node16-macos-x64",
    "node16-linux-x64"
  ],
  "outputPath": "dist"
}
```

- `scripts`: Entry point files
- `assets`: Additional files to include in the package
- `targets`: Target platforms (format: `nodeVersion-platform-arch`)
- `outputPath`: Output directory

## Troubleshooting

### Common Issues

1. **Missing Dependencies**

   If you see errors about missing dependencies, run:

   ```bash
   npm install
   ```

2. **Permission Denied (macOS/Linux)**

   If you can't execute the built binary, make it executable:

   ```bash
   chmod +x dist/gdbg-macos  # or gdbg-linux
   ```

3. **Node.js Version Issues**

   If you encounter issues with the Node.js version, try modifying the target in package.json (e.g., change `node16` to `node14` or `node18`).

## Distribution

After building, you can distribute the binaries to users who don't have Node.js installed. The binaries are self-contained and don't require any additional dependencies to run.

## Advanced

### Compression

The build scripts use GZip compression to reduce the size of the binaries. If you need to further reduce the size, you can try UPX:

```bash
# Install UPX
# Then compress the binary
upx --best dist/gdbg-win.exe
```

### Custom Targets

To build for additional platforms or architectures, modify the targets in `package.json`. For example:

```json
"targets": [
  "node16-win-x64",
  "node16-win-x86",
  "node16-macos-x64",
  "node16-macos-arm64",
  "node16-linux-x64",
  "node16-linux-arm64"
]
```

Then run:

```bash
pkg . --compress GZip
``` 