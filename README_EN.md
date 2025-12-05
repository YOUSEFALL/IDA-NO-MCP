English | [简体中文](README.md)

# IDA NO MCP

**Say goodbye to the complex, verbose, and laggy interaction mode of IDA MCP.**  

**AI Reverse Engineering, Zero Extra Configuration.**  

Simple · Fast · Intelligent · Low Cost

## Core Philosophy

Text, Source Code, and Shell are LLM's native languages.

AI is evolving rapidly with no fixed patterns—tools should stay simple. Export IDA decompilation results as source files, drop them into any AI IDE (Cursor / Claude Code / ...), and naturally benefit from indexing, parallelism, chunking (for huge decompiled functions), and other optimizations.

## Usage

Copy the entire `INP.py` → Paste into IDA Python console → Press Enter

Export directory: `{IDB_directory}/export-for-ai/`

## Exported Content

| File/Directory | Content |
|----------------|---------|
| `decompile/` | Decompiled C code (with call relationships) |
| `strings.txt` | String table |
| `imports.txt` | Import table |
| `exports.txt` | Export table |
| `memory/` | Memory hexdump (1MB chunks) |

## Tips

You can add more context in the IDB directory to give AI a complete picture:

| Directory | Content |
|-----------|---------|
| `apk/` | APK decompilation directory (APKLab one-click export) |
| `docs/` | Reverse engineering reports, notes |
| `codes/` | exp, Frida scripts, decryptor, etc. |

State-of-the-art AI models can leverage all this information and scripts to provide you with the most powerful reverse engineering assistance.
