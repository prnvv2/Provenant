#!/usr/bin/env node
/**
 * Entry point. Kept tiny so `provenant hook` starts fast: the CLI module is the
 * only import, and it pulls in nothing outside node: built-ins.
 */

import { main } from '../src/cli.js';

const code = await main(process.argv.slice(2));
process.exitCode = code;
