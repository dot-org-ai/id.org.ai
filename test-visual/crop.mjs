#!/usr/bin/env node
/** Dev aid: node test-visual/crop.mjs <in.png> <out.png> <y> <height> [x] [width] */
import { readFileSync, writeFileSync } from 'node:fs'
import { PNG } from 'pngjs'
const [inp, out, y, h, x = '0', w] = process.argv.slice(2)
const src = PNG.sync.read(readFileSync(inp))
const width = Math.min(Number(w ?? src.width), src.width - Number(x))
const height = Math.min(Number(h), src.height - Number(y))
const dst = new PNG({ width, height })
PNG.bitblt(src, dst, Number(x), Number(y), width, height, 0, 0)
writeFileSync(out, PNG.sync.write(dst))
