// Thin typed bridge to the Go backend (generated Wails bindings).
// Everything else in the UI depends on ./types and ./lib, not on Wails.
import * as Go from '../wailsjs/go/main/App'
import {fixer} from '../wailsjs/go/models'
import {BrowserOpenURL, EventsOff, EventsOn, OnFileDrop, OnFileDropOff} from '../wailsjs/runtime/runtime'

import type {ExportFormat, FixReport, FixRequest, ScanReport} from './types'

export const selectFolder = (): Promise<string> => Go.SelectFolder()
export const scan = (root: string) => Go.Scan(root) as unknown as Promise<ScanReport>
export const applyFixes = (root: string, reqs: FixRequest[]) =>
  Go.ApplyFixes(root, reqs.map(r => fixer.Request.createFrom(r))) as unknown as Promise<FixReport>
export const exportFormats = () => Go.ExportFormats() as unknown as Promise<ExportFormat[]>
export const exportReport = (formatId: string): Promise<string> => Go.Export(formatId)
export const openInFinder = (p: string) => Go.OpenInFinder(p)
export const openURL = (u: string) => BrowserOpenURL(u)
export const initialPath = (): Promise<string> => Go.InitialPath()

// Calls cb with the folder that was dropped onto the window.
export function onFolderDrop(cb: (dir: string) => void): () => void {
  OnFileDrop(async (_x, _y, paths) => {
    if (paths.length === 0) return
    const dir = await Go.ResolveDroppedPath(paths[0])
    if (dir) cb(dir)
  }, false)
  return () => OnFileDropOff()
}

export function onProgress(cb: (msg: string) => void): () => void {
  EventsOn('progress', cb)
  return () => EventsOff('progress')
}
