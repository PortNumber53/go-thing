import { useEffect, RefObject } from 'react'

export type OutsideDismissOptions = {
  enabled?: boolean
  keys?: string[]
  events?: Array<'mousedown' | 'touchstart'>
  restoreFocusTo?: RefObject<HTMLElement | null>
}

// useOutsideDismiss wires document listeners to dismiss a UI when:
// - user clicks/taps outside any of the provided refs
// - user presses one of the specified keys (default: Escape)
export function useOutsideDismiss(
  refs: Array<RefObject<HTMLElement | null>>,
  onDismiss: () => void,
  opts: OutsideDismissOptions = {}
) {
  const {
    enabled = true,
    keys = ['Escape'],
    events = ['mousedown'],
    restoreFocusTo,
  } = opts

  useEffect(() => {
    if (!enabled) return
    if (typeof document === 'undefined') return

    function isInsideAny(node: Node) {
      for (const r of refs) {
        const el = r.current
        if (el && el.contains(node)) return true
      }
      return false
    }

    function onDocPointer(e: Event) {
      const target = e.target
      if (!(target instanceof Node)) return
      if (isInsideAny(target)) return
      // Outside
      try { onDismiss() } finally {
        if (restoreFocusTo?.current) restoreFocusTo.current.focus()
      }
    }

    function onKey(e: KeyboardEvent) {
      if (keys.includes(e.key)) {
        try { onDismiss() } finally {
          if (restoreFocusTo?.current) restoreFocusTo.current.focus()
        }
      }
    }

    for (const ev of events) document.addEventListener(ev, onDocPointer, { passive: true })
    document.addEventListener('keydown', onKey)

    return () => {
      for (const ev of events) document.removeEventListener(ev, onDocPointer)
      document.removeEventListener('keydown', onKey)
    }
  }, [enabled, refs, onDismiss, restoreFocusTo, keys.join(','), events.join(',')])
}

export default useOutsideDismiss
