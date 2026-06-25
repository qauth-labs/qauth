import { type ReactNode, useEffect, useRef } from 'react';

const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

interface ModalProps {
  /** Heading shown at the top of the dialog. */
  title: string;
  /** Body content. */
  children: ReactNode;
  /** Footer actions (buttons). */
  footer?: ReactNode;
  /**
   * Called when the user dismisses the modal via the backdrop or Escape.
   * Omit (or no-op) to make the modal non-dismissible while an action is in
   * flight.
   */
  onClose: () => void;
  /** When true, backdrop click and Escape do not close the modal. */
  dismissible?: boolean;
}

/**
 * Minimal accessible modal dialog. Centered overlay that moves focus into the
 * dialog on open, keeps Tab / Shift+Tab cycling within it, and restores focus
 * to the previously focused element on close. Deliberately dependency-free (no
 * portal library) to match the portal's lean component set.
 */
export function Modal({ title, children, footer, onClose, dismissible = true }: ModalProps) {
  const dialogRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape' && dismissible) {
        onClose();
        return;
      }
      if (e.key !== 'Tab') return;

      const dialog = dialogRef.current;
      if (!dialog) return;
      const focusable = Array.from(dialog.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter(
        (el) => !el.hasAttribute('hidden') && el.getAttribute('aria-hidden') !== 'true'
      );
      if (focusable.length === 0) {
        // Nothing focusable inside: keep focus on the dialog container.
        e.preventDefault();
        dialog.focus();
        return;
      }

      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const active = document.activeElement;

      // Wrap around the ends, and pull focus back in if it has escaped the
      // dialog (e.g. focus was on the page behind it).
      if (e.shiftKey) {
        if (active === first || !dialog.contains(active)) {
          e.preventDefault();
          last.focus();
        }
      } else if (active === last || !dialog.contains(active)) {
        e.preventDefault();
        first.focus();
      }
    }

    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [onClose, dismissible]);

  // Move focus into the dialog on open; restore it to the previously focused
  // element on close.
  useEffect(() => {
    const previouslyFocused = document.activeElement as HTMLElement | null;
    const dialog = dialogRef.current;
    if (dialog) {
      const firstFocusable = dialog.querySelector<HTMLElement>(FOCUSABLE_SELECTOR);
      (firstFocusable ?? dialog).focus();
    }
    return () => {
      previouslyFocused?.focus?.();
    };
  }, []);

  return (
    <div
      role="presentation"
      onClick={() => {
        if (dismissible) onClose();
      }}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4"
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-lg space-y-4 rounded-lg border border-gray-200 bg-white p-6 shadow-lg outline-none"
      >
        <h2 className="text-lg font-semibold text-gray-900">{title}</h2>
        <div className="space-y-3 text-sm text-gray-700">{children}</div>
        {footer ? <div className="flex justify-end gap-3 pt-2">{footer}</div> : null}
      </div>
    </div>
  );
}
