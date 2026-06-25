import { Button } from '@qauth-labs/ui';
import { useState } from 'react';

interface CopyFieldProps {
  /** The value to display and copy. */
  value: string;
  /** Accessible label / field heading. */
  label: string;
  /** Render the value in a monospace, secret-styled box. */
  mono?: boolean;
}

/**
 * Read-only value with a copy-to-clipboard button. Used for `clientId`
 * (always visible) and one-time `clientSecret` displays. The component holds
 * no state beyond a transient "copied" flag — the caller owns the value's
 * lifetime, so a secret is dropped the moment its parent modal unmounts.
 */
export function CopyField({ value, label, mono = true }: CopyFieldProps) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard API may be unavailable (insecure context); the value stays
      // selectable for manual copy.
    }
  }

  return (
    <div className="space-y-1.5">
      <span className="text-sm font-medium text-gray-700">{label}</span>
      <div className="flex items-stretch gap-2">
        <code
          data-testid="copy-field-value"
          className={`flex-1 overflow-x-auto rounded-md border border-gray-300 bg-gray-50 px-3 py-2 text-sm text-gray-800 ${
            mono ? 'font-mono' : ''
          }`}
        >
          {value}
        </code>
        <Button
          type="button"
          variant="outline"
          onClick={() => void copy()}
          aria-label={`Copy ${label}`}
        >
          {copied ? 'Copied' : 'Copy'}
        </Button>
      </div>
    </div>
  );
}
