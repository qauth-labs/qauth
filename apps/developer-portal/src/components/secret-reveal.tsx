import { Button } from '@qauth-labs/ui';

import { CopyField } from './copy-field';
import { Modal } from './modal';

interface SecretRevealProps {
  /** The OAuth client identifier (safe to show again later). */
  clientId: string;
  /**
   * The one-time plaintext secret. Public clients have none — in that case
   * only the `clientId` is shown.
   */
  clientSecret?: string;
  /** Dialog title; differs for create vs. regenerate. */
  title: string;
  /** Called when the developer acknowledges they have stored the secret. */
  onDone: () => void;
}

/**
 * One-time secret display (issues #91, #93, #95). Renders inside a
 * non-dismissible modal so the developer cannot lose the secret by clicking
 * the backdrop. The secret is passed in as a prop and never written to any
 * store — when the parent removes this component the value is gone.
 */
export function SecretReveal({ clientId, clientSecret, title, onDone }: SecretRevealProps) {
  return (
    <Modal
      title={title}
      dismissible={false}
      onClose={onDone}
      footer={
        <Button type="button" onClick={onDone}>
          I&apos;ve stored the secret
        </Button>
      }
    >
      {clientSecret ? (
        <div
          role="alert"
          className="rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-800"
        >
          Copy this secret now. For your security, it will <strong>not</strong> be shown again. If
          you lose it you will have to regenerate it.
        </div>
      ) : (
        <p className="text-sm text-gray-600">
          This is a public client, so it has no secret. Use PKCE for the authorization code flow.
        </p>
      )}

      <CopyField label="Client ID" value={clientId} />
      {clientSecret ? <CopyField label="Client secret" value={clientSecret} /> : null}
    </Modal>
  );
}
