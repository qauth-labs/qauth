// @vitest-environment jsdom
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { Modal } from './modal';

// Opt into React's act() environment so effects flush synchronously.
(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
});

afterEach(() => {
  act(() => root.unmount());
  container.remove();
  vi.restoreAllMocks();
});

function renderModal(props: Partial<Parameters<typeof Modal>[0]> = {}) {
  act(() => {
    root.render(
      <Modal
        title="Test dialog"
        onClose={props.onClose ?? vi.fn()}
        dismissible={props.dismissible}
        footer={props.footer}
      >
        {props.children ?? <button type="button">Inside</button>}
      </Modal>
    );
  });
}

describe('Modal focus management', () => {
  it('moves focus into the dialog on open', () => {
    renderModal({ children: <button type="button">First action</button> });
    const dialog = container.querySelector('[role="dialog"]');
    expect(dialog).not.toBeNull();
    // First focusable element inside the dialog receives focus.
    expect(document.activeElement?.textContent).toBe('First action');
  });

  it('restores focus to the previously focused element on close', () => {
    const trigger = document.createElement('button');
    trigger.textContent = 'Opener';
    document.body.appendChild(trigger);
    trigger.focus();
    expect(document.activeElement).toBe(trigger);

    renderModal({ children: <button type="button">Inside</button> });
    expect(document.activeElement?.textContent).toBe('Inside');

    act(() => root.unmount());
    expect(document.activeElement).toBe(trigger);
    trigger.remove();
  });

  it('closes on Escape when dismissible', () => {
    const onClose = vi.fn();
    renderModal({ onClose, dismissible: true });
    act(() => {
      document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    });
    expect(onClose).toHaveBeenCalledOnce();
  });

  it('does not close on Escape when non-dismissible (one-time secret modal)', () => {
    const onClose = vi.fn();
    renderModal({ onClose, dismissible: false });
    act(() => {
      document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    });
    expect(onClose).not.toHaveBeenCalled();
  });

  it('wraps Tab from the last focusable element back to the first', () => {
    renderModal({
      children: (
        <>
          <button type="button">First</button>
          <button type="button">Last</button>
        </>
      ),
    });
    const buttons = Array.from(container.querySelectorAll('button'));
    const last = buttons[buttons.length - 1];
    last.focus();
    expect(document.activeElement).toBe(last);

    act(() => {
      document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Tab', bubbles: true }));
    });
    // Focus wrapped back to the first focusable element.
    expect(document.activeElement?.textContent).toBe('First');
  });
});
