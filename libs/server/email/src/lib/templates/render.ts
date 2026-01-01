import { render } from '@react-email/components';
import type { ReactElement } from 'react';

/**
 * Render a React Email template to HTML string
 *
 * @param template - React Email template component
 * @returns Promise resolving to HTML string
 */
export async function renderEmail(template: ReactElement): Promise<string> {
  return render(template);
}

/**
 * Render a React Email template to plain text string
 *
 * @param template - React Email template component
 * @returns Promise resolving to plain text string
 */
export async function renderEmailText(template: ReactElement): Promise<string> {
  return render(template, { plainText: true });
}
