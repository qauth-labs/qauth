import * as React from 'react';

import type { MailBrand } from '../../engine-mail/brand';
import { mailLink } from '../../engine-mail/links';
import { Body, Button, Container, Head, Html, Preview, Section, Text } from '../components';

/**
 * The frame every engine mail shares (PRO-14, #637): the realm's logo or
 * name, the content, and the footer. The brand sets the colours, the name, the
 * logo and the footer notice; it sets no link. The logo is loaded from the
 * realm's own host: its path, after the realm's issuer.
 */
export interface EngineMailLayoutProps {
  readonly brand: MailBrand;
  /** The realm's issuer: where the logo and every link start. */
  readonly baseUrl: string;
  /** The inbox preview line. */
  readonly preview: string;
  /** The heading. */
  readonly title: string;
  readonly children: React.ReactNode;
}

export function EngineMailLayout({
  brand,
  baseUrl,
  preview,
  title,
  children,
}: EngineMailLayoutProps) {
  const styles = stylesOf(brand);
  return (
    <Html>
      <Head />
      <Preview>{preview}</Preview>
      <Body style={styles.main}>
        <Container style={styles.container}>
          <Section style={styles.section}>
            {brand.logo === undefined ? (
              <Text style={styles.name}>{brand.name}</Text>
            ) : (
              <img
                src={mailLink(baseUrl, brand.logo.path)}
                width={brand.logo.width}
                height={brand.logo.height}
                alt={brand.name}
                style={styles.logo}
              />
            )}
            <Text style={styles.title}>{title}</Text>
            {children}
            <Text style={styles.footer}>
              This email was sent by {brand.name} to this address. Nobody from {brand.name} will ask
              you for a code or a link it carries.
              {brand.footer === undefined ? null : (
                <>
                  <br />
                  {brand.footer}
                </>
              )}
            </Text>
          </Section>
        </Container>
      </Body>
    </Html>
  );
}

/** A paragraph of an engine mail. */
export function Paragraph({ brand, children }: { brand: MailBrand; children: React.ReactNode }) {
  return <Text style={stylesOf(brand).text}>{children}</Text>;
}

/** A mailed code, set apart so it is read and copied as one word. */
export function CodeBlock({ brand, code }: { brand: MailBrand; code: string }) {
  return <Text style={stylesOf(brand).code}>{code}</Text>;
}

/** A button and the same link spelled out, for a client that shows no button. */
export function LinkButton({
  brand,
  href,
  label,
}: {
  brand: MailBrand;
  href: string;
  label: string;
}) {
  const styles = stylesOf(brand);
  return (
    <>
      <Section style={styles.buttonContainer}>
        <Button style={styles.button} href={href}>
          {label}
        </Button>
      </Section>
      <Text style={styles.text}>
        Or copy and paste this link into your browser:
        <br />
        <a href={href} style={styles.link}>
          {href}
        </a>
      </Text>
    </>
  );
}

function stylesOf(brand: MailBrand) {
  const { primary, background } = brand.colors;
  return {
    main: {
      backgroundColor: background,
      fontFamily:
        '-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Ubuntu,sans-serif',
    },
    container: {
      backgroundColor: '#ffffff',
      margin: '0 auto',
      padding: '20px 0 48px',
      marginBottom: '64px',
    },
    section: { padding: '0 48px' },
    name: {
      fontSize: '18px',
      lineHeight: '1.3',
      fontWeight: '700',
      color: primary,
      margin: '0 0 24px',
    },
    logo: { display: 'block', margin: '0 0 24px', maxWidth: '100%', height: 'auto' },
    title: {
      fontSize: '24px',
      lineHeight: '1.3',
      fontWeight: '700',
      color: '#1a1a1a',
      margin: '0 0 20px',
    },
    text: { fontSize: '16px', lineHeight: '1.5', color: '#4a5568', margin: '0 0 16px' },
    code: {
      fontSize: '32px',
      lineHeight: '1.2',
      fontWeight: '700',
      letterSpacing: '6px',
      color: '#1a1a1a',
      fontFamily: '"SFMono-Regular",Consolas,"Liberation Mono",Menlo,monospace',
      margin: '8px 0 24px',
    },
    buttonContainer: { padding: '27px 0' },
    button: {
      backgroundColor: primary,
      borderRadius: '6px',
      color: '#ffffff',
      fontSize: '16px',
      fontWeight: '600',
      textDecoration: 'none',
      textAlign: 'center' as const,
      display: 'block',
      padding: '12px 24px',
      width: 'fit-content',
      margin: '0 auto',
    },
    link: { color: primary, textDecoration: 'underline', wordBreak: 'break-all' as const },
    footer: {
      fontSize: '14px',
      lineHeight: '1.5',
      color: '#718096',
      margin: '32px 0 0',
      paddingTop: '16px',
      borderTop: '1px solid #e2e8f0',
    },
  };
}
