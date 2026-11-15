import * as React from 'react';

import { isAttachedLogo, type MailBrand } from '../../engine-mail/brand';
import { mailLink } from '../../engine-mail/links';
import { Body, Button, Container, Head, Html, Preview, Section, Text } from '../components';
import { MAIL_COLORS, MAIL_FONTS } from '../theme';

/**
 * The frame every mail shares (PRO-14, #637): the realm's logo or name, the
 * content, and the footer, in QAuth's design system (`../theme.ts`). The brand
 * sets the name, the logo, the button and link colour, the page colour and
 * the footer notice; it sets no link. The text colours, the faces and the
 * square, hairline-edged card are the design system's, whatever the brand.
 *
 * An attached logo (QAuth's) is shown through `cid:`, and the sender adds the
 * image as an inline part (`mailImagesOf`). An uploaded logo is loaded from
 * the realm's own host, its path after the realm's issuer; without an issuer
 * to start at, the name stands in.
 */
export interface MailFrameProps {
  readonly brand: MailBrand;
  /** The realm's issuer, where an uploaded logo is loaded from. */
  readonly baseUrl?: string;
  /** The inbox preview line. */
  readonly preview: string;
  /** The heading. */
  readonly title: string;
  readonly children: React.ReactNode;
}

export function MailFrame({ brand, baseUrl, preview, title, children }: MailFrameProps) {
  const styles = stylesOf(brand);
  const logoSrc = logoSrcOf(brand, baseUrl);
  return (
    <Html>
      <Head />
      <Preview>{preview}</Preview>
      <Body style={styles.main}>
        <Container style={styles.container}>
          <Section style={styles.section}>
            {brand.logo === undefined || logoSrc === undefined ? (
              <Text style={styles.name}>{brand.name}</Text>
            ) : (
              <Section style={styles.header}>
                <img
                  src={logoSrc}
                  width={brand.logo.width}
                  height={brand.logo.height}
                  alt={brand.name}
                  style={styles.logo}
                />
              </Section>
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

/** Where the frame's logo comes from, or `undefined` when the name stands in. */
function logoSrcOf(brand: MailBrand, baseUrl: string | undefined): string | undefined {
  if (brand.logo === undefined) return undefined;
  if (isAttachedLogo(brand.logo)) return `cid:${brand.logo.image.contentId}`;
  return baseUrl === undefined ? undefined : mailLink(baseUrl, brand.logo.path);
}

/** The frame of an engine mail: {@link MailFrame}, on the realm's issuer. */
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
  return (
    <MailFrame brand={brand} baseUrl={baseUrl} preview={preview} title={title}>
      {children}
    </MailFrame>
  );
}

/** A paragraph of a mail. */
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
      <Text style={styles.small}>
        Or copy and paste this link into your browser:
        <br />
        <a href={href} style={styles.link}>
          {href}
        </a>
      </Text>
    </>
  );
}

/** A hairline: the design system's edge, as a mail draws it. */
const HAIRLINE = `1px solid ${MAIL_COLORS.border}`;

function stylesOf(brand: MailBrand) {
  const { primary, background } = brand.colors;
  return {
    main: {
      backgroundColor: background,
      fontFamily: MAIL_FONTS.sans,
      margin: '0',
      padding: '40px 12px',
    },
    container: {
      backgroundColor: MAIL_COLORS.card,
      border: HAIRLINE,
      margin: '0 auto',
    },
    section: { padding: '36px 40px 32px' },
    name: {
      fontFamily: MAIL_FONTS.sans,
      fontSize: '16px',
      lineHeight: '24px',
      fontWeight: '600',
      color: MAIL_COLORS.foreground,
      margin: '0 0 32px',
      paddingBottom: '20px',
      borderBottom: HAIRLINE,
    },
    header: { margin: '0 0 32px', paddingBottom: '20px', borderBottom: HAIRLINE },
    logo: { display: 'block', maxWidth: '100%', height: 'auto', border: '0' },
    title: {
      fontFamily: MAIL_FONTS.display,
      fontSize: '36px',
      lineHeight: '1.15',
      fontWeight: '400',
      letterSpacing: '-0.01em',
      color: MAIL_COLORS.foreground,
      margin: '0 0 20px',
    },
    text: { fontSize: '16px', lineHeight: '1.65', color: MAIL_COLORS.body, margin: '0 0 16px' },
    small: { fontSize: '14px', lineHeight: '1.6', color: MAIL_COLORS.body, margin: '0 0 16px' },
    code: {
      display: 'inline-block',
      fontFamily: MAIL_FONTS.mono,
      fontSize: '28px',
      lineHeight: '1.2',
      fontWeight: '500',
      letterSpacing: '0.25em',
      color: MAIL_COLORS.foreground,
      backgroundColor: MAIL_COLORS.muted,
      border: HAIRLINE,
      // Less on the right: the spacing also follows the last digit.
      padding: '14px 13px 14px 20px',
      margin: '8px 0 24px',
    },
    buttonContainer: { padding: '8px 0 24px' },
    button: {
      backgroundColor: primary,
      borderRadius: '0',
      color: MAIL_COLORS.primaryForeground,
      fontFamily: MAIL_FONTS.sans,
      fontSize: '15px',
      fontWeight: '500',
      lineHeight: '20px',
      textDecoration: 'none',
      textAlign: 'center' as const,
      display: 'inline-block',
      padding: '12px 20px',
    },
    link: { color: primary, textDecoration: 'underline', wordBreak: 'break-all' as const },
    footer: {
      fontSize: '13px',
      lineHeight: '1.6',
      color: MAIL_COLORS.mutedForeground,
      margin: '32px 0 0',
      paddingTop: '20px',
      borderTop: HAIRLINE,
    },
  };
}
