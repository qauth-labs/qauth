import {
  Body,
  Button,
  Container,
  Head,
  Html,
  Preview,
  Section,
  Text,
} from '@react-email/components';
import * as React from 'react';

/**
 * Props for the VerifyEmail template
 */
export interface VerifyEmailProps {
  /**
   * Verification URL to include in the email
   */
  verificationUrl: string;
  /**
   * Expiration time description (e.g., "24 hours", "1 hour")
   */
  expiresIn: string;
}

/**
 * React Email template for email verification
 *
 * @param props - Template props
 * @returns React component
 */
export function VerifyEmail({ verificationUrl, expiresIn }: VerifyEmailProps) {
  return (
    <Html>
      <Head />
      <Preview>Verify your email address to complete your registration</Preview>
      <Body style={main}>
        <Container style={container}>
          <Section style={section}>
            <Text style={title}>Verify Your Email Address</Text>
            <Text style={text}>
              Thank you for registering with QAuth. Please verify your email address by clicking the
              button below:
            </Text>
            <Section style={buttonContainer}>
              <Button style={button} href={verificationUrl}>
                Verify Email
              </Button>
            </Section>
            <Text style={text}>
              Or copy and paste this link into your browser:
              <br />
              <a href={verificationUrl} style={link}>
                {verificationUrl}
              </a>
            </Text>
            <Text style={footer}>
              This verification link will expire in {expiresIn}. If you did not create an account,
              you can safely ignore this email.
            </Text>
          </Section>
        </Container>
      </Body>
    </Html>
  );
}

// Styles
const main = {
  backgroundColor: '#f6f9fc',
  fontFamily:
    '-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Ubuntu,sans-serif',
};

const container = {
  backgroundColor: '#ffffff',
  margin: '0 auto',
  padding: '20px 0 48px',
  marginBottom: '64px',
};

const section = {
  padding: '0 48px',
};

const title = {
  fontSize: '24px',
  lineHeight: '1.3',
  fontWeight: '700',
  color: '#1a1a1a',
  margin: '0 0 20px',
};

const text = {
  fontSize: '16px',
  lineHeight: '1.5',
  color: '#4a5568',
  margin: '0 0 16px',
};

const buttonContainer = {
  padding: '27px 0',
};

const button = {
  backgroundColor: '#2563eb',
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
};

const link = {
  color: '#2563eb',
  textDecoration: 'underline',
  wordBreak: 'break-all' as const,
};

const footer = {
  fontSize: '14px',
  lineHeight: '1.5',
  color: '#718096',
  margin: '32px 0 0',
  paddingTop: '16px',
  borderTop: '1px solid #e2e8f0',
};
