import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { ThemeProvider } from "@/components/theme-provider";
import { JsonLd } from "@/components/json-ld";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "id.org.ai - Simple, Secure Sign-In for Humans and AI Agents",
  description: "Authentication service for humans and AI agents. Secure, streamlined identity management that works seamlessly across human users and autonomous AI systems.",
  keywords: [
    "authentication",
    "AI agents",
    "identity management",
    "sign-in",
    "auth service",
    "human authentication",
    "AI authentication",
    "secure login",
    "identity verification",
    "OAuth",
    "SSO",
  ],
  authors: [{ name: "id.org.ai" }],
  metadataBase: new URL("https://id.org.ai"),
  alternates: {
    canonical: "/",
  },
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      "max-video-preview": -1,
      "max-image-preview": "large",
      "max-snippet": -1,
    },
  },
  openGraph: {
    type: "website",
    locale: "en_US",
    url: "https://id.org.ai",
    siteName: "id.org.ai",
    title: "id.org.ai - Simple, Secure Sign-In for Humans and AI Agents",
    description: "Authentication service for humans and AI agents. Secure, streamlined identity management that works seamlessly across human users and autonomous AI systems.",
    images: [
      {
        url: "/og.png",
        width: 1200,
        height: 630,
        alt: "id.org.ai - Humans. Agents. Auth.",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "id.org.ai - Simple, Secure Sign-In for Humans and AI Agents",
    description: "Authentication service for humans and AI agents. Secure, streamlined identity management that works seamlessly across human users and autonomous AI systems.",
    images: ["/og.png"],
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <JsonLd />
      </head>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        <ThemeProvider
          attribute="class"
          defaultTheme="system"
          enableSystem
          disableTransitionOnChange
        >
          {children}
        </ThemeProvider>
      </body>
    </html>
  );
}
