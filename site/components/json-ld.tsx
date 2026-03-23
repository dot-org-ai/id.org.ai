export function JsonLd() {
  const structuredData = {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "Organization",
        "@id": "https://id.org.ai/#organization",
        "name": "id.org.ai",
        "url": "https://id.org.ai",
        "logo": {
          "@type": "ImageObject",
          "url": "https://id.org.ai/logo.png",
          "@id": "https://id.org.ai/#logo"
        },
        "description": "Simple, secure sign-in for humans and AI agents",
        "sameAs": [
          "https://github.com/id-org-ai",
          "https://x.com/idorgai",
          "https://linkedin.com/company/id-org-ai"
        ]
      },
      {
        "@type": "WebSite",
        "@id": "https://id.org.ai/#website",
        "url": "https://id.org.ai",
        "name": "id.org.ai",
        "description": "Authentication service for humans and AI agents. Simple, secure sign-in for humans and AI agents.",
        "publisher": {
          "@id": "https://id.org.ai/#organization"
        },
        "inLanguage": "en-US"
      },
      {
        "@type": "SoftwareApplication",
        "@id": "https://id.org.ai/#software",
        "name": "id.org.ai",
        "url": "https://id.org.ai",
        "applicationCategory": "SecurityApplication",
        "description": "Authentication service for humans and AI agents. Simple, secure sign-in for humans and AI agents.",
        "offers": {
          "@type": "Offer",
          "price": "0",
          "priceCurrency": "USD"
        },
        "operatingSystem": "Web",
        "provider": {
          "@id": "https://id.org.ai/#organization"
        },
        "featureList": [
          "Universal authentication for both human users and AI agents",
          "Seamless sign-in experience with OAuth and OpenID Connect support",
          "Enterprise-grade security with end-to-end encryption",
          "AI agent identity verification and credential management",
          "Developer-friendly API with comprehensive documentation",
          "Zero-trust security architecture for modern applications",
          "Multi-factor authentication (MFA) support",
          "Cross-platform compatibility for web, mobile, and AI systems",
          "Real-time authentication monitoring and audit logs",
          "Scalable infrastructure for high-volume authentication requests"
        ],
        "audience": {
          "@type": "Audience",
          "audienceType": "Developers, AI applications, end users"
        }
      },
      {
        "@type": "FAQPage",
        "@id": "https://id.org.ai/#faq",
        "mainEntity": [
          {
            "@type": "Question",
            "name": "What is id.org.ai?",
            "acceptedAnswer": {
              "@type": "Answer",
              "text": "id.org.ai is a modern authentication service that provides simple, secure sign-in capabilities for both human users and AI agents. It offers a unified platform for managing identity and access control across traditional applications and AI-powered systems, making it easy for developers to implement secure authentication without the complexity of building custom solutions."
            }
          },
          {
            "@type": "Question",
            "name": "How does id.org.ai authenticate AI agents?",
            "acceptedAnswer": {
              "@type": "Answer",
              "text": "id.org.ai authenticates AI agents through specialized credential management and identity verification systems designed for autonomous systems. AI agents receive unique identifiers and secure tokens that allow them to authenticate themselves when accessing services and APIs. The platform supports API keys, OAuth tokens, and other machine-to-machine authentication protocols, ensuring AI agents can operate securely within your application ecosystem."
            }
          },
          {
            "@type": "Question",
            "name": "Is id.org.ai secure?",
            "acceptedAnswer": {
              "@type": "Answer",
              "text": "Yes, id.org.ai is built with enterprise-grade security features including end-to-end encryption, zero-trust architecture, and multi-factor authentication support. The platform follows industry best practices and security standards to protect user data and prevent unauthorized access. All authentication flows are encrypted, and the system includes real-time monitoring, audit logs, and comprehensive security controls to ensure your applications and data remain protected."
            }
          },
          {
            "@type": "Question",
            "name": "What's the difference between human and AI agent authentication?",
            "acceptedAnswer": {
              "@type": "Answer",
              "text": "Human authentication typically involves interactive methods like passwords, biometrics, or social logins, while AI agent authentication uses programmatic methods such as API keys, service tokens, or OAuth client credentials. id.org.ai supports both authentication types within a single platform, allowing you to manage human users and AI agents with appropriate security controls for each. Humans get user-friendly login interfaces, while AI agents receive machine-readable credentials for automated authentication."
            }
          },
          {
            "@type": "Question",
            "name": "How do I integrate id.org.ai?",
            "acceptedAnswer": {
              "@type": "Answer",
              "text": "Integrating id.org.ai is straightforward with comprehensive developer documentation and SDKs for popular programming languages. You can integrate the service using standard OAuth 2.0 and OpenID Connect protocols, or use the provided API libraries. The platform offers detailed guides, code examples, and quickstart templates to help you implement authentication in your applications quickly. Most developers can complete a basic integration in under an hour."
            }
          },
          {
            "@type": "Question",
            "name": "Is id.org.ai free?",
            "acceptedAnswer": {
              "@type": "Answer",
              "text": "Yes, id.org.ai offers a free tier that allows developers to get started with authentication for both human users and AI agents at no cost. The free tier includes core authentication features and is suitable for development, testing, and small-scale deployments. As your needs grow, additional pricing plans are available with advanced features, higher usage limits, and enterprise support options."
            }
          }
        ]
      }
    ]
  };

  return (
    <script
      type="application/ld+json"
      dangerouslySetInnerHTML={{ __html: JSON.stringify(structuredData) }}
    />
  );
}
