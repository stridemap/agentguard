# web/ — Next.js 14 Frontend

Part of [Stridemap Labs](https://stridemap.ai) — AI Security for the Enterprise.

## Overview

Next.js 14 App Router application serving two purposes:
1. **stridemap.ai homepage**: Stridemap Labs company page with AgentGuard as first product
2. **Enterprise dashboard** (`/dashboard/*`): Live feed, audit viewer, policy manager, compliance reports, RBAC-gated views

**Live**: https://stridemap.ai (Vercel)
**API**: https://api-production-13f3.up.railway.app

## Tech Stack

- **Next.js**: 14.2 (App Router, NOT Pages Router)
- **React**: 18.3
- **TypeScript**: 5.4 (strict mode enabled)
- **Styling**: Tailwind CSS
- **UI Components**: shadcn/ui (Sprint 11+)
- **Charts**: Recharts (Sprint 11+)
- **Deployment**: Vercel (stridemap.ai)

## Design System

- **Theme**: Professional dark theme
- **Primary accent**: Teal `#00D4AA`
- **Font**: System font stack (no custom fonts for performance)
- **Responsive**: Mobile-first, must work on all viewport sizes
- **SEO**: Meta tags, Open Graph, structured data

## Landing Page Sections (Sprint 1)

1. **Hero**: Problem statement + CTA ("Get Early Access")
2. **Problem**: 4 enterprise pain points as cards
3. **Solution**: 5-module architecture diagram
4. **How it Works**: 3 steps (pip install, wrap, deploy)
5. **Comparison Table**: AgentGuard vs HiddenLayer vs LangSmith vs CalypsoAI
6. **Early Access Form**: Email capture
7. **Footer**: GitHub link, email, MIT license

## Enterprise Dashboard Pages (Sprint 11+)

- `/dashboard` — Live event feed (WebSocket)
- `/audit` — Chain viewer + verify_chain() UI
- `/policies` — Rule manager (CRUD on YAML rules)
- `/reports` — Compliance export (SOC2 CC6, HIPAA 164.312)
- `/settings` — Configuration

## Commands

```bash
npm install          # Install dependencies
npm run dev          # Development server (http://localhost:3000)
npm run build        # Production build
npm run lint         # ESLint check
```

## File Structure

```
web/
├── src/
│   └── app/
│       ├── layout.tsx    # Root layout (metadata, fonts)
│       ├── page.tsx      # Landing page
│       └── globals.css   # Tailwind imports + custom styles
├── package.json
├── tsconfig.json
├── tailwind.config.ts
└── next.config.mjs
```

## Conventions

- Use **server components** by default, `"use client"` only when needed (interactivity, hooks)
- Path alias: `@/*` maps to `./src/*`
- Image optimization via `next/image`
- No inline styles — use Tailwind utility classes
- Component files: PascalCase (e.g., `HeroSection.tsx`)
- Keep bundle size minimal — lazy load non-critical components
