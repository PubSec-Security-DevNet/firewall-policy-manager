// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0
import { defineConfig } from "vitepress";

const base = process.env.DOCS_BASE ?? "/firewall-policy-manager/";
const repositoryUrl =
  "https://github.com/PubSec-Security-DevNet/firewall-policy-manager";
const siteUrl =
  "https://pubsec-security-devnet.github.io/firewall-policy-manager/";
const productSidebar = [
  {
    text: "Product capabilities",
    items: [
      { text: "Feature overview", link: "/features/" },
      {
        text: "Delegated administration",
        link: "/features/delegated-administration",
      },
      { text: "Policies & context", link: "/guide/policies" },
      { text: "Rules & objects", link: "/guide/rules-objects" },
      { text: "Change governance", link: "/guide/changesets" },
      { text: "Sync & drift", link: "/guide/sync-drift" },
      { text: "Provider operations", link: "/guide/provider-operations" },
      {
        text: "Deployment & recovery",
        link: "/features/deployment-recovery",
      },
      { text: "Workflow states", link: "/features/workflows" },
      { text: "API tokens", link: "/features/api" },
    ],
  },
];

export default defineConfig({
  title: "Firewall Policy Manager",
  titleTemplate: ":title | Firewall Policy Manager",
  description:
    "Governed delegation, ChangeSets, deployment, and drift management for Cisco FMC and SCC.",
  lang: "en-US",
  base,
  appearance: "force-dark",
  cleanUrls: true,
  lastUpdated: true,
  sitemap: { hostname: siteUrl },
  srcExclude: ["README.md"],
  head: [
    [
      "link",
      { rel: "icon", type: "image/svg+xml", href: `${base}favicon.svg` },
    ],
    ["link", { rel: "canonical", href: siteUrl }],
    ["meta", { name: "theme-color", content: "#07111e" }],
    ["meta", { property: "og:type", content: "website" }],
    ["meta", { property: "og:title", content: "Firewall Policy Manager" }],
    [
      "meta",
      {
        property: "og:description",
        content:
          "Delegate Cisco firewall policy work without delegating the firewall.",
      },
    ],
    ["meta", { property: "og:url", content: siteUrl }],
    ["meta", { property: "og:image", content: `${siteUrl}social-preview.png` }],
    ["meta", { name: "twitter:card", content: "summary_large_image" }],
  ],
  themeConfig: {
    logo: {
      src: "/firewall-policy-manager.svg",
      alt: "Firewall Policy Manager home",
    },
    siteTitle: false,
    nav: [
      { text: "Overview", link: "/overview" },
      {
        text: "Features",
        link: "/features/",
        activeMatch:
          "^/(features/|guide/(policies|rules-objects|changesets|sync-drift|provider-operations))",
      },
      { text: "Product tour", link: "/tour" },
      { text: "Architecture", link: "/architecture" },
      { text: "Security", link: "/security/" },
      { text: "Installation", link: "/installation/" },
      { text: "Operations", link: "/operations/" },
      {
        text: "Release candidate",
        items: [
          { text: "Release status", link: "/release" },
          {
            text: "GitHub releases",
            link: `${repositoryUrl}/releases`,
          },
          {
            text: "Contribute",
            link: `${repositoryUrl}/blob/main/CONTRIBUTING.md`,
          },
        ],
      },
    ],
    sidebar: {
      "/features/": productSidebar,
      "/security/": [
        {
          text: "Security",
          items: [
            { text: "Security model", link: "/security/" },
            {
              text: "Authorization & Active Group",
              link: "/security/authorization",
            },
            { text: "Authentication", link: "/security/authentication" },
          ],
        },
      ],
      "/providers/": [
        {
          text: "Provider integrations",
          items: [
            { text: "Provider model", link: "/providers/" },
            { text: "Cisco FMC", link: "/providers/fmc" },
            { text: "Cisco SCC", link: "/providers/scc" },
          ],
        },
      ],
      "/installation/": [
        {
          text: "Installation",
          items: [
            { text: "Production quick start", link: "/installation/" },
            { text: "Full production guide", link: "/installation/production" },
            { text: "Production configuration", link: "/guide/configuration" },
            { text: "TLS & certificates", link: "/installation/tls" },
            { text: "Vault & secrets", link: "/installation/secrets" },
            { text: "Authentication", link: "/security/authentication" },
            { text: "FMC", link: "/providers/fmc" },
            { text: "SCC", link: "/providers/scc" },
            { text: "Backups & restore", link: "/operations/backup-restore" },
            { text: "Monitoring", link: "/operations/monitoring" },
            { text: "Upgrade", link: "/operations/upgrade" },
            { text: "Troubleshooting", link: "/operations/troubleshooting" },
          ],
        },
      ],
      "/operations/": [
        {
          text: "Operations",
          items: [
            { text: "Operator guide", link: "/operations/" },
            { text: "Health & monitoring", link: "/operations/monitoring" },
            { text: "Workers & scheduler", link: "/operations/workers" },
            { text: "Backups & restore", link: "/operations/backup-restore" },
            { text: "Upgrade", link: "/operations/upgrade" },
            { text: "Troubleshooting", link: "/operations/troubleshooting" },
          ],
        },
      ],
      "/guide/": productSidebar,
      "/": [
        {
          text: "Discover",
          items: [
            { text: "Overview", link: "/overview" },
            { text: "Product tour", link: "/tour" },
            { text: "Architecture", link: "/architecture" },
            { text: "Security", link: "/security/" },
            { text: "Production installation", link: "/installation/" },
            { text: "Release status", link: "/release" },
          ],
        },
      ],
    },
    search: { provider: "local", options: { detailedView: true } },
    socialLinks: [{ icon: "github", link: repositoryUrl }],
    editLink: {
      pattern: `${repositoryUrl}/edit/main/docs-site/:path`,
      text: "Suggest a documentation change",
    },
    outline: { level: [2, 3], label: "On this page" },
    footer: {
      message: `Firewall Policy Manager is licensed under the <a href="${repositoryUrl}/blob/main/LICENSE">Apache License, Version 2.0</a>.`,
      copyright: "Copyright 2026 Cisco Systems, Inc.",
    },
    docFooter: { prev: "Previous", next: "Next" },
  },
  markdown: { image: { lazyLoading: true } },
});
