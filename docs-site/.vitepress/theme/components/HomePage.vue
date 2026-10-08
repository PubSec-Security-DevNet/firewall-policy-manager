<!-- Copyright 2026 Cisco Systems, Inc. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<script setup lang="ts">
import { withBase } from "vitepress";
</script>

<template>
  <main class="fm-home">
    <section class="home-hero">
      <div class="home-hero__copy">
        <div class="release-pill">
          <span></span> Current status · release candidate
        </div>
        <p class="eyebrow">Delegated Cisco firewall operations</p>
        <h1>Delegate policy work.<br /><em>Keep control.</em></h1>
        <p class="home-hero__lede">
          Firewall Policy Manager puts a governed control layer between teams
          and shared FMC or SCC policy—even when separate firewall instances or
          management domains are unavailable or impractical. Teams can move
          inside boundaries the platform team defines.
        </p>
        <div class="home-actions">
          <a
            class="home-button home-button--primary"
            :href="withBase('/features/')"
            >Explore features <span>→</span></a
          >
          <a class="home-button" :href="withBase('/installation/')"
            >Production installation</a
          >
        </div>
        <div class="home-proof" aria-label="Product highlights">
          <div>
            <strong>FMC + SCC</strong><span>One governed workflow</span>
          </div>
          <div>
            <strong>Default deny</strong><span>Server-enforced scope</span>
          </div>
          <div>
            <strong>ChangeSet first</strong
            ><span>Auditable provider writes</span>
          </div>
        </div>
      </div>
      <div class="home-hero__visual">
        <div class="hero-orbit hero-orbit--one"></div>
        <div class="hero-orbit hero-orbit--two"></div>
        <div class="hero-screen">
          <img
            :src="withBase('/screenshots/dashboard.png')"
            alt="Firewall Policy Manager security posture dashboard showing synchronized FMC and SCC providers"
          />
        </div>
        <div class="context-chip context-chip--group">
          <span>ACTIVE GROUP</span><strong>Finance</strong
          ><small>Only Finance grants apply</small>
        </div>
        <div class="context-chip context-chip--state">
          <span>PROVIDER STATE</span><strong><i></i> Synchronized</strong
          ><small>FMC and SCC inventory</small>
        </div>
      </div>
    </section>

    <section class="home-band" aria-label="Product promise">
      <p>Not a second firewall console.</p>
      <h2>
        A control plane for the space between <span>central ownership</span> and
        <span>delegated action.</span>
      </h2>
    </section>

    <section class="story-section story-section--split">
      <div class="story-copy">
        <p class="eyebrow">01 · Explicit context</p>
        <h2>
          One person can belong to many teams. Their permissions never blend.
        </h2>
        <p>
          Alice may belong to Finance and Engineering. When Finance is active,
          only Finance policy assignments, object rights, zone rights, and
          authorized network ranges participate. Engineering contributes nothing
          until Alice deliberately switches context.
        </p>
        <a :href="withBase('/security/authorization')"
          >Understand Active Group authorization →</a
        >
      </div>
      <div
        class="active-group-visual"
        role="img"
        aria-label="Alice selects Finance as her Active Group. Finance rights apply and Engineering rights do not."
      >
        <div class="identity-node">
          <span>USER</span><strong>Alice</strong><small>2 memberships</small>
        </div>
        <div class="choice-rail">
          <div class="choice-node choice-node--active">
            <b>✓</b
            ><span><strong>Finance</strong><small>Active Group</small></span>
          </div>
          <div class="choice-node choice-node--muted">
            <b>×</b
            ><span
              ><strong>Engineering</strong><small>Not in context</small></span
            >
          </div>
        </div>
        <div class="scope-node">
          <span>EFFECTIVE BOUNDARY</span><strong>Finance Access Policy</strong>
          <ul>
            <li>Assigned policies</li>
            <li>Granted objects &amp; zones</li>
            <li>Authorized IP ranges</li>
          </ul>
        </div>
      </div>
    </section>

    <section class="story-section governance-section">
      <div class="section-heading">
        <p class="eyebrow">02 · Govern every change</p>
        <h2>
          Intent becomes provider state through a visible, recoverable
          lifecycle.
        </h2>
        <p>
          Rule and object edits do not jump from a browser to Cisco
          infrastructure. They become durable ChangeSets, revalidated at
          execution, then tracked through provider configuration and deployment.
        </p>
      </div>
      <div
        class="pipeline"
        role="img"
        aria-label="ChangeSet lifecycle from draft through validation, approval, provider execution, pending deployment, and device results"
      >
        <div><b>01</b><strong>Draft</strong><span>Scoped intent</span></div>
        <i>→</i>
        <div>
          <b>02</b><strong>Validate</strong><span>Rights + revisions</span>
        </div>
        <i>→</i>
        <div><b>03</b><strong>Approve</strong><span>When required</span></div>
        <i>→</i>
        <div><b>04</b><strong>Execute</strong><span>FMC / SCC write</span></div>
        <i>→</i>
        <div>
          <b>05</b><strong>Deploy</strong><span>Per-device result</span>
        </div>
      </div>
      <div class="governance-grid">
        <article>
          <span class="cap-icon">⌁</span>
          <h3>Use is not ownership</h3>
          <p>
            Reference a shared DNS object without gaining the right to edit it.
            Modify and delete decisions remain separate.
          </p>
        </article>
        <article>
          <span class="cap-icon">◎</span>
          <h3>Reality is allowed to differ</h3>
          <p>
            Synchronization detects provider-only, missing, or drifted
            resources. Reconciliation is an explicit decision, never silent
            adoption.
          </p>
        </article>
        <article>
          <span class="cap-icon">↺</span>
          <h3>Recovery without magic</h3>
          <p>
            Eligible rollback creates a compensating ChangeSet after revision
            and dependency checks. It is not a transactional firewall rewind.
          </p>
        </article>
      </div>
    </section>

    <section class="story-section screen-story">
      <div class="story-copy">
        <p class="eyebrow">03 · Operational clarity</p>
        <h2>Configuration, deployment, and observed state stay distinct.</h2>
        <p>
          Operators can see what Firewall Policy Manager requested, what FMC or
          SCC accepted, what remains pending deployment, and what each device
          reported. Scheduled and authorized forced deployments share the same
          evidence trail.
        </p>
        <div class="provider-tags">
          <span>FMC</span><span>SCC</span><span>Sync</span><span>Drift</span
          ><span>Audit</span>
        </div>
        <a :href="withBase('/tour')">Take the product tour →</a>
      </div>
      <div class="screen-stack">
        <img
          :src="withBase('/screenshots/changesets.png')"
          alt="ChangeSets workspace showing approval, success, conflict, and retry states"
        />
      </div>
    </section>

    <section class="story-section capability-section">
      <div class="section-heading">
        <p class="eyebrow">Built for enterprise boundaries</p>
        <h2>The control plane around the control plane.</h2>
      </div>
      <div class="capability-list">
        <a :href="withBase('/security/')"
          ><strong>Security model</strong
          ><span
            >Default deny, server authorization, secure sessions, TLS, Vault,
            audit</span
          ><b>→</b></a
        >
        <a :href="withBase('/providers/fmc')"
          ><strong>FMC integration</strong
          ><span
            >Inventory, policy changes, synchronization, pending state,
            deployment</span
          ><b>→</b></a
        >
        <a :href="withBase('/providers/scc')"
          ><strong>SCC integration</strong
          ><span
            >Cloud-managed inventory and writes through the same governed
            lifecycle</span
          ><b>→</b></a
        >
        <a :href="withBase('/operations/')"
          ><strong>Production operations</strong
          ><span
            >Health, workers, scheduler, metrics, backup, restore, and
            upgrades</span
          ><b>→</b></a
        >
      </div>
    </section>

    <section class="home-cta">
      <div>
        <p class="eyebrow">Production ready path</p>
        <h2>Install the complete control plane.</h2>
        <p>
          Deploy the hardened container stack, establish TLS and secrets,
          connect OIDC, then onboard FMC or SCC with writes disabled until
          validation is complete.
        </p>
      </div>
      <a
        class="home-button home-button--primary"
        :href="withBase('/installation/')"
        >Start production installation →</a
      >
    </section>
  </main>
</template>
